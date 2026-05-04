/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
)

const (
	socks5Ver         = 0x05
	socks5CmdUDPAssoc = 0x03
	socks5AtypIPv4    = 0x01
	socks5AtypDomain  = 0x03
	socks5AtypIPv6    = 0x04

	// 最大 SOCKS5 UDP 帧头: RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2)
	socks5MaxFrameHdr = 22
	// Read buffer: max DNS UDP payload (4096, EDNS0 theoretical max) + max SOCKS5 frame header (22).
	// The caller readMsgUdp allocates a 4095-byte buffer, so responses >= 4096 bytes
	// will be truncated by socks5Unframe, consistent with native UDP behavior.
	socks5ReadBufSize = 4096 + socks5MaxFrameHdr
)

var errSocks5UdpClosed = errors.New("socks5: udp connection closed")

// socks5UdpConn 通过 SOCKS5 UDP ASSOCIATE 传输 UDP 数据。
// 实现 net.Conn，可直接传给 transport.NewDnsConn。
// 内部维护 TCP 控制连接，断开时自动使 UDP 连接失效。
type socks5UdpConn struct {
	udpConn   net.Conn // 连接到代理中继的 UDP socket
	tcpConn   net.Conn // SOCKS5 TCP 控制连接（保活以维持 UDP 关联）
	targetHdr []byte   // 目标地址帧头，Write 时复用
	readBuf   []byte   // 读缓冲区，避免每次分配

	closeOnce   sync.Once
	closeNotify chan struct{}
	monitorWg   sync.WaitGroup // waits for tcpMonitor goroutine to exit
}

func (c *socks5UdpConn) Read(b []byte) (int, error) {
	select {
	case <-c.closeNotify:
		return 0, errSocks5UdpClosed
	default:
	}

	n, err := c.udpConn.Read(c.readBuf)
	if err != nil {
		return 0, err
	}
	return socks5Unframe(c.readBuf[:n], b)
}

func (c *socks5UdpConn) Write(b []byte) (int, error) {
	select {
	case <-c.closeNotify:
		return 0, errSocks5UdpClosed
	default:
	}

	frameSize := len(c.targetHdr) + len(b)
	buf := pool.GetBuf(frameSize)
	defer pool.ReleaseBuf(buf)

	copy(*buf, c.targetHdr)
	copy((*buf)[len(c.targetHdr):], b)

	if _, err := c.udpConn.Write((*buf)[:frameSize]); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UdpConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeNotify)
		c.tcpConn.Close()
		c.udpConn.Close()
	})
	c.monitorWg.Wait()
	return nil
}

func (c *socks5UdpConn) LocalAddr() net.Addr  { return c.udpConn.LocalAddr() }
func (c *socks5UdpConn) RemoteAddr() net.Addr { return c.udpConn.RemoteAddr() }
func (c *socks5UdpConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c *socks5UdpConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *socks5UdpConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// tcpMonitor 持续读取 TCP 控制连接，检测其存活状态。
// TCP 断开后立即触发 UDP deadline，使 readLoop 快速失败并重建连接。
func (c *socks5UdpConn) tcpMonitor() {
	defer c.monitorWg.Done()
	io.Copy(io.Discard, c.tcpConn)
	select {
	case <-c.closeNotify:
		return // Close() already closed everything
	default:
	}
	c.udpConn.SetDeadline(time.Now())
}

// newSocks5UdpConn 通过 SOCKS5 代理建立 UDP ASSOCIATE 连接。
func newSocks5UdpConn(ctx context.Context, s5Addr, targetAddr string, dialer *net.Dialer) (*socks5UdpConn, error) {
	tcpConn, err := dialer.DialContext(ctx, "tcp", s5Addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: failed to dial tcp to proxy, %w", err)
	}

	relayAddr, err := socks5Associate(tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	if udpAddr, ok := relayAddr.(*net.UDPAddr); ok && udpAddr.Port == 0 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5: relay port is 0, unable to establish udp connection")
	}

	udpConn, err := dialer.DialContext(ctx, "udp", relayAddr.String())
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5: failed to dial udp to relay, %w", err)
	}

	targetHdr, err := buildSocks5TargetHdr(targetAddr)
	if err != nil {
		tcpConn.Close()
		udpConn.Close()
		return nil, err
	}

	c := &socks5UdpConn{
		udpConn:     udpConn,
		tcpConn:     tcpConn,
		targetHdr:   targetHdr,
		readBuf:     make([]byte, socks5ReadBufSize),
		closeNotify: make(chan struct{}),
	}
	c.monitorWg.Add(1)
	go c.tcpMonitor()
	return c, nil
}

// socks5Associate 在已建立的 TCP 连接上执行 SOCKS5 握手并请求 UDP ASSOCIATE。
// 返回代理分配的 UDP 中继地址。
func socks5Associate(tcpConn net.Conn) (net.Addr, error) {
	// 握手超时 5 秒，与 dialer 默认超时一致
	if err := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("socks5: failed to set handshake deadline, %w", err)
	}
	defer tcpConn.SetDeadline(time.Time{}) // 清除 deadline，交由后续 tcpMonitor 管理

	var buf [22]byte

	// 方法协商
	buf[0] = socks5Ver
	buf[1] = 1
	buf[2] = 0x00 // 仅支持无认证
	if _, err := tcpConn.Write(buf[:3]); err != nil {
		return nil, fmt.Errorf("socks5: failed to send method negotiation, %w", err)
	}

	if _, err := io.ReadFull(tcpConn, buf[:2]); err != nil {
		return nil, fmt.Errorf("socks5: failed to read method selection, %w", err)
	}
	if buf[0] != socks5Ver || buf[1] != 0x00 {
		return nil, fmt.Errorf("socks5: server rejected no-auth method (method=%d)", buf[1])
	}

	// UDP ASSOCIATE with DST.ADDR=0.0.0.0, DST.PORT=0 (RFC 1928 NAT scenario).
	// buf[4:10] remains zeroed from the previous write or from the initial var declaration.
	buf[0] = socks5Ver
	buf[1] = socks5CmdUDPAssoc
	buf[2] = 0x00
	buf[3] = socks5AtypIPv4
	if _, err := tcpConn.Write(buf[:10]); err != nil {
		return nil, fmt.Errorf("socks5: failed to send UDP ASSOCIATE, %w", err)
	}

	if _, err := io.ReadFull(tcpConn, buf[:4]); err != nil {
		return nil, fmt.Errorf("socks5: failed to read UDP ASSOCIATE response, %w", err)
	}
	if buf[0] != socks5Ver || buf[1] != 0x00 {
		return nil, fmt.Errorf("socks5: UDP ASSOCIATE rejected (rep=%d)", buf[1])
	}

	return readSocks5Addr(tcpConn, buf[3])
}

// readSocks5Addr 从连接中读取 SOCKS5 格式的地址。
func readSocks5Addr(r io.Reader, atyp byte) (net.Addr, error) {
	switch atyp {
	case socks5AtypIPv4:
		var raw [6]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return nil, fmt.Errorf("socks5: failed to read IPv4 relay address, %w", err)
		}
		return &net.UDPAddr{
			IP:   net.IP(raw[:4]),
			Port: int(binary.BigEndian.Uint16(raw[4:6])),
		}, nil

	case socks5AtypIPv6:
		var raw [18]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return nil, fmt.Errorf("socks5: failed to read IPv6 relay address, %w", err)
		}
		return &net.UDPAddr{
			IP:   net.IP(raw[:16]),
			Port: int(binary.BigEndian.Uint16(raw[16:18])),
		}, nil

	case socks5AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("socks5: failed to read domain length, %w", err)
		}
		domainLen := int(lenBuf[0])
		body := make([]byte, domainLen+2)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("socks5: failed to read relay domain, %w", err)
		}
		port := binary.BigEndian.Uint16(body[domainLen:])
		ips, err := net.LookupIP(string(body[:domainLen]))
		if err != nil {
			return nil, fmt.Errorf("socks5: failed to resolve relay domain, %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("socks5: relay domain resolved to empty result: %s", string(body[:domainLen]))
		}
		return &net.UDPAddr{IP: ips[0], Port: int(port)}, nil

	default:
		return nil, fmt.Errorf("socks5: unsupported address type: %d", atyp)
	}
}

// buildSocks5TargetHdr 根据目标地址构建 SOCKS5 UDP 帧头（不含载荷）。
func buildSocks5TargetHdr(targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid target address, %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid target port, %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("socks5: target address must be an IP: %s", host)
	}

	if ip4 := ip.To4(); ip4 != nil {
		hdr := make([]byte, 10)
		hdr[3] = socks5AtypIPv4
		copy(hdr[4:8], ip4)
		binary.BigEndian.PutUint16(hdr[8:10], uint16(port))
		return hdr, nil
	}

	hdr := make([]byte, socks5MaxFrameHdr)
	hdr[3] = socks5AtypIPv6
	copy(hdr[4:20], ip.To16())
	binary.BigEndian.PutUint16(hdr[20:22], uint16(port))
	return hdr, nil
}

// socks5Unframe 从 SOCKS5 UDP 帧中提取 DNS 载荷到 payload 缓冲区。
func socks5Unframe(framed, payload []byte) (int, error) {
	if len(framed) < 4 {
		return 0, fmt.Errorf("socks5: frame too short: %d bytes", len(framed))
	}
	if framed[2] != 0x00 {
		return 0, fmt.Errorf("socks5: fragmentation not supported (frag=%d)", framed[2])
	}

	var hdrLen int
	switch atyp := framed[3]; atyp {
	case socks5AtypIPv4:
		hdrLen = 10
	case socks5AtypIPv6:
		hdrLen = socks5MaxFrameHdr
	case socks5AtypDomain:
		if len(framed) < 5 {
			return 0, fmt.Errorf("socks5: invalid domain address format")
		}
		hdrLen = 4 + 1 + int(framed[4]) + 2
	default:
		return 0, fmt.Errorf("socks5: unknown address type: %d", atyp)
	}

	if hdrLen > len(framed) {
		return 0, fmt.Errorf("socks5: header length %d exceeds data length %d", hdrLen, len(framed))
	}

	payloadSize := len(framed) - hdrLen
	if payloadSize > len(payload) {
		payloadSize = len(payload) // Truncate to caller buffer size, consistent with native UDP behavior
	}

	return copy(payload, framed[hdrLen:hdrLen+payloadSize]), nil
}
