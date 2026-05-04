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
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
)

// socks5UdpPacketConn implements net.PacketConn over SOCKS5 UDP ASSOCIATE.
// Unlike socks5UdpConn (which implements net.Conn for stream-oriented DNS),
// this type provides datagram-oriented ReadFrom/WriteTo for QUIC/H3 protocols.
//
// WriteTo ignores the addr parameter — all packets are sent to the SOCKS5 relay
// with the pre-built target frame header. ReadFrom returns the relay address as
// the source. quic-go demultiplexes by Connection ID, not by address tuple,
// so this is safe for multiple QUIC connections sharing one PacketConn.
type socks5UdpPacketConn struct {
	udpConn   net.Conn // connected UDP socket to SOCKS5 relay
	tcpConn   net.Conn // SOCKS5 TCP control connection
	targetHdr []byte   // pre-built SOCKS5 frame header for the target address
	readBuf   []byte   // read buffer, sized for max framed datagram
	relayAddr net.Addr // relay address, returned by ReadFrom

	closeOnce   sync.Once
	closeNotify chan struct{}
	monitorWg   sync.WaitGroup // waits for tcpMonitor goroutine to exit
}

func (c *socks5UdpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closeNotify:
		return 0, nil, errSocks5UdpClosed
	default:
	}

	n, err := c.udpConn.Read(c.readBuf)
	if err != nil {
		return 0, nil, err
	}
	payloadLen, err := socks5Unframe(c.readBuf[:n], p)
	if err != nil {
		return 0, nil, err
	}
	return payloadLen, c.relayAddr, nil
}

func (c *socks5UdpPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closeNotify:
		return 0, errSocks5UdpClosed
	default:
	}

	frameSize := len(c.targetHdr) + len(p)
	buf := pool.GetBuf(frameSize)
	defer pool.ReleaseBuf(buf)

	copy(*buf, c.targetHdr)
	copy((*buf)[len(c.targetHdr):], p)

	if _, err := c.udpConn.Write((*buf)[:frameSize]); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UdpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeNotify)
		c.tcpConn.Close()
		c.udpConn.Close()
	})
	c.monitorWg.Wait()
	return nil
}

func (c *socks5UdpPacketConn) LocalAddr() net.Addr  { return c.udpConn.LocalAddr() }
func (c *socks5UdpPacketConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}
func (c *socks5UdpPacketConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}
func (c *socks5UdpPacketConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// tcpMonitor continuously reads the TCP control connection to detect its liveness.
// When TCP dies, it immediately triggers the UDP deadline so that the quic.Transport
// read loop fails fast and closes all associated QUIC connections.
func (c *socks5UdpPacketConn) tcpMonitor() {
	defer c.monitorWg.Done()
	io.Copy(io.Discard, c.tcpConn)
	select {
	case <-c.closeNotify:
		return // Close() already closed everything
	default:
	}
	c.udpConn.SetDeadline(time.Now())
}

// newSocks5UdpPacketConn establishes a SOCKS5 UDP ASSOCIATE and returns a
// net.PacketConn suitable for quic.Transport.
func newSocks5UdpPacketConn(ctx context.Context, s5Addr, targetAddr string, dialer *net.Dialer) (*socks5UdpPacketConn, error) {
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

	c := &socks5UdpPacketConn{
		udpConn:     udpConn,
		tcpConn:     tcpConn,
		targetHdr:   targetHdr,
		readBuf:     make([]byte, socks5ReadBufSize),
		relayAddr:   relayAddr,
		closeNotify: make(chan struct{}),
	}
	c.monitorWg.Add(1)
	go c.tcpMonitor()
	return c, nil
}
