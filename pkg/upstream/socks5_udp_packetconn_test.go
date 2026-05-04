package upstream

import (
	"bytes"
	"net"
	"testing"
)

func Test_socks5UdpPacketConn_WriteTo(t *testing.T) {
	// Build a minimal IPv4 frame header for 1.1.1.1:53
	targetHdr := []byte{
		0x00, 0x00, // RSV
		0x00,       // FRAG
		0x01,       // ATYP IPv4
		1, 1, 1, 1, // IP
		0x00, 0x35, // PORT 53
	}

	// Create a connected UDP pair for testing
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	server, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	c := &socks5UdpPacketConn{
		udpConn:     client,
		tcpConn:     client, // dummy, not used in this test
		targetHdr:   targetHdr,
		readBuf:     make([]byte, socks5ReadBufSize),
		relayAddr:   server.LocalAddr(),
		closeNotify: make(chan struct{}),
	}

	payload := []byte{0xAA, 0xBB, 0xCC}
	n, err := c.WriteTo(payload, nil)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo() n = %d, want %d", n, len(payload))
	}

	// Read the framed datagram from the server side
	buf := make([]byte, 2048)
	nr, err := server.Read(buf)
	if err != nil {
		t.Fatalf("server Read() error = %v", err)
	}

	// Verify: frame header + payload (use copy to avoid modifying targetHdr)
	expected := make([]byte, len(targetHdr)+len(payload))
	copy(expected, targetHdr)
	copy(expected[len(targetHdr):], payload)
	if !bytes.Equal(buf[:nr], expected) {
		t.Errorf("server received %x, want %x", buf[:nr], expected)
	}
}

func Test_socks5UdpPacketConn_ReadFrom(t *testing.T) {
	// Build a minimal IPv4 frame for the response
	framed := []byte{
		0x00, 0x00, // RSV
		0x00,       // FRAG
		0x01,       // ATYP IPv4
		1, 2, 3, 4, // IP
		0x00, 0x35, // PORT 53
		0xAA, 0xBB, 0xCC, // payload
	}

	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	server, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	c := &socks5UdpPacketConn{
		udpConn:     client,
		tcpConn:     client,
		readBuf:     make([]byte, socks5ReadBufSize),
		relayAddr:   server.LocalAddr(),
		closeNotify: make(chan struct{}),
	}

	// Server sends a framed datagram to the client
	_, err = server.WriteToUDP(framed, client.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("server WriteToUDP() error = %v", err)
	}

	// Client reads via ReadFrom
	payload := make([]byte, 2048)
	n, addr, err := c.ReadFrom(payload)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if n != 3 {
		t.Errorf("ReadFrom() n = %d, want 3", n)
	}
	if !bytes.Equal(payload[:n], []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("ReadFrom() payload = %x, want AABBCC", payload[:n])
	}
	if addr != c.relayAddr {
		t.Errorf("ReadFrom() addr = %v, want relay addr %v", addr, c.relayAddr)
	}
}

func Test_socks5UdpPacketConn_Close(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	server, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	c := &socks5UdpPacketConn{
		udpConn:     client,
		tcpConn:     client,
		readBuf:     make([]byte, socks5ReadBufSize),
		relayAddr:   server.LocalAddr(),
		closeNotify: make(chan struct{}),
	}

	// Close should be idempotent
	if err := c.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	// WriteTo after close should fail
	_, err = c.WriteTo([]byte{0x01}, nil)
	if err == nil {
		t.Error("WriteTo() after Close should return error")
	}

	// ReadFrom after close should fail
	_, _, err = c.ReadFrom(make([]byte, 2048))
	if err == nil {
		t.Error("ReadFrom() after Close should return error")
	}
}
