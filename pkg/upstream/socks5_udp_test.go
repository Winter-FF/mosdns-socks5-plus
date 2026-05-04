package upstream

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func Test_buildSocks5TargetHdr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantHdr []byte
		wantErr bool
	}{
		{
			name: "ipv4",
			addr: "1.1.1.1:53",
			wantHdr: []byte{
				0x00, 0x00, // RSV
				0x00,       // FRAG
				0x01,       // ATYP IPv4
				1, 1, 1, 1, // IP
				0x00, 0x35, // PORT 53
			},
		},
		{
			name: "ipv6",
			addr: "[2001:4860:4860::8888]:53",
			wantHdr: []byte{
				0x00, 0x00, // RSV
				0x00,       // FRAG
				0x04,       // ATYP IPv6
				0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
				0x00, 0x35, // PORT 53
			},
		},
		{
			name:    "no_port",
			addr:    "1.1.1.1",
			wantErr: true,
		},
		{
			name:    "domain_target",
			addr:    "dns.google:53",
			wantErr: true,
		},
		{
			name:    "invalid_addr",
			addr:    "not-an-addr",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, err := buildSocks5TargetHdr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("buildSocks5TargetHdr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !bytes.Equal(hdr, tt.wantHdr) {
				t.Errorf("buildSocks5TargetHdr(%q) = %x, want %x", tt.addr, hdr, tt.wantHdr)
			}
		})
	}
}

func Test_readSocks5Addr(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		atyp     byte
		wantIP   string
		wantPort int
		wantErr  bool
	}{
		{
			name: "ipv4",
			data: []byte{1, 2, 3, 4, 0x00, 0x35},
			atyp: socks5AtypIPv4,
			wantIP: "1.2.3.4",
			wantPort: 53,
		},
		{
			name: "ipv6",
			data: func() []byte {
				b := make([]byte, 18)
				b[0] = 0x20
				b[1] = 0x01
				binary.BigEndian.PutUint16(b[16:18], 53)
				return b
			}(),
			atyp: socks5AtypIPv6,
			wantIP: "2001::",
			wantPort: 53,
		},
		{
			name:    "too_short",
			data:    []byte{1, 2},
			atyp:    socks5AtypIPv4,
			wantErr: true,
		},
		{
			name:    "unsupported_type",
			data:    []byte{0xff},
			atyp:    0xff,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			addr, err := readSocks5Addr(r, tt.atyp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readSocks5Addr() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				t.Fatalf("readSocks5Addr() returned %T, want *net.UDPAddr", addr)
			}
			if udpAddr.IP.String() != tt.wantIP {
				t.Errorf("IP = %s, want %s", udpAddr.IP, tt.wantIP)
			}
			if udpAddr.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", udpAddr.Port, tt.wantPort)
			}
		})
	}
}

func Test_readSocks5AddrDomain(t *testing.T) {
	domain := "example.com"
	domainLen := byte(len(domain))
	port := uint16(53)

	var buf bytes.Buffer
	buf.WriteByte(domainLen)
	buf.WriteString(domain)
	binary.Write(&buf, binary.BigEndian, port)

	addr, err := readSocks5Addr(&buf, socks5AtypDomain)
	if err != nil {
		t.Fatalf("readSocks5Addr(domain) error = %v", err)
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("returned %T, want *net.UDPAddr", addr)
	}
	if udpAddr.Port != 53 {
		t.Errorf("Port = %d, want 53", udpAddr.Port)
	}
	// DNS resolution result may vary by environment, only verify port and non-empty IP
	if len(udpAddr.IP) == 0 {
		t.Error("IP is empty")
	}
}

func Test_socks5Unframe(t *testing.T) {
	tests := []struct {
		name    string
		framed  []byte
		bufSize int // 0 = default 2048
		wantN   int
		wantErr bool
	}{
		{
			name: "ipv4",
			framed: []byte{
				0x00, 0x00, // RSV
				0x00,       // FRAG
				0x01,       // ATYP IPv4
				1, 2, 3, 4, // ADDR
				0x00, 0x35, // PORT
				0x01, 0x02, 0x03, // payload
			},
			wantN: 3,
		},
		{
			name: "ipv6",
			framed: func() []byte {
				b := make([]byte, 22+5)
				b[3] = socks5AtypIPv6
				copy(b[22:], []byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e})
				return b
			}(),
			wantN: 5,
		},
		{
			name: "domain",
			framed: func() []byte {
				domain := "a.b"
				b := make([]byte, 4+1+len(domain)+2+3)
				b[3] = socks5AtypDomain
				b[4] = byte(len(domain))
				copy(b[5:5+len(domain)], domain)
				binary.BigEndian.PutUint16(b[5+len(domain):], 53)
				copy(b[5+len(domain)+2:], []byte{0xAA, 0xBB, 0xCC})
				return b
			}(),
			wantN: 3,
		},
		{
			name:    "too_short_frame",
			framed:  []byte{0x00, 0x00},
			wantErr: true,
		},
		{
			name: "fragmentation_not_supported",
			framed: []byte{
				0x00, 0x00, // RSV
				0x01,       // FRAG=1
				0x01,       // ATYP
				1, 2, 3, 4,
				0x00, 0x35,
			},
			wantErr: true,
		},
		{
			name:   "unknown_atyp",
			framed: []byte{0x00, 0x00, 0x00, 0xff},
			wantErr: true,
		},
		{
			name: "payload_truncated",
			framed: []byte{
				0x00, 0x00, 0x00, 0x01,
				1, 2, 3, 4, 0x00, 0x35,
				0xAA, 0xBB, // 2-byte payload
			},
			bufSize: 1, // buffer too small → truncated
			wantN:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bufSize := tt.bufSize
			if bufSize == 0 {
				bufSize = 2048
			}
			payload := make([]byte, bufSize)
			n, err := socks5Unframe(tt.framed, payload)
			if (err != nil) != tt.wantErr {
				t.Fatalf("socks5Unframe() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if n != tt.wantN {
				t.Errorf("socks5Unframe() n = %d, want %d", n, tt.wantN)
			}
		})
	}
}
