package network

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSTUNMappingsUsesSameSocket(t *testing.T) {
	var servers []string
	ports := make(chan int, 2)
	for _, mappedPort := range []uint16{10001, 10002} {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		servers = append(servers, conn.LocalAddr().String())
		go func(c *net.UDPConn, p uint16) {
			buf := make([]byte, 1500)
			n, src, e := c.ReadFromUDP(buf)
			if e != nil || n < 20 {
				return
			}
			ports <- src.Port
			makeResponse := func(valid bool) []byte {
				b := make([]byte, 32)
				binary.BigEndian.PutUint16(b, 0x0101)
				binary.BigEndian.PutUint16(b[2:], 12)
				binary.BigEndian.PutUint32(b[4:], 0x2112a442)
				copy(b[8:20], buf[8:20])
				if !valid {
					b[8] ^= 0xff
				}
				binary.BigEndian.PutUint16(b[20:], 0x0020)
				binary.BigEndian.PutUint16(b[22:], 8)
				b[25] = 1
				binary.BigEndian.PutUint16(b[26:], p^0x2112)
				binary.BigEndian.PutUint32(b[28:], 0x0a000001^0x2112a442)
				return b
			}
			c.WriteToUDP(makeResponse(false), src)
			c.WriteToUDP(makeResponse(true), src)
		}(conn, mappedPort)
	}
	result, err := ProbeSTUNMappings(0, servers)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result[0].Port != 10001 || result[1].Port != 10002 {
		t.Fatalf("unexpected mapped results: %+v", result)
	}
	a, b := <-ports, <-ports
	if a != b {
		t.Fatalf("different source ports %d %d", a, b)
	}
}
func TestRawPunchPortAndCoexistence(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stop, err := StartNATPuncher(45321, "127.0.0.1", c.LocalAddr().(*net.UDPAddr).Port, 4)
	if err != nil {
		t.Skipf("raw socket unavailable: %v", err)
	}
	defer stop()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 32)
	n, addr, err := c.ReadFromUDP(b)
	if err != nil || n != 1 || addr.Port != 45321 {
		t.Fatalf("received n=%d addr=%v err=%v", n, addr, err)
	}
	// The raw sender does not occupy the UDP source port.
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 45321})
	if err != nil {
		t.Fatalf("raw sender blocked UDP bind: %v", err)
	}
	listener.Close()
}
