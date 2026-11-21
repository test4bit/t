//go:build linux

package network

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// StartNATPuncher sends low-TTL UDP packets with a raw socket. Unlike a second
// SO_REUSEPORT listener, a raw sending socket cannot steal WireGuard packets.
// The source port matches the AWG listener; the loop keeps NAT filtering open.
func StartNATPuncher(localPort int, targetIP string, targetPort, ttl int) (func(), error) {
	return startNATPuncher(localPort, targetIP, targetPort, ttl, 25*time.Second)
}

func startNATPuncher(localPort int, targetIP string, targetPort, ttl int, interval time.Duration) (func(), error) {
	if interval <= 0 {
		return nil, fmt.Errorf("invalid NAT punch interval")
	}
	ip := net.ParseIP(targetIP).To4()
	if ip == nil || localPort < 1 || localPort > 65535 || targetPort < 1 || targetPort > 65535 || ttl < 1 || ttl > 255 {
		return nil, fmt.Errorf("invalid NAT punch parameters")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw NAT punch socket (CAP_NET_RAW required): %w", err)
	}
	dest := &unix.SockaddrInet4{Port: targetPort}
	copy(dest.Addr[:], ip)
	// Linux IP_HDRINCL fills source address, ID and IP checksum when zero.
	packet := make([]byte, 29)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = byte(ttl)
	packet[9] = unix.IPPROTO_UDP
	copy(packet[16:20], ip)
	binary.BigEndian.PutUint16(packet[20:22], uint16(localPort))
	binary.BigEndian.PutUint16(packet[22:24], uint16(targetPort))
	binary.BigEndian.PutUint16(packet[24:26], 9)
	send := func() error { return unix.Sendto(fd, packet, 0, dest) }
	if err := send(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("initial NAT punch: %w", err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := send(); err != nil {
					log.Printf("warning: periodic NAT punch: %v", err)
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop); <-done; unix.Close(fd) }) }, nil
}
