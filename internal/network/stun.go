// File: internal/network/stun.go
package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pion/stun"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func GetExternalIPAndPort(port int, stunServers []string) (string, int, error) {
	var lastErr error
	for _, server := range stunServers {
		ip, p, err := querySTUN(server, port)
		if err == nil {
			return ip, p, nil
		}
		lastErr = err
	}
	return "", 0, fmt.Errorf("all STUN servers failed: %w", lastErr)
}

func querySTUN(server string, port int) (string, int, error) {
	addr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", 0, err
	}

	lc := net.ListenConfig{
		Control: func(n, a string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	for range 3 {
		if _, err := conn.WriteTo(msg.Raw, addr); err != nil {
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		resp := new(stun.Message)
		resp.Raw = buf[:n]
		if err := resp.Decode(); err != nil {
			continue
		}

		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(resp); err == nil {
			return xorAddr.IP.String(), xorAddr.Port, nil
		}
	}

	return "", 0, fmt.Errorf("no response from %s", server)
}

func PunchNATOnce(lport int, ip string, dport int, ttl int) {
	lc := net.ListenConfig{
		Control: func(n, a string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			})
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", lport))
	if err != nil {
		log.Printf("warning: open punch socket: %v", err)
		return
	}
	defer conn.Close()

	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", ip, dport))
	if err != nil {
		log.Printf("warning: resolve punch target: %v", err)
		return
	}
	for range 3 {
		if _, err := conn.WriteTo([]byte{0}, addr); err != nil {
			log.Printf("warning: NAT punch write: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func StartKeepalive(localPort int, sIP string, sPort int) func() {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	lc := net.ListenConfig{
		Control: func(n, a string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", localPort))
	if err != nil {
		log.Printf("warning: keepalive socket port %d: %v", localPort, err)
		cancel()
		return func() {}
	}

	target := "1.1.1.1:53"
	if sIP != "" && sPort != 0 {
		target = fmt.Sprintf("%s:%d", sIP, sPort)
	}
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		log.Printf("warning: resolve keepalive target %s: %v", target, err)
		addr, _ = net.ResolveUDPAddr("udp4", "8.8.8.8:53")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer conn.Close()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			if _, err := conn.WriteTo([]byte{0}, addr); err != nil {
				log.Printf("warning: keepalive write: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return func() {
		cancel()
		wg.Wait()
	}
}

func CheckVPNHealth(nsFd netns.NsHandle) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		log.Printf("warning: health check get ns: %v", err)
		return false
	}
	defer origns.Close()
	defer netns.Set(origns)

	if err := netns.Set(nsFd); err != nil {
		log.Printf("warning: health check set ns: %v", err)
		return false
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		log.Printf("warning: health check socket: %v", err)
		return false
	}
	defer unix.Close(fd)

	sa := unix.SockaddrInet4{Port: 53}
	copy(sa.Addr[:], net.ParseIP("1.1.1.1").To4())

	if err := unix.Connect(fd, &sa); err != nil && err != unix.EINPROGRESS {
		return false
	}

	pollFds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	n, err := unix.Poll(pollFds, 5000)
	if err != nil || n <= 0 {
		return false
	}

	sockErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil || sockErr != 0 {
		return false
	}
	return true
}

// STUNMapping captures one observation. Comparing different servers is meaningful
// only while using the same live socket (and during a short measurement window).
type STUNMapping struct {
	Server string
	IP     string
	Port   int
}

func ProbeSTUNMappings(port int, servers []string) ([]STUNMapping, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				sockErr = err
				return
			}
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	c, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("STUN socket: %w", err)
	}
	defer c.Close()
	var results []STUNMapping
	for _, server := range servers {
		addr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			log.Printf("STUN %s: %v", server, err)
			continue
		}
		msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		var found bool
		for attempt := 0; attempt < 2 && !found; attempt++ {
			if _, err = c.WriteTo(msg.Raw, addr); err != nil {
				break
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 2048)
			for {
				n, src, e := c.ReadFrom(buf)
				if e != nil {
					break
				}
				udp, ok := src.(*net.UDPAddr)
				if !ok || !udp.IP.Equal(addr.IP) || udp.Port != addr.Port {
					continue
				}
				response := new(stun.Message)
				response.Raw = buf[:n]
				if response.Decode() != nil || response.TransactionID != msg.TransactionID || response.Type != stun.BindingSuccess {
					continue
				}
				var mapped stun.XORMappedAddress
				if mapped.GetFrom(response) == nil && mapped.IP.To4() != nil {
					results = append(results, STUNMapping{Server: server, IP: mapped.IP.String(), Port: mapped.Port})
					found = true
					break
				}
			}
		}
		if !found {
			log.Printf("STUN %s: no valid response", server)
		}
		if len(results) >= 2 {
			break
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("all STUN servers failed")
	}
	return results, nil
}
