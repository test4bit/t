// Package warpcontrol exposes a deliberately restricted SSH control plane on the VPN address.
package warpcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/crypto/ssh"
)

// Device is the subset of amneziawg-go's UAPI needed for endpoint management.
type Device interface {
	IpcSet(string) error
	IpcGet() (string, error)
}

type Config struct {
	Address      string
	HostKey      []byte
	Password     string
	PeerKey      string // base64 WireGuard public key
	ScoutPath    string // optional, an absolute path to the installed warpscout binary
	ScoutAccount string // optional, an absolute path to an existing account file
}

type Server struct {
	ln                      net.Listener
	ssh                     *ssh.ServerConfig
	dev                     Device
	peerHex                 string
	scoutPath, scoutAccount string
	mu                      sync.Mutex
	ctx                     context.Context
	cancel                  context.CancelFunc
	wg                      sync.WaitGroup
	connMu                  sync.Mutex
	conns                   map[net.Conn]struct{}
	closed                  bool
	scanning                chan struct{}
}

// StartInNetNS creates the listening socket inside ns and restores the calling thread.
// It does not change the namespace of the device's UDP socket, nor of warpscout.
func StartInNetNS(ns netns.NsHandle, cfg Config, dev Device) (*Server, error) {
	s, err := newServer(cfg, dev)
	if err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		s.cancel()
		return nil, err
	}
	if err = netns.Set(ns); err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		s.cancel()
		return nil, err
	}
	ln, listenErr := net.Listen("tcp4", cfg.Address)
	restoreErr := netns.Set(orig)
	orig.Close()
	// If restoration failed, do not return the contaminated OS thread to the Go pool.
	if restoreErr == nil {
		runtime.UnlockOSThread()
	}
	if restoreErr != nil {
		if ln != nil {
			ln.Close()
		}
		s.cancel()
		return nil, fmt.Errorf("restore netns: %w", restoreErr)
	}
	if listenErr != nil {
		s.cancel()
		return nil, fmt.Errorf("listen in netns: %w", listenErr)
	}
	s.serve(ln)
	return s, nil
}

func newServer(cfg Config, dev Device) (*Server, error) {
	if len(cfg.Password) < 16 {
		return nil, errors.New("WARP_SSH_PASSWORD must be at least 16 bytes")
	}
	if dev == nil {
		return nil, errors.New("nil WARP device")
	}
	signer, err := ssh.ParsePrivateKey(cfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("SSH host key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(cfg.PeerKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid WARP peer public key")
	}
	passwordHash := sha256.Sum256([]byte(cfg.Password))
	sshCfg := &ssh.ServerConfig{MaxAuthTries: 3, PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		got := sha256.Sum256(p)
		if c.User() != "warp" || subtle.ConstantTimeCompare(got[:], passwordHash[:]) != 1 {
			return nil, errors.New("authentication failed")
		}
		return &ssh.Permissions{}, nil
	}}
	sshCfg.AddHostKey(signer)
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{ssh: sshCfg, dev: dev, peerHex: hex.EncodeToString(key), scoutPath: cfg.ScoutPath, scoutAccount: cfg.ScoutAccount, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{}), scanning: make(chan struct{}, 1)}, nil
}

func (s *Server) serve(ln net.Listener) {
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		sem := make(chan struct{}, 8)
		for {
			c, err := ln.Accept()
			if err != nil {
				if s.ctx.Err() == nil {
					log.Printf("warp SSH accept: %v", err)
				}
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				c.Close()
				continue
			}
			s.connMu.Lock()
			if s.closed {
				s.connMu.Unlock()
				<-sem
				c.Close()
				continue
			}
			s.conns[c] = struct{}{}
			s.wg.Add(1)
			s.connMu.Unlock()
			go func() {
				defer s.wg.Done()
				defer func() { <-sem; s.connMu.Lock(); delete(s.conns, c); s.connMu.Unlock(); c.Close() }()
				s.handle(c)
			}()
		}
	}()
}

func (s *Server) Close() {
	s.cancel()
	if s.ln != nil {
		s.ln.Close()
	}
	s.connMu.Lock()
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	s.connMu.Unlock()
	s.wg.Wait()
}

func (s *Server) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(c, s.ssh)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			channel.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, reqs, err := channel.Accept()
		if err != nil {
			continue
		}
		// Only one exec per connection. No shell, PTY, SFTP, forwarding or arbitrary commands.
		for req := range reqs {
			if req.Type != "exec" {
				req.Reply(false, nil)
				continue
			}
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil || len(payload.Command) > 256 {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			output, err := s.command(payload.Command)
			if err != nil {
				fmt.Fprintln(ch.Stderr(), err)
			} else {
				fmt.Fprintln(ch, output)
			}
			code := uint32(0)
			if err != nil {
				code = 1
			}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
			ch.Close()
			return
		}
		ch.Close()
	}
}

// Explicit WARP IPv4 pools, matching warpscout's WireGuard pools at the pinned
// version. Update deliberately if Cloudflare adds pools; private IPs and hostnames
// are not accepted, preventing arbitrary UDP redirection via this control channel.
var warpPools = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{"8.6.112.0/24", "8.34.70.0/24", "8.34.146.0/24", "8.35.211.0/24", "8.39.125.0/24", "8.39.204.0/24", "8.39.214.0/24", "8.47.69.0/24", "162.159.192.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

func validateEndpoint(value string) (string, error) {
	ep, err := netip.ParseAddrPort(value)
	if err != nil || !ep.Addr().Is4() || ep.Port() == 0 {
		return "", errors.New("expected IPv4:port with nonzero port")
	}
	for _, p := range warpPools {
		if p.Contains(ep.Addr()) {
			return ep.String(), nil
		}
	}
	return "", errors.New("address is outside the configured WARP IPv4 pools")
}

func (s *Server) command(command string) (string, error) {
	fields := strings.Fields(command)
	if len(fields) == 1 && fields[0] == "status" {
		return s.status()
	}
	if len(fields) == 2 && fields[0] == "set" {
		return s.set(fields[1])
	}
	if len(fields) == 1 && fields[0] == "scan" {
		ep, err := s.scan()
		if err != nil {
			return "", err
		}
		return s.set(ep)
	}
	return "", errors.New("commands: status | set IPv4:port | scan")
}
func (s *Server) status() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.dev.IpcGet()
	if err != nil {
		return "", err
	}
	active := false
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "public_key=") {
			active = strings.TrimPrefix(line, "public_key=") == s.peerHex
		}
		if active && strings.HasPrefix(line, "endpoint=") {
			return line, nil
		}
	}
	return "", errors.New("WARP peer or endpoint not found")
}
func (s *Server) set(value string) (string, error) {
	endpoint, err := validateEndpoint(value)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// update_only silently ignores a missing peer, so check first.
	state, err := s.dev.IpcGet()
	if err != nil {
		return "", err
	}
	if !strings.Contains("\n"+state, "\npublic_key="+s.peerHex+"\n") {
		return "", errors.New("WARP peer not found")
	}
	// update_only prevents creating an accidental new peer.
	if err := s.dev.IpcSet("public_key=" + s.peerHex + "\nupdate_only=true\nendpoint=" + endpoint + "\n"); err != nil {
		return "", fmt.Errorf("set endpoint: %w", err)
	}
	return "endpoint requested=" + endpoint + " (not yet verified; use status to inspect)", nil
}
func (s *Server) scan() (string, error) {
	select {
	case s.scanning <- struct{}{}:
		defer func() { <-s.scanning }()
	default:
		return "", errors.New("scan already running")
	}
	if s.scoutPath == "" || s.scoutAccount == "" || !strings.HasPrefix(s.scoutPath, "/") || !strings.HasPrefix(s.scoutAccount, "/") {
		return "", errors.New("scan unavailable: configure absolute WARP_SCOUT_PATH and WARP_SCOUT_ACCOUNT")
	}
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Minute)
	defer cancel()
	// Scan in the host network namespace, exactly like the WARP UDP socket.
	cmd := exec.CommandContext(ctx, s.scoutPath, "scan", "-p", "wg", "-best", "-plain", "-no-report", "-a", s.scoutAccount)
	cmd.Stderr = io.Discard // may contain account paths; do not return secrets over SSH
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("warpscout canceled or timed out: %w", ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("warpscout failed: %w", err)
	}
	if len(out) > 256 {
		return "", errors.New("unexpected warpscout output")
	}
	return validateEndpoint(strings.TrimSpace(string(out)))
}

// ConfigFromEnv is intentionally opt-in; a missing key and password disable SSH.
// Providing only one is an error, rather than silently exposing a weak service.
func ConfigFromEnv(peerKey, address string) (Config, bool, error) {
	key, pass := os.Getenv("WARP_SSH_HOST_KEY"), os.Getenv("WARP_SSH_PASSWORD")
	if key == "" && pass == "" {
		return Config{}, false, nil
	}
	if key == "" || pass == "" {
		return Config{}, false, errors.New("set both WARP_SSH_HOST_KEY and WARP_SSH_PASSWORD")
	}
	return Config{Address: address, HostKey: []byte(key), Password: pass, PeerKey: peerKey, ScoutPath: os.Getenv("WARP_SCOUT_PATH"), ScoutAccount: os.Getenv("WARP_SCOUT_ACCOUNT")}, true, nil
}
