package warpcontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeDevice struct {
	mu            sync.Mutex
	key, endpoint string
	calls         int
}

func (f *fakeDevice) IpcGet() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("private_key=secret\npublic_key=%s\nendpoint=%s\n", f.key, f.endpoint), nil
}
func (f *fakeDevice) IpcSet(v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	for _, line := range strings.Split(v, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			f.endpoint = strings.TrimPrefix(line, "endpoint=")
		}
	}
	return nil
}
func testServer(t *testing.T) (*Server, *fakeDevice, ssh.PublicKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	peer := make([]byte, 32)
	rand.Read(peer)
	cfg := Config{HostKey: pem.EncodeToMemory(block), Password: "very-long-test-password", PeerKey: base64.StdEncoding.EncodeToString(peer)}
	fake := &fakeDevice{key: hex.EncodeToString(peer), endpoint: "162.159.192.1:2408"}
	s, err := newServer(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.serve(ln)
	t.Cleanup(s.Close)
	return s, fake, signer.PublicKey(), ln.Addr().String()
}
func dial(t *testing.T, addr, password string, key ssh.PublicKey) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "warp", Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.FixedHostKey(key), Timeout: time.Second * 3})
}
func run(t *testing.T, addr, password string, key ssh.PublicKey, cmd string) (string, error) {
	t.Helper()
	c, err := dial(t, addr, password, key)
	if err != nil {
		return "", err
	}
	defer c.Close()
	session, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	out, err := session.CombinedOutput(cmd)
	return string(out), err
}
func TestControlSSH(t *testing.T) {
	_, f, key, addr := testServer(t)
	if _, err := dial(t, addr, "wrong password", key); err == nil {
		t.Fatal("bad password accepted")
	}
	out, err := run(t, addr, "very-long-test-password", key, "status")
	if err != nil || out != "endpoint=162.159.192.1:2408\n" {
		t.Fatalf("status %q %v", out, err)
	}
	if strings.Contains(out, "secret") {
		t.Fatal("leaked UAPI")
	}
	out, err = run(t, addr, "very-long-test-password", key, "set 188.114.97.10:500")
	if err != nil || !strings.Contains(out, "not yet verified") {
		t.Fatalf("set %q %v", out, err)
	}
	out, err = run(t, addr, "very-long-test-password", key, "status")
	if err != nil || !strings.Contains(out, "188.114.97.10:500") {
		t.Fatalf("status %q %v", out, err)
	}
	for _, cmd := range []string{"set 127.0.0.1:22", "set 8.8.8.8:53", "set 188.114.97.10:0", "set 188.114.97.10:500\npublic_key=x", "whoami", "scan"} {
		if out, err = run(t, addr, "very-long-test-password", key, cmd); err == nil {
			t.Fatalf("%q accepted: %s", cmd, out)
		}
	}
	if f.calls != 1 {
		t.Fatalf("calls: %d", f.calls)
	}
}
func TestScan(t *testing.T) {
	s, _, key, addr := testServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "warpscout")
	account := filepath.Join(dir, "account")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 188.114.96.42:2408\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s.scoutPath = path
	s.scoutAccount = account
	out, err := run(t, addr, "very-long-test-password", key, "scan")
	if err != nil || !strings.Contains(out, "188.114.96.42:2408") {
		t.Fatalf("scan %q %v", out, err)
	}
}
func TestNoSilentPeerCreation(t *testing.T) {
	s, f, _, _ := testServer(t)
	f.mu.Lock()
	f.key = strings.Repeat("a", 64)
	f.mu.Unlock()
	if _, err := s.set("188.114.96.1:2408"); err == nil {
		t.Fatal("missing peer")
	}
}
func TestCloseActiveConnection(t *testing.T) {
	s, _, _, addr := testServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(10 * time.Millisecond)
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close blocked")
	}
}
