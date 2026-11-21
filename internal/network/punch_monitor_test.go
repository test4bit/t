package network

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeIPC struct {
	mu    sync.Mutex
	state string
}

func (f *fakeIPC) IpcGet() (string, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.state, nil }
func (f *fakeIPC) set(s string)            { f.mu.Lock(); defer f.mu.Unlock(); f.state = s }
func TestPeerHandshakeComplete(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	tests := []struct {
		status, key string
		want        bool
	}{
		{"private_key=secret\npublic_key=" + a + "\nlast_handshake_time_sec=0\n", a, false},
		{"public_key=" + a + "\nlast_handshake_time_sec=0\npublic_key=" + b + "\nlast_handshake_time_sec=123\n", a, false},
		{"public_key=" + a + "\nlast_handshake_time_sec=0\npublic_key=" + b + "\nlast_handshake_time_sec=123\n", b, true},
		{"public_key=" + a + "\nlast_handshake_time_sec=-1\n", a, false},
		{"public_key=" + a + "\nlast_handshake_time_sec=not-a-number\n", a, false},
	}
	for _, tc := range tests {
		if got := peerHandshakeComplete(tc.status, tc.key); got != tc.want {
			t.Errorf("key %s: got %v want %v", tc.key[:4], got, tc.want)
		}
	}
}
func TestPunchMonitorStopsAfterAuthenticatedHandshake(t *testing.T) {
	peer := make([]byte, 32)
	for i := range peer {
		peer[i] = byte(i + 1)
	}
	hexKey := hex.EncodeToString(peer)
	f := &fakeIPC{state: "public_key=" + hexKey + "\nlast_handshake_time_sec=0\n"}
	stopped := make(chan struct{}, 1)
	cancel, err := StopPunchAfterHandshake(f, base64.StdEncoding.EncodeToString(peer), func() { stopped <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	select {
	case <-stopped:
		t.Fatal("stopped before handshake")
	case <-time.After(1200 * time.Millisecond):
	}
	f.set("public_key=" + hexKey + "\nlast_handshake_time_sec=1700000000\n")
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("did not stop after handshake")
	}
	select {
	case <-stopped:
		t.Fatal("stopped twice")
	case <-time.After(20 * time.Millisecond):
	}
}
func TestPunchMonitorCancel(t *testing.T) {
	f := &fakeIPC{}
	stopped := make(chan struct{}, 1)
	cancel, err := StopPunchAfterHandshake(f, base64.StdEncoding.EncodeToString(make([]byte, 32)), func() { stopped <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { cancel(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor failed to stop")
	}
	select {
	case <-stopped:
		t.Fatal("stopped on cancellation rather than handshake")
	default:
	}
}
