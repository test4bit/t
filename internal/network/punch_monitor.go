package network

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

type ipcReader interface{ IpcGet() (string, error) }

// peerHandshakeComplete reads only the specified peer's state. UAPI also contains
// secret keys: never log or return the raw output.
func peerHandshakeComplete(status, peerHex string) bool {
	selected := false
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			selected = value == peerHex
			continue
		}
		if selected && key == "last_handshake_time_sec" {
			seconds, err := strconv.ParseInt(value, 10, 64)
			return err == nil && seconds > 0
		}
	}
	return false
}

// StopPunchAfterHandshake stops the bootstrap punch only after AWG reports a
// completed authenticated handshake for this peer. stop is idempotent. The
// returned function stops and joins the monitor; call it before closing dev.
// On later connection failure the client health check restarts the VPN cycle.
func StopPunchAfterHandshake(dev ipcReader, peerPublicKey string, stop func()) (func(), error) {
	peer, err := base64.StdEncoding.DecodeString(peerPublicKey)
	if err != nil || len(peer) != 32 {
		return nil, fmt.Errorf("invalid peer public key")
	}
	if dev == nil || stop == nil {
		return nil, fmt.Errorf("missing device or punch stop function")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	peerHex := hex.EncodeToString(peer)
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				state, err := dev.IpcGet()
				if err != nil {
					continue
				}
				if peerHandshakeComplete(state, peerHex) {
					stop()
					log.Print("AWG peer handshake confirmed; stopped bootstrap NAT punching")
					return
				}
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}
