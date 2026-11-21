package warpcontrol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/crypto/curve25519"
)

func keypair(t *testing.T) (string, string) {
	t.Helper()
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	pk, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sk), hex.EncodeToString(pk)
}
func TestAWG31Packets(t *testing.T) {
	akey, apub := keypair(t)
	bkey, bpub := keypair(t)
	hpk := make([]byte, 32)
	rand.Read(hpk)
	at, bt := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a := device.NewDevice(at.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "a"))
	defer a.Close()
	b := device.NewDevice(bt.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "b"))
	defer b.Close()
	base := fmt.Sprintf("jc=7\njmin=8\njmax=80\ns1=40\ns2=40\ns3=40\ns4=40\nh1=70-100\nh2=110-140\nh3=150-180\nh4=190-220\nheader_protection_key=%x\nrandom_trailers=true\n", hpk)
	acfg := fmt.Sprintf("private_key=%s\n%sdisable_cookies=true\npublic_key=%s\nallowed_ip=192.168.166.1/32\npersistent_keepalive_interval=25-30\n", akey, base, bpub)
	bcfg := fmt.Sprintf("private_key=%s\n%sdisable_cookies=false\npublic_key=%s\nallowed_ip=192.168.166.2/32\n", bkey, base, apub)
	if err := a.IpcSet(acfg); err != nil {
		t.Fatal("client config", err)
	}
	if err := b.IpcSet(bcfg); err != nil {
		t.Fatal("server config", err)
	}
	if err := a.Up(); err != nil {
		t.Fatal(err)
	}
	if err := b.Up(); err != nil {
		t.Fatal(err)
	}
	bs, err := b.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, l := range strings.Split(bs, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			port = v
		}
	}
	if port == "" || port == "0" {
		t.Fatalf("bad port %q", port)
	}
	if err := a.IpcSet("public_key=" + bpub + "\nupdate_only=true\nendpoint=127.0.0.1:" + port + "\n"); err != nil {
		t.Fatal(err)
	}
	pkt := tuntest.Ping(netip.MustParseAddr("192.168.166.1"), netip.MustParseAddr("192.168.166.2"))
	select {
	case at.Outbound <- pkt:
	case <-time.After(time.Second):
		t.Fatal("cannot write tun")
	}
	select {
	case got := <-bt.Inbound:
		if string(pkt) != string(got) {
			t.Fatal("packet mismatch")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no decrypted packet received")
	}
}
