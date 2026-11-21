// File: internal/network/wg.go
package network

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/crypto/curve25519"
	"vpn-runner/internal/config"
)

type WGInterfaceConfig struct {
	Name                string
	CIDR                string
	PrivateKey          string
	ListenPort          int
	PeerPubKey          string
	PeerEndpoint        string
	AllowedIP           string
	Keepalive           string // Updated for AWG 3.0 string ranges support
	HeaderProtectionKey string // Added for AWG 3.0
	AWG                 config.AWGParams
}

func GenerateWGKeys() (privateKey, publicKey string) {
	var pr [32]byte
	if _, err := rand.Read(pr[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	// Clamp private key per RFC 7748 to prevent small-subgroup attacks.
	pr[0] &= 248  // Clear lowest 3 bits
	pr[31] &= 127 // Clear highest bit
	pr[31] |= 64  // Set second highest bit
	var pu [32]byte
	curve25519.ScalarBaseMult(&pu, &pr)
	return base64.StdEncoding.EncodeToString(pr[:]), base64.StdEncoding.EncodeToString(pu[:])
}

// GenerateSymmetricKey generates random 32 bytes for Header Protection (AWG 3.0)
func GenerateSymmetricKey() string {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func hexKey(b64 string) string {
	d, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Printf("warning: decode base64 key: %v", err)
		return ""
	}
	return fmt.Sprintf("%x", d)
}

func BuildUAPI(cfg WGInterfaceConfig) string {
	var b string
	b += "private_key=" + hexKey(cfg.PrivateKey) + "\n"
	if cfg.ListenPort > 0 {
		b += fmt.Sprintf("listen_port=%d\n", cfg.ListenPort)
	}

	p := cfg.AWG
	b += fmt.Sprintf("random_trailers=%t\ndisable_cookies=%t\n", p.RandomTrailers, p.DisableCookies)
	b += fmt.Sprintf("jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\nh1=%s\nh2=%s\nh3=%s\nh4=%s\n",
		p.JC, p.JMin, p.JMax, p.S1, p.S2, p.S3, p.S4, p.H1, p.H2, p.H3, p.H4)

	// AWG 3.0 new parameters
	if cfg.HeaderProtectionKey != "" {
		b += "header_protection_key=" + hexKey(cfg.HeaderProtectionKey) + "\n"
	}
	if p.ContentPaddingAddition != "" {
		b += fmt.Sprintf("content_padding_addition=%s\n", p.ContentPaddingAddition)
	}
	if p.RekeyAfterTime != "" {
		b += fmt.Sprintf("rekey_after_time=%s\n", p.RekeyAfterTime)
	}
	if p.RekeyTimeout != "" {
		b += fmt.Sprintf("rekey_timeout=%s\n", p.RekeyTimeout)
	}
	if p.RejectAfterTime != "" {
		b += fmt.Sprintf("reject_after_time=%s\n", p.RejectAfterTime)
	}
	if p.KeepaliveTimeout != "" {
		b += fmt.Sprintf("keepalive_timeout=%s\n", p.KeepaliveTimeout)
	}
	if p.MaxHandshakeAttempts != "" {
		b += fmt.Sprintf("max_handshake_attempts=%s\n", p.MaxHandshakeAttempts)
	}
	if p.I1 != "" {
		b += fmt.Sprintf("i1=%s\n", p.I1)
	}
	if p.I2 != "" {
		b += fmt.Sprintf("i2=%s\n", p.I2)
	}
	if p.I3 != "" {
		b += fmt.Sprintf("i3=%s\n", p.I3)
	}
	if p.I4 != "" {
		b += fmt.Sprintf("i4=%s\n", p.I4)
	}
	if p.I5 != "" {
		b += fmt.Sprintf("i5=%s\n", p.I5)
	}

	b += "public_key=" + hexKey(cfg.PeerPubKey) + "\n"
	if cfg.PeerEndpoint != "" {
		b += fmt.Sprintf("endpoint=%s\n", cfg.PeerEndpoint)
	}
	if cfg.AllowedIP != "" {
		b += fmt.Sprintf("allowed_ip=%s\n", cfg.AllowedIP)
	}
	if cfg.Keepalive != "" {
		b += fmt.Sprintf("persistent_keepalive_interval=%s\n", cfg.Keepalive)
	}
	return b
}

func CreateWGInterface(cfg WGInterfaceConfig, nsFd netns.NsHandle) (*device.Device, error) {
	t, err := tun.CreateTUN(cfg.Name, config.TUNMTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %s: %w", cfg.Name, err)
	}
	dev := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	cleanup := func() {
		dev.Close()
	}

	uapi := BuildUAPI(cfg)
	if err = dev.IpcSet(uapi); err != nil {
		cleanup()
		return nil, fmt.Errorf("configure WireGuard %s: %w", cfg.Name, err)
	}
	if err = dev.Up(); err != nil {
		cleanup()
		return nil, fmt.Errorf("bring up WireGuard %s: %w", cfg.Name, err)
	}

	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("find link %s: %w", cfg.Name, err)
	}

	if nsFd > 0 {
		if err = netlink.LinkSetNsFd(link, int(nsFd)); err != nil {
			cleanup()
			return nil, fmt.Errorf("move link %s to netns: %w", cfg.Name, err)
		}
	}

	addr, err := netlink.ParseAddr(cfg.CIDR)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("parse addr %s: %w", cfg.CIDR, err)
	}

	if nsFd > 0 {
		nlHandle, nlErr := netlink.NewHandleAt(nsFd)
		if nlErr != nil {
			cleanup()
			return nil, fmt.Errorf("netlink handle at netns: %w", nlErr)
		}
		defer nlHandle.Close()

		nsLink, nsErr := nlHandle.LinkByName(cfg.Name)
		if nsErr != nil {
			cleanup()
			return nil, fmt.Errorf("find link %s in netns: %w", cfg.Name, nsErr)
		}
		if addrErr := nlHandle.AddrAdd(nsLink, addr); addrErr != nil && !errors.Is(addrErr, syscall.EEXIST) {
			cleanup()
			return nil, fmt.Errorf("add addr %s: %w", cfg.CIDR, addrErr)
		}
		if upErr := nlHandle.LinkSetUp(nsLink); upErr != nil {
			cleanup()
			return nil, fmt.Errorf("bring up link %s: %w", cfg.Name, upErr)
		}
	} else {
		if addrErr := netlink.AddrAdd(link, addr); addrErr != nil && !errors.Is(addrErr, syscall.EEXIST) {
			cleanup()
			return nil, fmt.Errorf("add addr %s: %w", cfg.CIDR, addrErr)
		}
		if upErr := netlink.LinkSetUp(link); upErr != nil {
			cleanup()
			return nil, fmt.Errorf("bring up link %s: %w", cfg.Name, upErr)
		}
	}

	return dev, nil
}

func AddDefaultRoute(ifaceName string, nsFd netns.NsHandle) error {
	var link netlink.Link
	var nlHandle *netlink.Handle
	var err error

	if nsFd > 0 {
		nlHandle, err = netlink.NewHandleAt(nsFd)
		if err != nil {
			return fmt.Errorf("netlink handle at netns: %w", err)
		}
		defer nlHandle.Close()
		link, err = nlHandle.LinkByName(ifaceName)
	} else {
		link, err = netlink.LinkByName(ifaceName)
	}
	if err != nil {
		return fmt.Errorf("find link %s: %w", ifaceName, err)
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
	}

	if nsFd > 0 {
		if err := nlHandle.RouteAdd(route); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
	} else {
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
	}
	return nil
}

func EnableIPForwardInNetNS(nsFd int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer origns.Close()
	defer netns.Set(origns)

	if nsFd > 0 {
		if err := netns.Set(netns.NsHandle(nsFd)); err != nil {
			return fmt.Errorf("set netns: %w", err)
		}
	}

	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("enable ip_forward in netns: %w", err)
	}
	return nil
}

func EnableIPForwardHost() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		log.Printf("warning: enable ip_forward: %v", err)
	}
	return nil
}
