// File: internal/app/server.go
package app

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	cf "vpn-runner/internal/cloudflare"
	"vpn-runner/internal/config"
	gh "vpn-runner/internal/github"
	"vpn-runner/internal/network"
	"vpn-runner/internal/warpcontrol"
)

type ServerOptions struct {
	Mode   string
	GistID string
	Repo   string
}

func StartServer(opts ServerOptions, shutdownCh <-chan struct{}) error {
	pat := os.Getenv("GH_PAT")
	if pat == "" {
		return fmt.Errorf("missing GH_PAT environment variable")
	}

	ghc := gh.NewClient(pat, opts.Repo, shutdownCh)

	data, err := ghc.ReadGist(opts.GistID)
	if err != nil {
		return fmt.Errorf("read gist: %w", err)
	}

	// Compare destinations on the same live UDP socket; separate socket
	// lifetimes do not constitute a valid NAT mapping test.
	mappings, err := network.ProbeSTUNMappings(config.ServerLPort, config.STUNServers)
	if err != nil {
		return fmt.Errorf("server STUN: %w", err)
	}
	for _, m := range mappings {
		log.Printf("STUN mapping %s -> %s:%d", m.Server, m.IP, m.Port)
	}
	first := mappings[0]
	if len(mappings) < 2 {
		log.Print("warning: only one STUN response; mapping behavior is unknown")
	} else if mappings[1].IP != first.IP || mappings[1].Port != first.Port {
		// Fail this runner promptly, allowing the client to dispatch another.
		// This is a conservative heuristic, not a complete NAT classification.
		data.Status = config.StatusServerNATIncompatible
		if err := ghc.UpdateGist(opts.GistID, data); err != nil {
			return fmt.Errorf("report incompatible runner: %w", err)
		}
		return fmt.Errorf("runner has destination-dependent STUN mapping; retry with another runner")
	}
	privKey, pubKey := network.GenerateWGKeys()
	data.ServerIP, data.ServerPort = first.IP, first.Port
	data.ServerPub, data.ServerHPK = pubKey, network.GenerateSymmetricKey()

	log.Println("Starting periodic low-TTL NAT punch...")
	stopPunch, err := network.StartNATPuncher(config.ServerLPort, data.ClientIP, data.ClientPort, 4)
	if err != nil {
		return err
	}
	defer stopPunch()
	ready := func() error {
		data.Status = config.StatusServerReady
		if err := ghc.UpdateGist(opts.GistID, data); err != nil {
			return fmt.Errorf("update gist: %w", err)
		}
		return nil
	}

	clientIF := network.WGInterfaceConfig{
		Name:                config.VPNIface,
		CIDR:                config.ServerIPWG + "/30",
		PrivateKey:          privKey,
		ListenPort:          config.ServerLPort,
		PeerPubKey:          data.ClientPub,
		AllowedIP:           config.ClientIPWG + "/32",
		AWG:                 config.DefaultAWGParams(), // AWG для клиента
		HeaderProtectionKey: data.ServerHPK,
	}

	if opts.Mode == "warp" {
		return runWarpMode(clientIF, shutdownCh, ready)
	}
	return runHostMode(clientIF, shutdownCh, ready)
}

func runWarpMode(clientIF network.WGInterfaceConfig, shutdownCh <-chan struct{}, ready func() error) error {
	if err := network.EnsureNetNS(config.NSName); err != nil {
		return fmt.Errorf("ensure server netns: %w", err)
	}

	nsFd, err := netns.GetFromName(config.NSName)
	if err != nil {
		return fmt.Errorf("get server netns: %w", err)
	}
	defer nsFd.Close()

	wgDev, err := network.CreateWGInterface(clientIF, nsFd)
	if err != nil {
		return fmt.Errorf("start client VPN in netns: %w", err)
	}
	defer wgDev.Close()

	warpReg, err := cf.RegisterWarp(shutdownCh)
	if err != nil {
		return fmt.Errorf("register WARP: %w", err)
	}

	// Фикс: Cloudflare часто возвращает IP уже с суффиксом /32
	warpCIDR := warpReg.Address
	if !strings.Contains(warpCIDR, "/") {
		warpCIDR += "/32"
	}

	warpIF := network.WGInterfaceConfig{
		Name:         config.WARPIface,
		CIDR:         warpCIDR,
		PrivateKey:   warpReg.PrivateKey,
		PeerPubKey:   warpReg.PublicKey,
		PeerEndpoint: warpReg.Endpoint,
		AllowedIP:    "0.0.0.0/0",
		Keepalive:    "25",                      // Cloudflare требует стандартный интервал, не диапазон
		AWG:          config.StandardWGParams(), // ФИКС: Используем стандартный WG для Cloudflare!
	}

	warpDev, err := network.CreateWGInterface(warpIF, nsFd)
	if err != nil {
		return fmt.Errorf("start WARP interface: %w", err)
	} else {
		defer warpDev.Close()

		if err := network.AddDefaultRoute(config.WARPIface, nsFd); err != nil {
			return fmt.Errorf("add WARP default route: %w", err)
		}

		if err := network.EnableIPForwardInNetNS(int(nsFd)); err != nil {
			return fmt.Errorf("enable ip_forward in netns: %w", err)
		}
		if err := network.SetupNftablesInNetNS(int(nsFd), config.WARPIface); err != nil {
			return fmt.Errorf("setup nftables in netns: %w", err)
		}
		ctlCfg, enabled, err := warpcontrol.ConfigFromEnv(warpReg.PublicKey, config.ServerIPWG+":2222")
		if err != nil {
			return fmt.Errorf("WARP control configuration: %w", err)
		}
		if enabled {
			ctl, err := warpcontrol.StartInNetNS(nsFd, ctlCfg, warpDev)
			if err != nil {
				return fmt.Errorf("start WARP SSH control: %w", err)
			}
			defer ctl.Close()
			log.Printf("WARP SSH control listening on %s inside VPN", ctlCfg.Address)
		} else {
			log.Print("WARP SSH control disabled: configure WARP_SSH_HOST_KEY and WARP_SSH_PASSWORD")
		}
	}

	if err := ready(); err != nil {
		return err
	}
	log.Println("Server active. WARP interface configured (handshake not yet verified).")
	<-shutdownCh
	return nil
}

func runHostMode(clientIF network.WGInterfaceConfig, shutdownCh <-chan struct{}, ready func() error) error {
	outIface, err := network.GetDefaultOutboundInterface()
	if err != nil {
		log.Printf("warning: determine outbound interface: %v", err)
	}

	network.EnableIPForwardHost()

	wgDev, err := network.CreateWGInterface(clientIF, 0)
	if err != nil {
		return fmt.Errorf("start VPN in host: %w", err)
	}
	defer wgDev.Close()

	if err := network.SetupNftablesHost(outIface); err != nil {
		log.Printf("warning: setup nftables on host: %v", err)
	}

	if err := ready(); err != nil {
		return err
	}
	log.Println("Server active. Interface configured (handshake not yet verified).")
	<-shutdownCh

	if link, err := netlink.LinkByName(config.VPNIface); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			log.Printf("warning: delete %s: %v", config.VPNIface, err)
		}
	}
	return nil
}
