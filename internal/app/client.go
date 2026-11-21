// File: internal/app/client.go
package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/vishvananda/netns"
	"vpn-runner/internal/config"
	gh "vpn-runner/internal/github"
	"vpn-runner/internal/network"
)

type ClientOptions struct {
	Mode string
	Repo string
}

func StartClient(opts ClientOptions, shutdownCh, rotateCh <-chan struct{}) error {
	pat := os.Getenv("GH_PAT")
	if pat == "" {
		return fmt.Errorf("missing GH_PAT environment variable")
	}
	if opts.Repo == "" {
		return fmt.Errorf("missing GH_REPO environment variable")
	}

	ghc := gh.NewClient(pat, opts.Repo, shutdownCh)

	log.Println("--- Starting Automated VPN Cycle ---")

	network.DeleteInterface(config.NSName, config.VPNIface)

	randOffset, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return fmt.Errorf("random offset: %w", err)
	}
	clientPort := config.MinClientPort + int(randOffset.Int64())
	log.Printf("Client Local Port: %d", clientPort)

	cIP, cPort, err := network.GetExternalIPAndPort(clientPort, config.STUNServers)
	if err != nil {
		return fmt.Errorf("client STUN: %w", err)
	}
	log.Printf("Client NAT Mapped IP:Port -> %s:%d", cIP, cPort)

	stopKeepalive := network.StartKeepalive(clientPort, "", 0)
	privKey, pubKey := network.GenerateWGKeys()

	gistID, err := ghc.CreateGist(gh.GistPayload{
		Status:     config.StatusClientReady,
		ClientIP:   cIP,
		ClientPort: cPort,
		ClientPub:  pubKey,
	})
	if err != nil {
		stopKeepalive()
		return fmt.Errorf("create gist: %w", err)
	}
	log.Printf("Gist created: %s", gistID)

	var runID int
	gistCreated := true
	defer func() {
		if !gistCreated {
			return
		}
		log.Println("Deferring GitHub resource cleanup...")
		if runID != 0 {
			ghc.CancelRun(runID)
		}
		if err := ghc.DeleteGist(gistID); err != nil {
			log.Printf("warning: deferred deleteGist: %v", err)
		}
	}()

	if err := ghc.TriggerWorkflow(opts.Mode, gistID); err != nil {
		stopKeepalive()
		return fmt.Errorf("trigger workflow: %w", err)
	}

	for range 15 {
		runID, err = ghc.FindRunID(gistID)
		if err != nil {
			log.Printf("warning: find newest run ID: %v", err)
		}
		if runID != 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("GitHub Run ID: %d", runID)

	var sIP, sPub, sHPK string
	var sPort int
	serverReady := false
	for range 60 {
		data, err := ghc.ReadGist(gistID)
		if err == nil && data.Status == config.StatusServerReady {
			sIP = data.ServerIP
			sPort = data.ServerPort
			sPub = data.ServerPub
			sHPK = data.ServerHPK // AWG 3.0 Header Protection Key
			serverReady = true
			break
		}
		select {
		case <-time.After(3 * time.Second):
		case <-shutdownCh:
			stopKeepalive()
			return fmt.Errorf("shutdown while waiting for server")
		}
	}

	if !serverReady {
		stopKeepalive()
		return fmt.Errorf("timeout waiting for server")
	}
	log.Printf("Server ready at %s:%d", sIP, sPort)

	stopKeepalive()

	uapi := network.WGInterfaceConfig{
		Name:                config.VPNIface,
		CIDR:                config.ClientIPWG + "/30",
		PrivateKey:          privKey,
		ListenPort:          clientPort,
		PeerPubKey:          sPub,
		PeerEndpoint:        fmt.Sprintf("%s:%d", sIP, sPort),
		AllowedIP:           "0.0.0.0/0",
		Keepalive:           "25-30", // AWG 3.0 range support
		AWG:                 config.ClientAWGParams(),
		HeaderProtectionKey: sHPK, // AWG 3.0 HPK
	}

	wgDev, err := createWGInterfaceWithRetry(uapi, clientPort)
	if err != nil {
		return err
	}
	defer wgDev.Close()

	nsFd, err := netns.GetFromName(config.NSName)
	if err != nil {
		return fmt.Errorf("get netns for route: %w", err)
	}
	defer nsFd.Close()

	if err := network.AddDefaultRoute(config.VPNIface, nsFd); err != nil {
		log.Printf("warning: add default route: %v", err)
	}

	log.Println("=====================================================")
	log.Println("[+] VPN interface configured in persistent namespace (handshake not yet verified).")
	log.Println("Run apps with: sudo -E ip netns exec amnezia sudo -E -u user bash")
	log.Println("=====================================================")

	return waitForRotation(shutdownCh, rotateCh, nsFd)
}

func createWGInterfaceWithRetry(cfg network.WGInterfaceConfig, clientPort int) (*device.Device, error) {
	const maxRetries = 5
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(200*(attempt-1)) * time.Millisecond
			log.Printf("Retrying VPN start (attempt %d/%d) after %v...", attempt, maxRetries, backoff)
			time.Sleep(backoff)
		}

		nsFd, err := netns.GetFromName(config.NSName)
		if err != nil {
			return nil, fmt.Errorf("get netns: %w", err)
		}
		dev, err := network.CreateWGInterface(cfg, nsFd)
		nsFd.Close()

		if err == nil {
			return dev, nil
		}

		if isAddressInUse(err) {
			log.Printf("Port %d still in use (attempt %d/%d)", clientPort, attempt, maxRetries)
			continue
		}
		return nil, fmt.Errorf("start VPN in netns: %w", err)
	}
	return nil, fmt.Errorf("failed to start VPN after %d retries: port %d remained in use", maxRetries, clientPort)
}

func isAddressInUse(err error) bool {
	return err != nil && errors.Is(err, syscall.EADDRINUSE)
}

func waitForRotation(shutdownCh, rotateCh <-chan struct{}, nsFd netns.NsHandle) error {
	rotationTimer := time.NewTimer(5*time.Hour + 59*time.Minute)
	defer rotationTimer.Stop()

	healthTicker := time.NewTicker(1 * time.Minute)
	defer healthTicker.Stop()

	var consecutiveFailures int
	const maxConsecutiveFailures = 2

	for {
		select {
		case <-shutdownCh:
			log.Println("Shutdown signal received during tunnel.")
			return nil
		case <-rotateCh:
			log.Println("Rotation signal received (SIGUSR1).")
			return nil
		case <-rotationTimer.C:
			log.Println("Rotation time reached.")
			return nil
		case <-healthTicker.C:
			if network.CheckVPNHealth(nsFd) {
				consecutiveFailures = 0
			} else {
				consecutiveFailures++
				log.Printf("VPN health check failed (%d/%d)", consecutiveFailures, maxConsecutiveFailures)
				if consecutiveFailures >= maxConsecutiveFailures {
					log.Println("VPN tunnel appears dead. Forcing rotation.")
					return nil
				}
			}
		}
	}
}
