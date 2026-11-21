// File: cmd/vpn/main.go
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"vpn-runner/internal/app"
	"vpn-runner/internal/config"
	"vpn-runner/internal/network"
)

var (
	shutdownCh   = make(chan struct{})
	shutdownOnce sync.Once
	rotateCh     = make(chan struct{})
	rotateMu     sync.Mutex
	rotateClosed bool
)

func main() {
	role := flag.String("role", "client", "Role: client or server")
	mode := flag.String("mode", "warp", "Mode: awg or warp")
	repo := flag.String("repo", os.Getenv("GH_REPO"), "GitHub Repo: user/repo")

	defaultGist := os.Getenv("GIST_ID")
	gistID := flag.String("gist", defaultGist, "Gist ID (mandatory for server)")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)

	defer network.FullTeardown(config.NSName)
	setupSignals()

	if *role == "client" || (*role == "server" && *mode == "warp") {
		if err := network.EnsureNetNS(config.NSName); err != nil {
			log.Printf("Failed to initialize persistent NetNS: %v", err)
			return
		}
	}

	if *role == "client" {
		runClient(*mode, *repo)
	} else {
		if *gistID == "" {
			log.Printf("Server error: missing gist_id. Pass via -gist or GIST_ID env var.")
			return
		}
		runServer(*mode, *gistID, *repo)
	}
}

func runClient(mode, repo string) {
	opts := app.ClientOptions{Mode: mode, Repo: repo}
	for {
		select {
		case <-shutdownCh:
			log.Println("Shutdown detected in main loop. Exiting.")
			return
		default:
		}

		rotateMu.Lock()
		currentCh := rotateCh
		rotateMu.Unlock()

		if err := app.StartClient(opts, shutdownCh, currentCh); err != nil {
			log.Printf("Cycle finished: %v. Restarting in 20s...", err)
			select {
			case <-time.After(20 * time.Second):
			case <-shutdownCh:
				return
			}
		}
		resetRotation()
	}
}

func runServer(mode, gistID, repo string) {
	opts := app.ServerOptions{Mode: mode, GistID: gistID, Repo: repo}

	if err := app.StartServer(opts, shutdownCh); err != nil {
		log.Printf("Fatal error: %v", err)
		return
	}
}

func setupSignals() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for sig := range c {
			if sig == syscall.SIGUSR1 {
				log.Println("Received SIGUSR1. Triggering VPN rotation...")
				triggerRotation()
			} else {
				log.Printf("Received signal %v. Triggering graceful shutdown...", sig)
				triggerShutdown()
			}
		}
	}()
}

func triggerShutdown() {
	shutdownOnce.Do(func() {
		close(shutdownCh)
	})
}

func triggerRotation() {
	rotateMu.Lock()
	defer rotateMu.Unlock()
	if !rotateClosed {
		close(rotateCh)
		rotateClosed = true
	}
}

func resetRotation() {
	rotateMu.Lock()
	defer rotateMu.Unlock()
	rotateCh = make(chan struct{})
	rotateClosed = false
}
