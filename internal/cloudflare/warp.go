// File: internal/cloudflare/warp.go
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
	"vpn-runner/internal/network"
)

type Registration struct {
	PrivateKey string
	PublicKey  string
	Endpoint   string
	Address    string
}

func RegisterWarp(shutdownCh <-chan struct{}) (Registration, error) {
	privKey, pubKey := network.GenerateWGKeys()

	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	payload, err := json.Marshal(map[string]string{"key": pubKey, "tos": ts, "type": "Android"})
	if err != nil {
		return Registration{}, fmt.Errorf("marshal registration: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		select {
		case <-shutdownCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.cloudflareclient.com/v0a2158/reg", bytes.NewBuffer(payload))
	if err != nil {
		return Registration{}, fmt.Errorf("create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Registration{}, fmt.Errorf("register warp: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if resp.StatusCode == http.StatusTooManyRequests {
			return Registration{}, fmt.Errorf("cloudflare rate limited (HTTP %d): try again later", resp.StatusCode)
		}
		return Registration{}, fmt.Errorf("registration failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var r struct {
		Config struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4 string `json:"v4"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Registration{}, fmt.Errorf("decode registration response: %w", err)
	}
	if len(r.Config.Peers) == 0 {
		return Registration{}, fmt.Errorf("no peers in registration response")
	}

	endpoint := r.Config.Peers[0].Endpoint.V4
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	endpoint = net.JoinHostPort(host, "2408")

	return Registration{
		PrivateKey: privKey,
		PublicKey:  r.Config.Peers[0].PublicKey,
		Endpoint:   endpoint,
		Address:    r.Config.Interface.Addresses.V4,
	}, nil
}
