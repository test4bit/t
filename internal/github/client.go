// File: internal/github/client.go
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type GistPayload struct {
	Status     string `json:"status"`
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port"`
	ClientPub  string `json:"client_pub"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	ServerPub  string `json:"server_pub"`
	ServerHPK  string `json:"server_hpk"` // AWG 3.0 Header Protection Key передается в Payload
}

type Client struct {
	pat        string
	repo       string
	http       *http.Client
	shutdownCh <-chan struct{}
	mu         sync.Mutex
}

func NewClient(pat, repo string, shutdownCh <-chan struct{}) *Client {
	return &Client{
		pat:        pat,
		repo:       repo,
		http:       &http.Client{Timeout: 30 * time.Second},
		shutdownCh: shutdownCh,
	}
}

func (c *Client) reqCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-c.shutdownCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (c *Client) CreateGist(payload GistPayload) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal gist payload: %w", err)
	}
	body := fmt.Sprintf(`{"public":false,"files":{"v.json":{"content":%q}}}`, string(b))

	ctx, cancel := c.reqCtx()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.github.com/gists", strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.pat)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("create gist: %w", err)
	}
	defer c.closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("create gist: status %d", resp.StatusCode)
	}

	var r struct{ ID string }
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("decode gist response: %w", err)
	}
	return r.ID, nil
}

func (c *Client) ReadGist(id string) (GistPayload, error) {
	ctx, cancel := c.reqCtx()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/gists/"+id, nil)
	if err != nil {
		return GistPayload{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.pat)

	resp, err := c.http.Do(req)
	if err != nil {
		return GistPayload{}, fmt.Errorf("fetch gist: %w", err)
	}
	defer c.closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GistPayload{}, fmt.Errorf("read gist: status %d", resp.StatusCode)
	}

	var r struct {
		Files map[string]struct{ Content string } `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return GistPayload{}, fmt.Errorf("decode gist: %w", err)
	}
	file, ok := r.Files["v.json"]
	if !ok {
		return GistPayload{}, fmt.Errorf("gist %s missing v.json", id)
	}
	var p GistPayload
	if err := json.Unmarshal([]byte(file.Content), &p); err != nil {
		return GistPayload{}, fmt.Errorf("unmarshal gist content: %w", err)
	}
	return p, nil
}

func (c *Client) UpdateGist(id string, payload GistPayload) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal gist payload: %w", err)
	}
	body := fmt.Sprintf(`{"files":{"v.json":{"content":%q}}}`, string(b))

	ctx, cancel := c.reqCtx()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "PATCH", "https://api.github.com/gists/"+id, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.pat)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("update gist: %w", err)
	}
	defer c.closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("update gist: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) DeleteGist(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "DELETE", "https://api.github.com/gists/"+id, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.pat)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("delete gist: %w", err)
	}
	defer c.closeBody(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("delete gist: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) TriggerWorkflow(mode, gistID string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/vpn.yml/dispatches", c.repo)
	body := fmt.Sprintf(`{"ref":"main","inputs":{"mode":"%s","gist_id":"%s"}}`, mode, gistID)

	ctx, cancel := c.reqCtx()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.pat)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch workflow: %w", err)
	}
	defer c.closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dispatch workflow: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) FindRunID(gistID string) (int, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/vpn.yml/runs?event=workflow_dispatch&per_page=100", c.repo)

	ctx, cancel := c.reqCtx()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.pat)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch runs: %w", err)
	}
	defer c.closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("fetch runs: status %d", resp.StatusCode)
	}

	var res struct {
		Runs []struct {
			ID           int    `json:"id"`
			DisplayTitle string `json:"display_title"`
			Status       string `json:"status"`
		} `json:"workflow_runs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return 0, fmt.Errorf("decode runs response: %w", err)
	}
	for _, run := range res.Runs {
		if run.DisplayTitle == "vpn-"+gistID && run.Status != "completed" {
			return run.ID, nil
		}
	}
	return 0, nil
}

func (c *Client) CancelRun(id int) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/cancel", c.repo, id)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "token "+c.pat)

	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	c.closeBody(resp)
}

func (c *Client) closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
