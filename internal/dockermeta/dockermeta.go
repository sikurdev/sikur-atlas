// Package dockermeta resolves container ids to human names and images
// via the Docker Engine API. It is optional enrichment: when the Docker
// socket is unavailable, Atlas still works and containers show their
// short id.
package dockermeta

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

// Meta is the subset of container metadata Atlas uses.
type Meta struct {
	Name           string
	Image          string
	ComposeProject string
	ComposeService string
}

// ParseContainerInspect extracts Meta from a /containers/<id>/json
// response body. Docker Compose identity comes from the standard labels
// compose sets on every container it manages.
func ParseContainerInspect(data []byte) (Meta, error) {
	var payload struct {
		Name   string `json:"Name"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return Meta{}, err
	}
	return Meta{
		Name:           strings.TrimPrefix(payload.Name, "/"),
		Image:          payload.Config.Image,
		ComposeProject: payload.Config.Labels["com.docker.compose.project"],
		ComposeService: payload.Config.Labels["com.docker.compose.service"],
	}, nil
}

// Client queries a Docker Engine API over the injected http.Client
// (a unix-socket transport in production, httptest in tests).
type Client struct {
	http    *http.Client
	baseURL string
}

func NewClient(httpClient *http.Client, baseURL string) *Client {
	return &Client{http: httpClient, baseURL: baseURL}
}

// Inspect fetches metadata for one container id.
func (c *Client) Inspect(ctx context.Context, containerID string) (Meta, error) {
	url := c.baseURL + "/containers/" + containerID + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Meta{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Meta{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Meta{}, fmt.Errorf("docker inspect %s: status %d", containerID[:min(12, len(containerID))], resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Meta{}, err
	}
	return ParseContainerInspect(body)
}

// Enricher resolves container ids in the background and applies results
// through the supplied callback. Callers enqueue an id on every
// observation; the enricher deduplicates, so a lookup that failed
// transiently is retried by the next observation after the retry
// interval (traffic-driven retry).
type Enricher struct {
	client *Client
	apply  func(containerID string, meta Meta)
	queue  chan string
	retry  time.Duration

	mu   sync.Mutex
	done map[string]time.Time // zero time = resolved for good
}

func NewEnricher(client *Client, apply func(containerID string, meta Meta)) *Enricher {
	return &Enricher{
		client: client,
		apply:  apply,
		queue:  make(chan string, 256),
		done:   make(map[string]time.Time),
		retry:  30 * time.Second,
	}
}

// Enqueue schedules a container id for resolution; never blocks. Ids
// that are already resolved, or failed too recently, are dropped here so
// hot paths don't churn the queue.
func (e *Enricher) Enqueue(containerID string) {
	if e.settled(containerID) {
		return
	}
	select {
	case e.queue <- containerID:
	default: // queue full: drop, a later observation will retry
	}
}

func (e *Enricher) settled(cid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.done[cid]
	return ok && (t.IsZero() || time.Since(t) < e.retry)
}

// Run processes the queue until ctx is done. Call from one goroutine.
func (e *Enricher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cid := <-e.queue:
			if e.settled(cid) {
				continue
			}
			reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			meta, err := e.client.Inspect(reqCtx, cid)
			cancel()
			e.mu.Lock()
			if err != nil {
				e.done[cid] = time.Now() // opens a retry window
			} else {
				e.done[cid] = time.Time{}
			}
			e.mu.Unlock()
			if err == nil {
				e.apply(cid, meta)
			}
		}
	}
}
