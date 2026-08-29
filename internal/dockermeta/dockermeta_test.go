package dockermeta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const inspectBody = `{
  "Id": "4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f",
  "Name": "/atlas-demo-gateway",
  "Config": {
    "Image": "nginx:1.27-alpine",
    "Env": ["PATH=/usr/bin"],
    "Labels": {
      "com.docker.compose.project": "atlas-demo",
      "com.docker.compose.service": "gateway",
      "com.docker.compose.container-number": "1"
    }
  }
}`

func TestParseContainerInspect(t *testing.T) {
	meta, err := ParseContainerInspect([]byte(inspectBody))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "atlas-demo-gateway" {
		t.Fatalf("name = %q (leading slash must be trimmed)", meta.Name)
	}
	if meta.Image != "nginx:1.27-alpine" {
		t.Fatalf("image = %q", meta.Image)
	}
	if meta.ComposeProject != "atlas-demo" || meta.ComposeService != "gateway" {
		t.Fatalf("compose identity = %q/%q", meta.ComposeProject, meta.ComposeService)
	}

	if _, err := ParseContainerInspect([]byte("not json")); err == nil {
		t.Fatal("invalid JSON must error")
	}

	// Containers outside compose have no labels; must not error.
	plain, err := ParseContainerInspect([]byte(`{"Name":"/x","Config":{"Image":"redis"}}`))
	if err != nil || plain.ComposeService != "" {
		t.Fatalf("plain container: %+v, %v", plain, err)
	}
}

func TestClientInspect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/abc123/json" {
			w.Write([]byte(inspectBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL)
	meta, err := c.Inspect(context.Background(), "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "atlas-demo-gateway" {
		t.Fatalf("meta = %+v", meta)
	}

	if _, err := c.Inspect(context.Background(), "missing000000"); err == nil {
		t.Fatal("404 must error")
	}
}

func TestEnricherAppliesOncePerContainer(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.Path]++
		mu.Unlock()
		w.Write([]byte(inspectBody))
	}))
	defer srv.Close()

	applied := make(chan Meta, 10)
	e := NewEnricher(NewClient(srv.Client(), srv.URL), func(cid string, m Meta) {
		applied <- m
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	e.Enqueue("abc")
	e.Enqueue("abc")
	e.Enqueue("abc")

	select {
	case m := <-applied:
		if m.Name != "atlas-demo-gateway" {
			t.Fatalf("meta = %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("apply never called")
	}
	// Give the duplicate enqueues a chance to (incorrectly) fire.
	time.Sleep(100 * time.Millisecond)
	select {
	case <-applied:
		t.Fatal("resolved container was re-applied")
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["/containers/abc/json"] != 1 {
		t.Fatalf("inspect called %d times, want 1", calls["/containers/abc/json"])
	}
}
