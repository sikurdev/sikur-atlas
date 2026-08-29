// Package api exposes the graph over HTTP: a snapshot endpoint, a
// Server-Sent Events stream for live updates, agent metadata, and the
// embedded web UI.
package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

// Meta describes the running agent for /api/meta.
type Meta struct {
	Version          string      `json:"version"`
	StartedAt        time.Time   `json:"startedAt"`
	Kernel           string      `json:"kernel,omitempty"`
	Collector        any         `json:"collector"`
	KernelDrops      uint64      `json:"kernelDrops"`
	DecodeErrors     uint64      `json:"decodeErrors"`
	DockerEnrichment bool        `json:"dockerEnrichment"`
}

// Server wires the HTTP API. UI may be nil when no web assets are built.
type Server struct {
	store    *graph.Store
	metaFn   func() Meta
	ui       fs.FS
	debounce time.Duration
	handler  http.Handler
}

func NewServer(store *graph.Store, metaFn func() Meta, ui fs.FS) *Server {
	s := &Server{
		store:    store,
		metaFn:   metaFn,
		ui:       ui,
		debounce: 250 * time.Millisecond,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/graph", s.handleGraph)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("/", s.handleUI)
	s.handler = mux
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) handleGraph(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.store.Snapshot())
}

func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.metaFn())
}

// handleStream sends the current snapshot immediately, then a debounced
// fresh snapshot after every graph change, as SSE `snapshot` events.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	changes, cancel := s.store.Subscribe()
	defer cancel()

	if err := writeSSE(w, s.store.Snapshot()); err != nil {
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-changes:
			// Debounce: absorb the burst, then send one snapshot.
			timer := time.NewTimer(s.debounce)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			select {
			case <-changes: // drain anything that arrived while waiting
			default:
			}
			if err := writeSSE(w, s.store.Snapshot()); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.ui == nil {
		http.Error(w, "Atlas web UI not built — run `make web` and rebuild the agent.", http.StatusNotFound)
		return
	}
	f, err := s.ui.Open(pathFor(r.URL.Path))
	if err != nil {
		// SPA fallback: unknown paths get index.html.
		r2 := *r
		r2.URL.Path = "/"
		http.ServeFileFS(w, &r2, s.ui, "index.html")
		return
	}
	f.Close()
	http.ServeFileFS(w, r, s.ui, pathFor(r.URL.Path))
}

func pathFor(urlPath string) string {
	if urlPath == "/" || urlPath == "" {
		return "index.html"
	}
	return urlPath[1:]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	_ = enc.Encode(v)
}

func writeSSE(w http.ResponseWriter, snap graph.Snapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data)
	return err
}
