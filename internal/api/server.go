// Package api exposes the graph over HTTP: live snapshot + SSE stream,
// historical reconstruction (Replay), moment comparison, the activity
// timeline, agent metadata, and the embedded web UI.
package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/appview"
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/history"
	"github.com/sikurdev/sikur-atlas/internal/lens"
)

// Meta describes the running agent for /api/meta.
type Meta struct {
	Version          string    `json:"version"`
	StartedAt        time.Time `json:"startedAt"`
	Kernel           string    `json:"kernel,omitempty"`
	Collector        any       `json:"collector"`
	KernelDrops      uint64    `json:"kernelDrops"`
	DecodeErrors     uint64    `json:"decodeErrors"`
	DockerEnrichment bool      `json:"dockerEnrichment"`
	History          bool      `json:"history"`
	// HostPSI is the host pressure-stall snapshot (resources.HostPSI);
	// absent on kernels without PSI.
	HostPSI any `json:"hostPsi,omitempty"`
}

// Config wires a Server.
type Config struct {
	Store   *graph.Store
	History *history.Store // nil disables replay/compare/timeline
	MetaFn  func() Meta
	UI      fs.FS // nil when no web assets are built
	// SelfExe marks the agent's own executable in the application view.
	SelfExe string
}

// Server wires the HTTP API.
type Server struct {
	cfg      Config
	debounce time.Duration
	handler  http.Handler
}

// StreamPayload is one SSE snapshot event: the raw graph plus its
// application-view projection, so the client renders either without a
// second round trip.
type StreamPayload struct {
	Raw graph.Snapshot `json:"raw"`
	App appview.Graph  `json:"app"`
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg:      cfg,
		debounce: 250 * time.Millisecond,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/graph", s.handleGraph)
	mux.HandleFunc("GET /api/appview", s.handleAppView)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /api/timeline", s.handleTimeline)
	mux.HandleFunc("GET /api/compare", s.handleCompare)
	mux.HandleFunc("GET /api/lens", s.handleLens)
	mux.HandleFunc("GET /api/lifecycle", s.handleLifecycle)
	mux.HandleFunc("GET /api/metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("/", s.handleUI)
	s.handler = mux
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }

// liveSnapshot returns the in-memory graph decorated with recent health
// windows from history.
func (s *Server) liveSnapshot() graph.Snapshot {
	snap := s.cfg.Store.Snapshot()
	if s.cfg.History == nil {
		return snap
	}
	windows, err := s.cfg.History.WindowHealth(time.Now(), history.DefaultMetricWindow)
	if err != nil {
		return snap
	}
	for i := range snap.Edges {
		if w, ok := windows[snap.Edges[i].ID]; ok {
			w := w
			snap.Edges[i].Window = &w
		}
	}
	return snap
}

// snapshotFor resolves the ?at= parameter: absent means live. Optional
// presence= and window= (seconds) tune the reconstruction windows.
func (s *Server) snapshotFor(r *http.Request) (graph.Snapshot, error) {
	q := r.URL.Query()
	atParam := q.Get("at")
	if atParam == "" {
		return s.liveSnapshot(), nil
	}
	if s.cfg.History == nil {
		return graph.Snapshot{}, fmt.Errorf("history disabled")
	}
	at, err := parseTime(atParam)
	if err != nil {
		return graph.Snapshot{}, err
	}
	presence, err := parseSeconds(q.Get("presence"))
	if err != nil {
		return graph.Snapshot{}, err
	}
	window, err := parseSeconds(q.Get("window"))
	if err != nil {
		return graph.Snapshot{}, err
	}
	return s.cfg.History.SnapshotAt(at, presence, window)
}

func parseSeconds(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad duration %q (want seconds)", v)
	}
	return time.Duration(n) * time.Second, nil
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshotFor(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, snap)
}

func (s *Server) handleAppView(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshotFor(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, appview.Project(snap, appview.Options{SelfExe: s.cfg.SelfExe}))
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	if s.cfg.History == nil {
		http.Error(w, "history disabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	now := time.Now()
	to := now
	from := now.Add(-15 * time.Minute)
	var err error
	if v := q.Get("from"); v != "" {
		if from, err = parseTime(v); err != nil {
			http.Error(w, "bad from: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if v := q.Get("to"); v != "" {
		if to, err = parseTime(v); err != nil {
			http.Error(w, "bad to: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if !to.After(from) {
		http.Error(w, "to must be after from", http.StatusBadRequest)
		return
	}
	step := to.Sub(from) / 120
	if v := q.Get("step"); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil || secs <= 0 {
			http.Error(w, "bad step", http.StatusBadRequest)
			return
		}
		step = time.Duration(secs) * time.Second
	}
	if step < time.Second {
		step = time.Second
	}
	// Bound the response: a huge range with a tiny step would otherwise
	// materialize millions of buckets.
	if buckets := to.Sub(from) / step; buckets > 5000 {
		http.Error(w, fmt.Sprintf("range/step yields %d buckets; max 5000", buckets), http.StatusBadRequest)
		return
	}
	series, err := s.cfg.History.Timeline(from, to, step)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"from": from.Unix(), "to": to.Unix(),
		"step": int(step.Seconds()), "buckets": series,
	})
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	if s.cfg.History == nil {
		http.Error(w, "history disabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	a, errA := parseTime(q.Get("a"))
	b, errB := parseTime(q.Get("b"))
	if errA != nil || errB != nil {
		http.Error(w, "compare needs a= and b= timestamps", http.StatusBadRequest)
		return
	}
	// The diff's semantics are "A = earlier, B = later"; normalize so a
	// reversed pin order cannot silently invert added/removed.
	if a.After(b) {
		a, b = b, a
	}
	presence, errP := parseSeconds(q.Get("presence"))
	window, errW := parseSeconds(q.Get("window"))
	if errP != nil || errW != nil {
		http.Error(w, "bad presence/window", http.StatusBadRequest)
		return
	}
	snapA, err := s.cfg.History.SnapshotAt(a, presence, window)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snapB, err := s.cfg.History.SnapshotAt(b, presence, window)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	opts := appview.Options{SelfExe: s.cfg.SelfExe}
	viewA := appview.Project(snapA, opts)
	viewB := appview.Project(snapB, opts)
	diff := appview.ComputeDiff(viewA, viewB)

	// Attach recorded lifecycle evidence, mapped onto the service graph
	// (either era's membership may know the node).
	events, err := s.cfg.History.LifecycleRange(a, b, "")
	if err == nil {
		members := viewB.MemberIndex()
		membersA := viewA.MemberIndex()
		labels := viewB.LabelIndex()
		labelsA := viewA.LabelIndex()
		for _, ev := range events {
			svc, ok := members[ev.NodeID]
			label := labels[svc]
			if !ok {
				if svc, ok = membersA[ev.NodeID]; !ok {
					continue
				}
				label = labelsA[svc]
			}
			diff.Lifecycle = append(diff.Lifecycle, appview.LifecycleEntry{
				Node: svc, Label: label, Kind: ev.Kind,
				Detail: ev.Detail, Time: ev.Time,
			})
		}
	}
	writeJSON(w, diff)
}

// handleLens runs the Incident Lens over a recorded window:
// GET /api/lens?from=&to=[&service=]. service focuses the investigation
// on one service's dependency component.
func (s *Server) handleLens(w http.ResponseWriter, r *http.Request) {
	if s.cfg.History == nil {
		http.Error(w, "history disabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	from, errF := parseTime(q.Get("from"))
	to, errT := parseTime(q.Get("to"))
	if errF != nil || errT != nil {
		http.Error(w, "lens needs from= and to= timestamps", http.StatusBadRequest)
		return
	}
	if from.After(to) {
		from, to = to, from
	}
	if !to.After(from) {
		http.Error(w, "lens window is empty", http.StatusBadRequest)
		return
	}
	// Bound the window: beyond retention there is nothing to read, and
	// an unbounded range would only scan empty space.
	if to.Sub(from) > 24*time.Hour {
		http.Error(w, "lens window exceeds 24h", http.StatusBadRequest)
		return
	}
	report, err := lens.Run(s.cfg.History, from, to, q.Get("service"),
		appview.Options{SelfExe: s.cfg.SelfExe})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, report)
}

// handleLifecycle serves recorded lifecycle events; node= filters by
// raw node id.
func (s *Server) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	if s.cfg.History == nil {
		http.Error(w, "history disabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	now := time.Now()
	from := now.Add(-15 * time.Minute)
	to := now
	var err error
	if v := q.Get("from"); v != "" {
		if from, err = parseTime(v); err != nil {
			http.Error(w, "bad from: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if v := q.Get("to"); v != "" {
		if to, err = parseTime(v); err != nil {
			http.Error(w, "bad to: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	events, err := s.cfg.History.LifecycleRange(from, to, q.Get("node"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"events": events})
}

// handleMetrics serves a node's resource series.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.History == nil {
		http.Error(w, "history disabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	nodeID := q.Get("node")
	if nodeID == "" {
		http.Error(w, "metrics needs node=", http.StatusBadRequest)
		return
	}
	now := time.Now()
	from := now.Add(-15 * time.Minute)
	to := now
	var err error
	if v := q.Get("from"); v != "" {
		if from, err = parseTime(v); err != nil {
			http.Error(w, "bad from: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if v := q.Get("to"); v != "" {
		if to, err = parseTime(v); err != nil {
			http.Error(w, "bad to: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	points, err := s.cfg.History.MetricsRange(nodeID, from, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"node": nodeID, "points": points})
}

func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.cfg.MetaFn())
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

	changes, cancel := s.cfg.Store.Subscribe()
	defer cancel()

	if err := s.writeStreamEvent(w); err != nil {
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
			if err := s.writeStreamEvent(w); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) writeStreamEvent(w http.ResponseWriter) error {
	snap := s.liveSnapshot()
	payload := StreamPayload{
		Raw: snap,
		App: appview.Project(snap, appview.Options{SelfExe: s.cfg.SelfExe}),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data)
	return err
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.cfg.UI == nil {
		http.Error(w, "Atlas web UI not built — run `make web` and rebuild the agent.", http.StatusNotFound)
		return
	}
	if _, err := fs.Stat(s.cfg.UI, pathFor(r.URL.Path)); err != nil {
		// SPA fallback: unknown paths get index.html.
		r2 := *r
		r2.URL.Path = "/"
		http.ServeFileFS(w, &r2, s.cfg.UI, "index.html")
		return
	}
	http.ServeFileFS(w, r, s.cfg.UI, pathFor(r.URL.Path))
}

func pathFor(urlPath string) string {
	if urlPath == "/" || urlPath == "" {
		return "index.html"
	}
	return urlPath[1:]
}

// parseTime accepts unix seconds, unix milliseconds or RFC3339.
func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n > 1e12 { // milliseconds
			return time.UnixMilli(n), nil
		}
		return time.Unix(n, 0), nil
	}
	return time.Parse(time.RFC3339, v)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	_ = enc.Encode(v)
}
