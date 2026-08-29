package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/appview"
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/history"
)

func testServer(t *testing.T, ui bool) (*graph.Store, *history.Store, *httptest.Server) {
	t.Helper()
	store := graph.NewStore()
	hist, err := history.Open(filepath.Join(t.TempDir(), "h.db"), store,
		history.WithSpans(10*time.Second, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hist.Close() })

	var uiFS fstest.MapFS
	if ui {
		uiFS = fstest.MapFS{
			"index.html":    {Data: []byte("<html><body>atlas-ui</body></html>")},
			"assets/app.js": {Data: []byte("console.log('x')")},
		}
	}
	meta := func() Meta {
		return Meta{Version: "test", StartedAt: time.Unix(1000, 0).UTC(), KernelDrops: 7, History: true}
	}
	cfg := Config{Store: store, History: hist, MetaFn: meta, SelfExe: "/opt/atlas"}
	if ui {
		cfg.UI = uiFS
	}
	s := NewServer(cfg)
	s.debounce = 10 * time.Millisecond
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return store, hist, srv
}

func seed(store *graph.Store) {
	store.ObserveConnection(
		graph.NodeSpec{ID: "proc:/usr/bin/curl", Kind: graph.NodeProcess, Label: "curl"},
		graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx"},
		8080, time.Now().UTC(),
	)
}

func getJSON(t *testing.T, url string, out any) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 && out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp
}

func TestGraphEndpoint(t *testing.T) {
	store, _, srv := testServer(t, false)
	seed(store)

	var snap graph.Snapshot
	resp := getJSON(t, srv.URL+"/api/graph", &snap)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(snap.Nodes) != 2 || len(snap.Edges) != 1 {
		t.Fatalf("snapshot %d nodes / %d edges", len(snap.Nodes), len(snap.Edges))
	}
	if snap.Edges[0].DstPort != 8080 {
		t.Fatalf("edge = %+v", snap.Edges[0])
	}
}

// The live graph carries recent health windows sourced from history.
func TestGraphEndpointAttachesWindows(t *testing.T) {
	store, hist, srv := testServer(t, false)
	seed(store)
	id := "proc:/usr/bin/curl->proc:/usr/sbin/nginx:8080"
	hist.EdgeOpened(id, time.Now())
	hist.EdgeRTT(id, 2500, time.Now())

	var snap graph.Snapshot
	getJSON(t, srv.URL+"/api/graph", &snap)
	if snap.Edges[0].Window == nil {
		t.Fatal("live edge missing health window")
	}
	if snap.Edges[0].Window.Opens != 1 || snap.Edges[0].Window.RTTAvgUs != 2500 {
		t.Fatalf("window = %+v", snap.Edges[0].Window)
	}
}

func TestAppViewEndpoint(t *testing.T) {
	store, _, srv := testServer(t, false)
	seed(store)

	var av appview.Graph
	getJSON(t, srv.URL+"/api/appview", &av)
	if len(av.Nodes) != 2 || len(av.Edges) != 1 {
		t.Fatalf("appview %d nodes / %d edges", len(av.Nodes), len(av.Edges))
	}
	if av.Nodes[0].Category == "" {
		t.Fatalf("missing category: %+v", av.Nodes[0])
	}
}

func TestReplayEndpoint(t *testing.T) {
	store, hist, srv := testServer(t, false)
	seed(store)
	now := time.Now()
	id := "proc:/usr/bin/curl->proc:/usr/sbin/nginx:8080"
	hist.EdgeOpened(id, now.Add(-30*time.Second))
	if err := hist.Flush(now); err != nil {
		t.Fatal(err)
	}

	var snap graph.Snapshot
	resp := getJSON(t, fmt.Sprintf("%s/api/graph?at=%d", srv.URL, now.Unix()), &snap)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(snap.Edges) != 1 || snap.Edges[0].Window == nil {
		t.Fatalf("replay snapshot = %+v", snap)
	}

	// Nonsense timestamps are a client error.
	if resp := getJSON(t, srv.URL+"/api/graph?at=banana", nil); resp.StatusCode != 400 {
		t.Fatalf("bad at => %d, want 400", resp.StatusCode)
	}
}

func TestCompareEndpoint(t *testing.T) {
	store, hist, srv := testServer(t, false)
	seed(store)
	base := time.Now().Add(-30 * time.Minute)
	id := "proc:/usr/bin/curl->proc:/usr/sbin/nginx:8080"

	// Era A has the edge; era B is silent.
	hist.EdgeOpened(id, base)
	if err := hist.Flush(base.Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("%s/api/compare?a=%d&b=%d",
		srv.URL, base.Add(30*time.Second).Unix(), base.Add(20*time.Minute).Unix())
	var diff appview.Diff
	resp := getJSON(t, url, &diff)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(diff.RemovedEdges) != 1 {
		t.Fatalf("diff = %+v", diff)
	}
	if len(diff.RemovedNodes) != 2 {
		t.Fatalf("removed nodes = %+v", diff.RemovedNodes)
	}

	if resp := getJSON(t, srv.URL+"/api/compare?a=1", nil); resp.StatusCode != 400 {
		t.Fatalf("missing b => %d, want 400", resp.StatusCode)
	}

	// Reversed order must not invert added/removed: the server
	// normalizes to A = earlier.
	swapped := fmt.Sprintf("%s/api/compare?a=%d&b=%d",
		srv.URL, base.Add(20*time.Minute).Unix(), base.Add(30*time.Second).Unix())
	var diff2 appview.Diff
	getJSON(t, swapped, &diff2)
	if len(diff2.RemovedEdges) != 1 || len(diff2.AddedEdges) != 0 {
		t.Fatalf("reversed compare inverted the diff: %+v", diff2)
	}
}

func TestLifecycleAndMetricsEndpoints(t *testing.T) {
	store, hist, srv := testServer(t, false)
	seed(store)
	now := time.Now()

	hist.NodeEvent("proc:/usr/sbin/nginx", "crash", 200, "killed by SIGSEGV (signal 11)", now.Add(-time.Minute))
	hist.NodeSample("proc:/usr/sbin/nginx", graph.NodeMetrics{
		CPUMillis: 1500, RSSBytes: 64 << 20, FDs: 12, Procs: 2, WindowSecs: 10,
	}, now.Add(-30*time.Second))
	if err := hist.Flush(now); err != nil {
		t.Fatal(err)
	}

	var life struct {
		Events []history.LifeEvent `json:"events"`
	}
	getJSON(t, fmt.Sprintf("%s/api/lifecycle?from=%d&to=%d", srv.URL, now.Add(-10*time.Minute).Unix(), now.Unix()), &life)
	if len(life.Events) != 1 || life.Events[0].Kind != "crash" {
		t.Fatalf("lifecycle = %+v", life)
	}

	var met struct {
		Points []history.MetricPoint `json:"points"`
	}
	getJSON(t, fmt.Sprintf("%s/api/metrics?node=%s&from=%d&to=%d",
		srv.URL, "proc:%2Fusr%2Fsbin%2Fnginx", now.Add(-10*time.Minute).Unix(), now.Unix()), &met)
	if len(met.Points) != 1 || met.Points[0].Metrics.CPUMillis != 1500 {
		t.Fatalf("metrics = %+v", met)
	}

	if resp := getJSON(t, srv.URL+"/api/metrics", nil); resp.StatusCode != 400 {
		t.Fatalf("missing node => %d, want 400", resp.StatusCode)
	}

	// Replay attaches the sampled window to the node.
	var snap graph.Snapshot
	getJSON(t, fmt.Sprintf("%s/api/graph?at=%d", srv.URL, now.Unix()), &snap)
	found := false
	for _, n := range snap.Nodes {
		if n.ID == "proc:/usr/sbin/nginx" {
			found = true
			if n.Metrics == nil || n.Metrics.CPUMillis != 1500 {
				t.Fatalf("replay metrics = %+v", n.Metrics)
			}
		}
	}
	if !found {
		t.Fatalf("nginx missing from replay: %+v", snap.Nodes)
	}
}

func TestCompareCarriesLifecycle(t *testing.T) {
	store, hist, srv := testServer(t, false)
	seed(store)
	base := time.Now().Add(-30 * time.Minute)

	hist.EdgeOpened("proc:/usr/bin/curl->proc:/usr/sbin/nginx:8080", base)
	hist.NodeEvent("proc:/usr/sbin/nginx", "oom", 200, "pid 200 chosen by the OOM killer", base.Add(5*time.Minute))
	if err := hist.Flush(base.Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}

	var diff appview.Diff
	getJSON(t, fmt.Sprintf("%s/api/compare?a=%d&b=%d",
		srv.URL, base.Add(30*time.Second).Unix(), base.Add(10*time.Minute).Unix()), &diff)
	if len(diff.Lifecycle) != 1 {
		t.Fatalf("lifecycle in compare = %+v", diff.Lifecycle)
	}
	e := diff.Lifecycle[0]
	if e.Kind != "oom" || e.Label != "nginx" || e.Node != "svc:proc:nginx" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestTimelineGuards(t *testing.T) {
	_, _, srv := testServer(t, false)
	now := time.Now().Unix()

	// Unbounded bucket count is refused, not materialized.
	if resp := getJSON(t, fmt.Sprintf("%s/api/timeline?from=0&to=%d&step=10", srv.URL, now), nil); resp.StatusCode != 400 {
		t.Fatalf("huge range => %d, want 400", resp.StatusCode)
	}
	// Inverted range is a client error.
	if resp := getJSON(t, fmt.Sprintf("%s/api/timeline?from=%d&to=%d", srv.URL, now, now-100), nil); resp.StatusCode != 400 {
		t.Fatalf("inverted range => %d, want 400", resp.StatusCode)
	}
}

func TestTimelineEndpoint(t *testing.T) {
	_, hist, srv := testServer(t, false)
	now := time.Now()
	hist.EdgeOpened("x->y:1", now.Add(-5*time.Minute))
	if err := hist.Flush(now); err != nil {
		t.Fatal(err)
	}

	var tl struct {
		Step    int                      `json:"step"`
		Buckets []history.TimelineBucket `json:"buckets"`
	}
	resp := getJSON(t, fmt.Sprintf("%s/api/timeline?from=%d&to=%d&step=60",
		srv.URL, now.Add(-10*time.Minute).Unix(), now.Unix()), &tl)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if tl.Step != 60 || len(tl.Buckets) == 0 {
		t.Fatalf("timeline = %+v", tl)
	}
	var opens uint64
	for _, b := range tl.Buckets {
		opens += b.Opens
	}
	if opens != 1 {
		t.Fatalf("timeline opens = %d, want 1", opens)
	}
}

func TestMetaEndpoint(t *testing.T) {
	_, _, srv := testServer(t, false)

	var m Meta
	getJSON(t, srv.URL+"/api/meta", &m)
	if m.Version != "test" || m.KernelDrops != 7 || !m.History {
		t.Fatalf("meta = %+v", m)
	}
}

func TestStreamSendsSnapshotThenUpdates(t *testing.T) {
	store, _, srv := testServer(t, false)
	seed(store)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(srv.URL + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}

	events := make(chan StreamPayload, 4)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if data, ok := strings.CutPrefix(line, "data: "); ok {
				var p StreamPayload
				if json.Unmarshal([]byte(data), &p) == nil {
					events <- p
				}
			}
		}
	}()

	first := waitPayload(t, events, "initial snapshot")
	if len(first.Raw.Nodes) != 2 {
		t.Fatalf("initial raw has %d nodes", len(first.Raw.Nodes))
	}
	if len(first.App.Nodes) != 2 {
		t.Fatalf("initial app view has %d nodes", len(first.App.Nodes))
	}

	store.ObserveConnection(
		graph.NodeSpec{ID: "proc:/usr/bin/wget", Kind: graph.NodeProcess, Label: "wget"},
		graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx"},
		8080, time.Now().UTC(),
	)

	second := waitPayload(t, events, "update snapshot")
	if len(second.Raw.Nodes) != 3 {
		t.Fatalf("update raw has %d nodes, want 3", len(second.Raw.Nodes))
	}
}

func waitPayload(t *testing.T, ch chan StreamPayload, what string) StreamPayload {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return StreamPayload{}
	}
}

func TestUIServedWithSPAFallback(t *testing.T) {
	_, _, srv := testServer(t, true)

	for _, path := range []string{"/", "/some/client/route"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 256)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body[:n]), "atlas-ui") {
			t.Fatalf("%s -> %d %q", path, resp.StatusCode, body[:n])
		}
	}

	resp, err := http.Get(srv.URL + "/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("asset status = %d", resp.StatusCode)
	}
}

func TestUIMissingIsExplicit(t *testing.T) {
	_, _, srv := testServer(t, false)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
