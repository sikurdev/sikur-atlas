package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

func testServer(t *testing.T, ui bool) (*Server, *graph.Store, *httptest.Server) {
	t.Helper()
	store := graph.NewStore()
	var uiFS fstest.MapFS
	if ui {
		uiFS = fstest.MapFS{
			"index.html":    {Data: []byte("<html><body>atlas-ui</body></html>")},
			"assets/app.js": {Data: []byte("console.log('x')")},
		}
	}
	meta := func() Meta {
		return Meta{Version: "test", StartedAt: time.Unix(1000, 0).UTC(), KernelDrops: 7}
	}
	var s *Server
	if ui {
		s = NewServer(store, meta, uiFS)
	} else {
		s = NewServer(store, meta, nil)
	}
	s.debounce = 10 * time.Millisecond
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, store, srv
}

func seed(store *graph.Store) {
	store.ObserveConnection(
		graph.NodeSpec{ID: "proc:/usr/bin/curl", Kind: graph.NodeProcess, Label: "curl"},
		graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx"},
		8080, time.Unix(2000, 0).UTC(),
	)
}

func TestGraphEndpoint(t *testing.T) {
	_, store, srv := testServer(t, false)
	seed(store)

	resp, err := http.Get(srv.URL + "/api/graph")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var snap graph.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Nodes) != 2 || len(snap.Edges) != 1 {
		t.Fatalf("snapshot %d nodes / %d edges", len(snap.Nodes), len(snap.Edges))
	}
	if snap.Edges[0].DstPort != 8080 {
		t.Fatalf("edge = %+v", snap.Edges[0])
	}
}

func TestMetaEndpoint(t *testing.T) {
	_, _, srv := testServer(t, false)

	resp, err := http.Get(srv.URL + "/api/meta")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m Meta
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "test" || m.KernelDrops != 7 {
		t.Fatalf("meta = %+v", m)
	}
}

func TestStreamSendsSnapshotThenUpdates(t *testing.T) {
	_, store, srv := testServer(t, false)
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

	events := make(chan graph.Snapshot, 4)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if data, ok := strings.CutPrefix(line, "data: "); ok {
				var snap graph.Snapshot
				if json.Unmarshal([]byte(data), &snap) == nil {
					events <- snap
				}
			}
		}
	}()

	first := waitSnap(t, events, "initial snapshot")
	if len(first.Nodes) != 2 {
		t.Fatalf("initial snapshot has %d nodes", len(first.Nodes))
	}

	store.ObserveConnection(
		graph.NodeSpec{ID: "proc:/usr/bin/wget", Kind: graph.NodeProcess, Label: "wget"},
		graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx"},
		8080, time.Unix(3000, 0).UTC(),
	)

	second := waitSnap(t, events, "update snapshot")
	if len(second.Nodes) != 3 {
		t.Fatalf("update snapshot has %d nodes, want 3", len(second.Nodes))
	}
}

func waitSnap(t *testing.T, ch chan graph.Snapshot, what string) graph.Snapshot {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return graph.Snapshot{}
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
