// Package history persists the topology and its health telemetry into an
// embedded SQLite database so past graph states can be reconstructed
// (Topology Replay) and two moments can be compared.
//
// Model: per-edge counters are accumulated into fixed time buckets
// (fine span, default 10s). A flusher writes completed buckets plus node
// presence and metadata. Retention compacts fine buckets into coarse
// ones (default 5m) after a few hours and drops coarse buckets after
// days. Reconstruction at time T = everything with activity or presence
// in a trailing window, with metrics summed over a metric window.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite driver

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

// Defaults; tests override via Options.
const (
	DefaultFineSpan        = 10 * time.Second
	DefaultCoarseSpan      = 5 * time.Minute
	DefaultFineRetention   = 2 * time.Hour
	DefaultCoarseRetention = 7 * 24 * time.Hour

	// DefaultPresenceWindow: how far back from T something must have
	// been seen to count as "present at T". Must comfortably exceed the
	// listen-scan interval (30s).
	DefaultPresenceWindow = 2 * time.Minute
	// DefaultMetricWindow: the trailing window whose sums are shown as
	// "activity at T".
	DefaultMetricWindow = time.Minute
)

type bucketKey struct {
	edgeID string
	start  int64
}

type acc struct {
	opens, closes, failures    uint64
	resets, retrans            uint64
	bytesSent, bytesRecv       uint64
	rttSumUs, rttCount         uint64
	rttMaxUs                   uint32
}

// Store owns the database and the in-memory accumulation state.
// Recorder methods (EdgeOpened etc.) implement collector.Recorder.
type Store struct {
	db    *sql.DB
	graph *graph.Store

	fineSpan        time.Duration
	coarseSpan      time.Duration
	fineRetention   time.Duration
	coarseRetention time.Duration

	mu           sync.Mutex
	buckets      map[bucketKey]*acc
	active       map[string]int64 // per-edge open connections
	metaVersion  uint64           // last flushed graph version
}

// Option configures a Store.
type Option func(*Store)

// WithSpans overrides bucket spans (used by tests).
func WithSpans(fine, coarse time.Duration) Option {
	return func(s *Store) {
		s.fineSpan = fine
		s.coarseSpan = coarse
	}
}

// WithRetention overrides retention windows.
func WithRetention(fine, coarse time.Duration) Option {
	return func(s *Store) {
		s.fineRetention = fine
		s.coarseRetention = coarse
	}
}

// Open opens (creating if needed) the history database. graphStore
// supplies node/edge metadata at flush time.
func Open(path string, graphStore *graph.Store, opts ...Option) (*Store, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening history db: %w", err)
	}
	// modernc/sqlite serializes writes; a single connection avoids
	// SQLITE_BUSY between the flusher and query paths.
	db.SetMaxOpenConns(1)

	s := &Store{
		db:              db,
		graph:           graphStore,
		fineSpan:        DefaultFineSpan,
		coarseSpan:      DefaultCoarseSpan,
		fineRetention:   DefaultFineRetention,
		coarseRetention: DefaultCoarseRetention,
		buckets:         make(map[bucketKey]*acc),
		active:          make(map[string]int64),
	}
	for _, o := range opts {
		o(s)
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  kind TEXT, label TEXT, exe TEXT,
  container_id TEXT, container_name TEXT, image TEXT,
  compose_project TEXT, compose_service TEXT,
  listen_ports TEXT, addrs TEXT, pids TEXT,
  first_seen INTEGER, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS edges (
  id TEXT PRIMARY KEY,
  src TEXT, dst TEXT, dst_port INTEGER, protocol TEXT,
  first_seen INTEGER, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS edge_buckets (
  edge_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  span INTEGER NOT NULL,
  opens INTEGER NOT NULL DEFAULT 0,
  closes INTEGER NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0,
  resets INTEGER NOT NULL DEFAULT 0,
  retrans INTEGER NOT NULL DEFAULT 0,
  bytes_sent INTEGER NOT NULL DEFAULT 0,
  bytes_recv INTEGER NOT NULL DEFAULT 0,
  rtt_sum_us INTEGER NOT NULL DEFAULT 0,
  rtt_count INTEGER NOT NULL DEFAULT 0,
  rtt_max_us INTEGER NOT NULL DEFAULT 0,
  active_end INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (edge_id, bucket, span)
);
CREATE INDEX IF NOT EXISTS idx_edge_buckets_bucket ON edge_buckets(bucket);
CREATE TABLE IF NOT EXISTS node_presence (
  node_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  span INTEGER NOT NULL,
  listening INTEGER NOT NULL DEFAULT 0,
  listen_ports TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (node_id, bucket, span)
);
CREATE INDEX IF NOT EXISTS idx_node_presence_bucket ON node_presence(bucket);
`)
	return err
}

// Close flushes nothing (callers Flush first) and closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// ---- collector.Recorder implementation ----

func (s *Store) bucketFor(edgeID string, at time.Time) *acc {
	k := bucketKey{edgeID: edgeID, start: at.Truncate(s.fineSpan).Unix()}
	a, ok := s.buckets[k]
	if !ok {
		a = &acc{}
		s.buckets[k] = a
	}
	return a
}

func (s *Store) EdgeOpened(edgeID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucketFor(edgeID, at).opens++
	s.active[edgeID]++
}

func (s *Store) EdgeClosed(edgeID string, bytesSent, bytesRecv uint64, rttUs uint32, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.bucketFor(edgeID, at)
	a.closes++
	a.bytesSent += bytesSent
	a.bytesRecv += bytesRecv
	if rttUs > 0 {
		a.rttSumUs += uint64(rttUs)
		a.rttCount++
		if rttUs > a.rttMaxUs {
			a.rttMaxUs = rttUs
		}
	}
	s.decActive(edgeID)
}

func (s *Store) EdgeExpired(edgeID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucketFor(edgeID, at).closes++
	s.decActive(edgeID)
}

func (s *Store) decActive(edgeID string) {
	if n := s.active[edgeID] - 1; n > 0 {
		s.active[edgeID] = n
	} else {
		delete(s.active, edgeID)
	}
}

func (s *Store) EdgeFailure(edgeID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucketFor(edgeID, at).failures++
}

func (s *Store) EdgeResets(edgeID string, n uint64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucketFor(edgeID, at).resets += n
}

func (s *Store) EdgeRetrans(edgeID string, n uint64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucketFor(edgeID, at).retrans += n
}

func (s *Store) EdgeRTT(edgeID string, rttUs uint32, at time.Time) {
	if rttUs == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.bucketFor(edgeID, at)
	a.rttSumUs += uint64(rttUs)
	a.rttCount++
	if rttUs > a.rttMaxUs {
		a.rttMaxUs = rttUs
	}
}

// ---- flushing ----

// Flush writes all buckets that ended at or before now, plus node/edge
// metadata and presence rows. The current (still open) bucket stays in
// memory.
func (s *Store) Flush(now time.Time) error {
	cutoff := now.Truncate(s.fineSpan).Unix()

	s.mu.Lock()
	done := make(map[bucketKey]*acc)
	for k, a := range s.buckets {
		// Buckets are span-aligned, so start < cutoff means the bucket
		// has fully ended by `now`.
		if k.start < cutoff {
			done[k] = a
			delete(s.buckets, k)
		}
	}
	// Idle-but-open edges keep their presence alive with an empty row
	// carrying the active count, in the just-completed bucket.
	lastBucket := cutoff - int64(s.fineSpan.Seconds())
	for edgeID, n := range s.active {
		if n <= 0 {
			continue
		}
		k := bucketKey{edgeID: edgeID, start: lastBucket}
		if _, ok := done[k]; !ok {
			done[k] = &acc{}
		}
	}
	activeSnapshot := make(map[string]int64, len(s.active))
	for k, v := range s.active {
		activeSnapshot[k] = v
	}
	s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	span := int64(s.fineSpan.Seconds())
	for k, a := range done {
		if _, err := tx.Exec(`
INSERT INTO edge_buckets (edge_id, bucket, span, opens, closes, failures, resets, retrans,
  bytes_sent, bytes_recv, rtt_sum_us, rtt_count, rtt_max_us, active_end)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(edge_id, bucket, span) DO UPDATE SET
  opens=opens+excluded.opens, closes=closes+excluded.closes,
  failures=failures+excluded.failures, resets=resets+excluded.resets,
  retrans=retrans+excluded.retrans,
  bytes_sent=bytes_sent+excluded.bytes_sent, bytes_recv=bytes_recv+excluded.bytes_recv,
  rtt_sum_us=rtt_sum_us+excluded.rtt_sum_us, rtt_count=rtt_count+excluded.rtt_count,
  rtt_max_us=MAX(rtt_max_us, excluded.rtt_max_us),
  active_end=excluded.active_end`,
			k.edgeID, k.start, span,
			a.opens, a.closes, a.failures, a.resets, a.retrans,
			a.bytesSent, a.bytesRecv, a.rttSumUs, a.rttCount, a.rttMaxUs,
			activeSnapshot[k.edgeID],
		); err != nil {
			return err
		}
	}

	if s.graph != nil {
		if err := s.flushMeta(tx, now, lastBucket, span); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) flushMeta(tx *sql.Tx, now time.Time, bucket, span int64) error {
	snap := s.graph.Snapshot()

	s.mu.Lock()
	sameVersion := snap.Version == s.metaVersion && snap.Version != 0
	s.metaVersion = snap.Version
	s.mu.Unlock()

	bucketStart := time.Unix(bucket, 0)
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if !sameVersion {
			ports, _ := json.Marshal(n.ListenPorts)
			addrs, _ := json.Marshal(n.Addrs)
			pids, _ := json.Marshal(n.PIDs)
			if _, err := tx.Exec(`
INSERT INTO nodes (id, kind, label, exe, container_id, container_name, image,
  compose_project, compose_service, listen_ports, addrs, pids, first_seen, last_seen)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  kind=excluded.kind, label=excluded.label, exe=excluded.exe,
  container_id=excluded.container_id, container_name=excluded.container_name,
  image=excluded.image, compose_project=excluded.compose_project,
  compose_service=excluded.compose_service, listen_ports=excluded.listen_ports,
  addrs=excluded.addrs, pids=excluded.pids, last_seen=excluded.last_seen`,
				n.ID, string(n.Kind), n.Label, n.Exe, n.ContainerID, n.ContainerName,
				n.Image, n.ComposeProject, n.ComposeService,
				string(ports), string(addrs), string(pids),
				n.FirstSeen.Unix(), n.LastSeen.Unix(),
			); err != nil {
				return err
			}
		}
		// Presence: node was seen during (or after) the flushed bucket.
		// Listen ports are snapshotted per presence row so Replay shows
		// the ports of that era, not today's.
		if n.LastSeen.After(bucketStart) || n.LastSeen.Equal(bucketStart) {
			listening := 0
			portsJSON := ""
			if len(n.ListenPorts) > 0 {
				listening = 1
				b, _ := json.Marshal(n.ListenPorts)
				portsJSON = string(b)
			}
			if _, err := tx.Exec(`
INSERT INTO node_presence (node_id, bucket, span, listening, listen_ports) VALUES (?,?,?,?,?)
ON CONFLICT(node_id, bucket, span) DO UPDATE SET
  listening=MAX(listening, excluded.listening),
  listen_ports=CASE WHEN excluded.listening > 0 THEN excluded.listen_ports ELSE listen_ports END`,
				n.ID, bucket, span, listening, portsJSON,
			); err != nil {
				return err
			}
		}
	}
	if !sameVersion {
		for i := range snap.Edges {
			e := &snap.Edges[i]
			if _, err := tx.Exec(`
INSERT INTO edges (id, src, dst, dst_port, protocol, first_seen, last_seen)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen`,
				e.ID, e.Src, e.Dst, e.DstPort, e.Protocol,
				e.FirstSeen.Unix(), e.LastSeen.Unix(),
			); err != nil {
				return err
			}
		}
	}
	_ = now
	return nil
}

// Run flushes on the fine-span cadence and applies retention hourly
// until ctx is done. Errors are delivered to onError (may be nil).
func (s *Store) Run(ctx context.Context, onError func(error)) {
	flush := time.NewTicker(s.fineSpan)
	defer flush.Stop()
	retain := time.NewTicker(time.Hour)
	defer retain.Stop()

	report := func(err error) {
		if err != nil && onError != nil {
			onError(err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			report(s.Flush(time.Now().Add(s.fineSpan))) // final flush incl. open bucket
			return
		case now := <-flush.C:
			report(s.Flush(now))
		case now := <-retain.C:
			report(s.Compact(now))
		}
	}
}
