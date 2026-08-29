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
	"strings"
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
	opens, closes, failures uint64
	resets, retrans         uint64
	bytesSent, bytesRecv    uint64
	rttSumUs, rttCount      uint64
	rttMaxUs                uint32
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

	mu      sync.Mutex
	buckets map[bucketKey]*acc
	// flushing stages drained buckets while their transaction is in
	// flight, so readers never see a gap and a failed flush can requeue
	// instead of losing telemetry.
	flushing    map[bucketKey]*acc
	active      map[string]int64 // per-edge open connections
	metaVersion uint64           // last successfully committed graph version

	// v0.3: lifecycle events and resource samples awaiting flush.
	pendingEvents      []LifeEvent
	pendingEventCounts map[string]int
	eventsDropped      uint64
	metrics            map[metricKey]*metricAcc
}

func mergeAcc(dst, src *acc) {
	dst.opens += src.opens
	dst.closes += src.closes
	dst.failures += src.failures
	dst.resets += src.resets
	dst.retrans += src.retrans
	dst.bytesSent += src.bytesSent
	dst.bytesRecv += src.bytesRecv
	dst.rttSumUs += src.rttSumUs
	dst.rttCount += src.rttCount
	if src.rttMaxUs > dst.rttMaxUs {
		dst.rttMaxUs = src.rttMaxUs
	}
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
		db:                 db,
		graph:              graphStore,
		fineSpan:           DefaultFineSpan,
		coarseSpan:         DefaultCoarseSpan,
		fineRetention:      DefaultFineRetention,
		coarseRetention:    DefaultCoarseRetention,
		buckets:            make(map[bucketKey]*acc),
		active:             make(map[string]int64),
		pendingEventCounts: make(map[string]int),
		metrics:            make(map[metricKey]*metricAcc),
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
CREATE TABLE IF NOT EXISTS lifecycle_events (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  node_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  pid INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_ts ON lifecycle_events(ts);
CREATE TABLE IF NOT EXISTS node_metrics (
  node_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  span INTEGER NOT NULL,
  cpu_ms INTEGER NOT NULL DEFAULT 0,
  rss_max INTEGER NOT NULL DEFAULT 0,
  io_read INTEGER NOT NULL DEFAULT 0,
  io_write INTEGER NOT NULL DEFAULT 0,
  fds INTEGER NOT NULL DEFAULT 0,
  threads INTEGER NOT NULL DEFAULT 0,
  procs INTEGER NOT NULL DEFAULT 0,
  throttled_us INTEGER NOT NULL DEFAULT 0,
  oom_kills INTEGER NOT NULL DEFAULT 0,
  mem_limit INTEGER NOT NULL DEFAULT 0,
  psi_cpu INTEGER NOT NULL DEFAULT 0,
  psi_mem INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, bucket, span)
);
CREATE INDEX IF NOT EXISTS idx_node_metrics_bucket ON node_metrics(bucket);
`)
	if err != nil {
		return err
	}
	// v0.2 → v0.3 upgrade: unix edges carry a socket path.
	if _, err := s.db.Exec(`ALTER TABLE edges ADD COLUMN path TEXT NOT NULL DEFAULT ''`); err != nil {
		// Duplicate column on an already-migrated database: fine.
		if !isDuplicateColumn(err) {
			return err
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column")
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
// memory. Drained buckets are staged (still visible to readers) until
// the transaction commits, and requeued if it fails, so a transient
// database error never loses telemetry.
func (s *Store) Flush(now time.Time) error {
	cutoff := now.Truncate(s.fineSpan).Unix()
	span := int64(s.fineSpan.Seconds())
	lastBucket := cutoff - span

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
	// Idle-but-open edges keep their presence alive with an empty row —
	// but only edges whose activity is NOT in the still-open bucket:
	// writing a row for those would backdate them into an era before
	// they existed.
	current := make(map[string]bool)
	for k := range s.buckets {
		current[k.edgeID] = true
	}
	for edgeID, n := range s.active {
		if n <= 0 || current[edgeID] {
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
	// Lifecycle events and completed metric buckets flush in the same
	// transaction. Pending events remain visible to LifecycleRange via
	// doneEvents until requeued or committed... they are drained here
	// and requeued on failure like the counters.
	doneEvents := s.pendingEvents
	s.pendingEvents = nil
	s.pendingEventCounts = make(map[string]int)
	doneMetrics := make(map[metricKey]*metricAcc)
	for k, a := range s.metrics {
		if k.start < cutoff {
			doneMetrics[k] = a
			delete(s.metrics, k)
		}
	}
	// Readers merge s.flushing, so the drained interval stays visible
	// while the transaction runs. (Between commit and the clear below a
	// reader could briefly double-count the interval — a microsecond
	// in-memory window, preferred over the old full-interval gap.)
	s.flushing = done
	s.mu.Unlock()

	committedVersion, err := s.flushTx(done, doneEvents, doneMetrics, activeSnapshot, now, lastBucket, span)

	s.mu.Lock()
	s.flushing = nil
	if err != nil {
		for k, a := range done {
			if exist, ok := s.buckets[k]; ok {
				mergeAcc(exist, a)
			} else {
				s.buckets[k] = a
			}
		}
		s.pendingEvents = append(doneEvents, s.pendingEvents...)
		for _, e := range doneEvents {
			s.pendingEventCounts[e.NodeID]++
		}
		for k, a := range doneMetrics {
			if _, ok := s.metrics[k]; !ok {
				s.metrics[k] = a
			}
		}
	} else if committedVersion != 0 {
		s.metaVersion = committedVersion
	}
	s.mu.Unlock()
	return err
}

func (s *Store) flushTx(done map[bucketKey]*acc, doneEvents []LifeEvent, doneMetrics map[metricKey]*metricAcc, activeSnapshot map[string]int64, now time.Time, lastBucket, span int64) (uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	for _, e := range doneEvents {
		if _, err := tx.Exec(`
INSERT INTO lifecycle_events (ts, node_id, kind, pid, detail) VALUES (?,?,?,?,?)`,
			e.Time.Unix(), e.NodeID, e.Kind, e.PID, e.Detail); err != nil {
			return 0, err
		}
	}
	for k, a := range doneMetrics {
		if _, err := tx.Exec(`
INSERT INTO node_metrics (node_id, bucket, span, cpu_ms, rss_max, io_read, io_write,
  fds, threads, procs, throttled_us, oom_kills, mem_limit, psi_cpu, psi_mem)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(node_id, bucket, span) DO UPDATE SET
  cpu_ms=cpu_ms+excluded.cpu_ms, rss_max=MAX(rss_max, excluded.rss_max),
  io_read=io_read+excluded.io_read, io_write=io_write+excluded.io_write,
  fds=excluded.fds, threads=excluded.threads, procs=excluded.procs,
  throttled_us=throttled_us+excluded.throttled_us,
  oom_kills=oom_kills+excluded.oom_kills, mem_limit=excluded.mem_limit,
  psi_cpu=MAX(psi_cpu, excluded.psi_cpu), psi_mem=MAX(psi_mem, excluded.psi_mem)`,
			k.nodeID, k.start, int64(s.fineSpan.Seconds()),
			a.cpuMillis, a.rssMax, a.ioRead, a.ioWrite,
			a.fds, a.threads, a.procs, a.throttledUs, a.oomKills, a.memLimit,
			a.psiCPUx100, a.psiMemX100); err != nil {
			return 0, err
		}
	}

	for k, a := range done {
		// active_end only means "open connections as of this flush" for
		// the just-completed bucket; a late write into an older bucket
		// (a stashed close applied after its bucket flushed) must not
		// stamp a present-day count into a past era.
		activeEnd := int64(0)
		if k.start >= lastBucket {
			activeEnd = activeSnapshot[k.edgeID]
		}
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
  active_end=CASE WHEN edge_buckets.bucket >= ? THEN excluded.active_end
                  ELSE edge_buckets.active_end END`,
			k.edgeID, k.start, span,
			a.opens, a.closes, a.failures, a.resets, a.retrans,
			a.bytesSent, a.bytesRecv, a.rttSumUs, a.rttCount, a.rttMaxUs,
			activeEnd, lastBucket,
		); err != nil {
			return 0, err
		}
	}

	var version uint64
	if s.graph != nil {
		if version, err = s.flushMeta(tx, now, lastBucket, span); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}

func (s *Store) flushMeta(tx *sql.Tx, now time.Time, bucket, span int64) (uint64, error) {
	snap := s.graph.Snapshot()

	s.mu.Lock()
	// metaVersion is only advanced by the caller after a successful
	// commit; comparing here just decides whether upserts can be
	// skipped.
	sameVersion := snap.Version == s.metaVersion && snap.Version != 0
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
				return 0, err
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
				return 0, err
			}
		}
	}
	if !sameVersion {
		for i := range snap.Edges {
			e := &snap.Edges[i]
			if _, err := tx.Exec(`
INSERT INTO edges (id, src, dst, dst_port, protocol, path, first_seen, last_seen)
VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen`,
				e.ID, e.Src, e.Dst, e.DstPort, e.Protocol, e.Path,
				e.FirstSeen.Unix(), e.LastSeen.Unix(),
			); err != nil {
				return 0, err
			}
		}
	}
	_ = now
	return snap.Version, nil
}

// FinalFlush persists everything including the still-open bucket. Call
// once at shutdown, before Close.
func (s *Store) FinalFlush() error {
	return s.Flush(time.Now().Add(s.fineSpan))
}

// Run flushes on the fine-span cadence and applies retention hourly
// until ctx is done. Errors are delivered to onError (may be nil).
// The caller owns the shutdown flush (FinalFlush) so it cannot race
// process exit.
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
			return
		case now := <-flush.C:
			report(s.Flush(now))
		case now := <-retain.C:
			report(s.Compact(now))
		}
	}
}
