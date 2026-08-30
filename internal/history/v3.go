package history

import (
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

// ---- v0.3 recorder surface: unix edges, lifecycle, resources ----

// EdgeConnects counts successful connects without touching the standing
// gauge (AF_UNIX semantics: connects are exact, standing pairs are
// sampled separately).
func (s *Store) EdgeConnects(edgeID string, n uint64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucketFor(edgeID, at).opens += n
}

// EdgeActive adjusts only the standing-connection gauge.
func (s *Store) EdgeActive(edgeID string, delta int64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.active[edgeID] + delta; n > 0 {
		s.active[edgeID] = n
	} else {
		delete(s.active, edgeID)
	}
}

// LifeEvent is one persisted lifecycle event.
type LifeEvent struct {
	NodeID string    `json:"node"`
	Kind   string    `json:"kind"` // exec | exit | crash | oom
	PID    uint32    `json:"pid"`
	Detail string    `json:"detail"`
	Time   time.Time `json:"time"`
}

// Cap of buffered lifecycle events per node between flushes: an exec
// storm inside one service must not flood the store.
const maxPendingEventsPerNode = 40

// NodeEvent records a lifecycle event for persistence.
func (s *Store) NodeEvent(nodeID, kind string, pid uint32, detail string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingEventCounts[nodeID] >= maxPendingEventsPerNode {
		s.eventsDropped++
		return
	}
	s.pendingEventCounts[nodeID]++
	s.pendingEvents = append(s.pendingEvents, LifeEvent{
		NodeID: nodeID, Kind: kind, PID: pid, Detail: detail, Time: at,
	})
}

// metricKey buckets node samples.
type metricKey struct {
	nodeID string
	start  int64
}

type metricAcc struct {
	cpuMillis   uint64
	rssMax      uint64
	ioRead      uint64
	ioWrite     uint64
	fds         int
	threads     int
	procs       int
	throttledUs uint64
	oomKills    uint64
	memLimit    uint64
	psiCPUx100  uint32
	psiMemX100  uint32
}

// NodeSample folds one resource sample into the node's current bucket:
// deltas accumulate, gauges keep the maximum (RSS, PSI) or the latest
// (fds/threads/procs/limit).
func (s *Store) NodeSample(nodeID string, m graph.NodeMetrics, at time.Time) {
	k := metricKey{nodeID: nodeID, start: at.Truncate(s.fineSpan).Unix()}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.metrics[k]
	if !ok {
		a = &metricAcc{}
		s.metrics[k] = a
	}
	a.cpuMillis += m.CPUMillis
	a.ioRead += m.IOReadBytes
	a.ioWrite += m.IOWriteBytes
	a.throttledUs += m.ThrottledUs
	a.oomKills += m.OOMKills
	if m.RSSBytes > a.rssMax {
		a.rssMax = m.RSSBytes
	}
	a.fds = m.FDs
	a.threads = m.Threads
	a.procs = m.Procs
	a.memLimit = m.MemLimit
	if v := uint32(m.PSICpuSomePct * 100); v > a.psiCPUx100 {
		a.psiCPUx100 = v
	}
	if v := uint32(m.PSIMemSomePct * 100); v > a.psiMemX100 {
		a.psiMemX100 = v
	}
}

// LifecycleRange returns events in (from, to], newest last, merging the
// unflushed buffer so live views are current.
func (s *Store) LifecycleRange(from, to time.Time, nodeID string) ([]LifeEvent, error) {
	q := `
SELECT node_id, kind, pid, detail, ts FROM lifecycle_events
WHERE ts > ? AND ts <= ?`
	args := []any{from.Unix(), to.Unix()}
	if nodeID != "" {
		q += ` AND node_id = ?`
		args = append(args, nodeID)
	}
	q += ` ORDER BY ts`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LifeEvent
	for rows.Next() {
		var e LifeEvent
		var ts int64
		if err := rows.Scan(&e.NodeID, &e.Kind, &e.PID, &e.Detail, &ts); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	// Staged events (in-flight flush) are not yet committed and no
	// longer pending: merge both so a running flush opens no gap.
	for _, buf := range [][]LifeEvent{s.flushingEvents, s.pendingEvents} {
		for _, e := range buf {
			if e.Time.After(from) && !e.Time.After(to) &&
				(nodeID == "" || e.NodeID == nodeID) {
				out = append(out, e)
			}
		}
	}
	s.mu.Unlock()
	return out, nil
}

// MetricPoint is one bucket of a node's resource series.
type MetricPoint struct {
	Start   int64             `json:"start"`
	Span    int64             `json:"span"`
	Metrics graph.NodeMetrics `json:"metrics"`
}

// MetricsRange returns a node's resource buckets overlapping (from, to],
// merging unflushed samples.
func (s *Store) MetricsRange(nodeID string, from, to time.Time) ([]MetricPoint, error) {
	rows, err := s.db.Query(`
SELECT bucket, span, cpu_ms, rss_max, io_read, io_write, fds, threads, procs,
       throttled_us, oom_kills, mem_limit, psi_cpu, psi_mem
FROM node_metrics
WHERE node_id = ? AND bucket + span > ? AND bucket <= ?
ORDER BY bucket`, nodeID, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricPoint
	for rows.Next() {
		p, err := scanMetricPoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	// Staged buckets (in-flight flush) merge like pending ones so a
	// running flush opens no gap.
	for _, buf := range []map[metricKey]*metricAcc{s.flushingMetrics, s.metrics} {
		for k, a := range buf {
			if k.nodeID != nodeID || k.start < from.Unix() || k.start > to.Unix() {
				continue
			}
			out = append(out, MetricPoint{
				Start: k.start, Span: int64(s.fineSpan.Seconds()),
				Metrics: accToMetrics(a, int(s.fineSpan.Seconds())),
			})
		}
	}
	s.mu.Unlock()
	return out, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanMetricPoint(rows rowScanner) (MetricPoint, error) {
	var p MetricPoint
	var m graph.NodeMetrics
	var psiCPU, psiMem uint32
	if err := rows.Scan(&p.Start, &p.Span, &m.CPUMillis, &m.RSSBytes,
		&m.IOReadBytes, &m.IOWriteBytes, &m.FDs, &m.Threads, &m.Procs,
		&m.ThrottledUs, &m.OOMKills, &m.MemLimit, &psiCPU, &psiMem); err != nil {
		return p, err
	}
	m.WindowSecs = int(p.Span)
	m.PSICpuSomePct = float64(psiCPU) / 100
	m.PSIMemSomePct = float64(psiMem) / 100
	p.Metrics = m
	return p, nil
}

func accToMetrics(a *metricAcc, windowSecs int) graph.NodeMetrics {
	return graph.NodeMetrics{
		WindowSecs:    windowSecs,
		CPUMillis:     a.cpuMillis,
		RSSBytes:      a.rssMax,
		IOReadBytes:   a.ioRead,
		IOWriteBytes:  a.ioWrite,
		FDs:           a.fds,
		Threads:       a.threads,
		Procs:         a.procs,
		ThrottledUs:   a.throttledUs,
		OOMKills:      a.oomKills,
		MemLimit:      a.memLimit,
		PSICpuSomePct: float64(a.psiCPUx100) / 100,
		PSIMemSomePct: float64(a.psiMemX100) / 100,
	}
}
