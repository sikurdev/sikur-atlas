package history

import (
	"time"
)

// ---- bulk range queries for the Incident Lens ----
//
// Each merges the unflushed and in-flight (staging) state the same way
// Timeline does, so an investigation of the last few minutes sees the
// buckets that have not hit the database yet.

// EdgeBucketPoint is one stored (or pending) edge health bucket.
type EdgeBucketPoint struct {
	EdgeID   string
	Start    int64 // unix seconds
	Span     int64 // seconds
	Opens    uint64
	Closes   uint64
	Failures uint64
	Resets   uint64
	Retrans  uint64
}

// EdgeBucketsRange returns every edge bucket overlapping (from, to],
// pending state merged, ordered by (edge, start).
func (s *Store) EdgeBucketsRange(from, to time.Time) ([]EdgeBucketPoint, error) {
	fromU, toU := from.Unix(), to.Unix()
	rows, err := s.db.Query(`
SELECT edge_id, bucket, span, opens, closes, failures, resets, retrans
FROM edge_buckets
WHERE bucket + span > ? AND bucket <= ?
ORDER BY edge_id, bucket`, fromU, toU)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EdgeBucketPoint
	for rows.Next() {
		var p EdgeBucketPoint
		if err := rows.Scan(&p.EdgeID, &p.Start, &p.Span, &p.Opens, &p.Closes,
			&p.Failures, &p.Resets, &p.Retrans); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	span := int64(s.fineSpan.Seconds())
	for _, m := range []map[bucketKey]*acc{s.flushing, s.buckets} {
		for k, a := range m {
			if k.start+span <= fromU || k.start > toU {
				continue
			}
			out = append(out, EdgeBucketPoint{
				EdgeID: k.edgeID, Start: k.start, Span: span,
				Opens: a.opens, Closes: a.closes, Failures: a.failures,
				Resets: a.resets, Retrans: a.retrans,
			})
		}
	}
	s.mu.Unlock()
	return out, nil
}

// PresencePoint is one stored node presence bucket.
type PresencePoint struct {
	NodeID    string
	Start     int64
	Span      int64
	Listening bool
}

// PresenceRange returns node presence rows overlapping (from, to].
// Presence is only written at flush time, so the still-open bucket is
// absent — callers must treat the last bucket span as unknown, not gone.
func (s *Store) PresenceRange(from, to time.Time) ([]PresencePoint, error) {
	rows, err := s.db.Query(`
SELECT node_id, bucket, span, listening
FROM node_presence
WHERE bucket + span > ? AND bucket <= ?
ORDER BY node_id, bucket`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PresencePoint
	for rows.Next() {
		var p PresencePoint
		var listening int
		if err := rows.Scan(&p.NodeID, &p.Start, &p.Span, &listening); err != nil {
			return nil, err
		}
		p.Listening = listening > 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// NodeMetricPoint is one stored (or pending) node resource bucket, the
// subset of columns the Lens rules consume.
type NodeMetricPoint struct {
	NodeID      string
	Start       int64
	Span        int64
	OOMKills    uint64
	RSSMax      uint64
	MemLimit    uint64
	ThrottledUs uint64
}

// NodeMetricsRange returns node metric buckets overlapping (from, to],
// pending state merged, ordered by (node, start).
func (s *Store) NodeMetricsRange(from, to time.Time) ([]NodeMetricPoint, error) {
	fromU, toU := from.Unix(), to.Unix()
	rows, err := s.db.Query(`
SELECT node_id, bucket, span, oom_kills, rss_max, mem_limit, throttled_us
FROM node_metrics
WHERE bucket + span > ? AND bucket <= ?
ORDER BY node_id, bucket`, fromU, toU)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeMetricPoint
	for rows.Next() {
		var p NodeMetricPoint
		if err := rows.Scan(&p.NodeID, &p.Start, &p.Span, &p.OOMKills,
			&p.RSSMax, &p.MemLimit, &p.ThrottledUs); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	span := int64(s.fineSpan.Seconds())
	for _, m := range []map[metricKey]*metricAcc{s.flushingMetrics, s.metrics} {
		for k, a := range m {
			if k.start+span <= fromU || k.start > toU {
				continue
			}
			out = append(out, NodeMetricPoint{
				NodeID: k.nodeID, Start: k.start, Span: span,
				OOMKills: a.oomKills, RSSMax: a.rssMax,
				MemLimit: a.memLimit, ThrottledUs: a.throttledUs,
			})
		}
	}
	s.mu.Unlock()
	return out, nil
}
