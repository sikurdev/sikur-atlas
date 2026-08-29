package history

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

// SnapshotAt reconstructs the graph as it stood at time t: nodes and
// edges seen within the presence window before t, with metrics summed
// over the metric window. Zero windows use the defaults.
func (s *Store) SnapshotAt(t time.Time, presence, metric time.Duration) (graph.Snapshot, error) {
	if presence <= 0 {
		presence = DefaultPresenceWindow
	}
	if metric <= 0 {
		metric = DefaultMetricWindow
	}
	tU := t.Unix()
	presFrom := t.Add(-presence).Unix()
	metricFrom := t.Add(-metric).Unix()

	type edgeAgg struct {
		w          graph.EdgeWindow
		rttSum     uint64
		rttCount   uint64
		lastBucket int64
		lastActive int64
		lastRTT    uint32
	}
	aggs := make(map[string]*edgeAgg)

	// bucket < t (strict): a bucket starting exactly at t lies entirely
	// in t's future. A bucket straddling t contributes whole — replay
	// resolution equals the bucket span, as documented.
	rows, err := s.db.Query(`
SELECT edge_id, bucket, span, opens, closes, failures, resets, retrans,
       bytes_sent, bytes_recv, rtt_sum_us, rtt_count, rtt_max_us, active_end
FROM edge_buckets
WHERE bucket + span > ? AND bucket < ?
ORDER BY bucket`, presFrom, tU)
	if err != nil {
		return graph.Snapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var bucket, span, activeEnd int64
		var opens, closes, failures, resets, retrans, bs, br, rttSum, rttCount uint64
		var rttMax uint32
		if err := rows.Scan(&id, &bucket, &span, &opens, &closes, &failures, &resets,
			&retrans, &bs, &br, &rttSum, &rttCount, &rttMax, &activeEnd); err != nil {
			return graph.Snapshot{}, err
		}
		a, ok := aggs[id]
		if !ok {
			a = &edgeAgg{}
			aggs[id] = a
		}
		if bucket >= a.lastBucket {
			a.lastBucket = bucket
			a.lastActive = activeEnd
		}
		if bucket+span > metricFrom {
			a.w.Opens += opens
			a.w.Closes += closes
			a.w.Failures += failures
			a.w.Resets += resets
			a.w.Retransmits += retrans
			a.w.BytesSent += bs
			a.w.BytesRecv += br
			a.rttSum += rttSum
			a.rttCount += rttCount
			if rttMax > a.lastRTT {
				a.lastRTT = rttMax
			}
			if rttMax > a.w.RTTMaxUs {
				a.w.RTTMaxUs = rttMax
			}
		}
	}
	if err := rows.Err(); err != nil {
		return graph.Snapshot{}, err
	}

	nodeIDs := make(map[string]int64)     // id -> latest presence bucket end
	eraPorts := make(map[string][]uint16) // id -> ports in this era
	prows, err := s.db.Query(`
SELECT node_id, bucket, span, listening, listen_ports
FROM node_presence
WHERE bucket + span > ? AND bucket < ?
ORDER BY bucket`, presFrom, tU)
	if err != nil {
		return graph.Snapshot{}, err
	}
	defer prows.Close()
	for prows.Next() {
		var id, portsJSON string
		var bucket, span int64
		var listening int
		if err := prows.Scan(&id, &bucket, &span, &listening, &portsJSON); err != nil {
			return graph.Snapshot{}, err
		}
		if end := bucket + span; end > nodeIDs[id] {
			nodeIDs[id] = end
		}
		if listening > 0 && portsJSON != "" {
			var ports []uint16
			if json.Unmarshal([]byte(portsJSON), &ports) == nil {
				eraPorts[id] = ports
			}
		}
	}
	if err := prows.Err(); err != nil {
		return graph.Snapshot{}, err
	}

	edgeMeta, nodeMeta, err := s.loadMeta()
	if err != nil {
		return graph.Snapshot{}, err
	}

	snap := graph.Snapshot{GeneratedAt: t}
	for id, a := range aggs {
		m, ok := edgeMeta[id]
		if !ok {
			continue
		}
		// Union edge endpoints into presence (covers idle-but-connected
		// nodes and external endpoints without presence rows).
		for _, nid := range []string{m.Src, m.Dst} {
			if _, ok := nodeIDs[nid]; !ok {
				nodeIDs[nid] = a.lastBucket
			}
		}
		w := a.w
		w.Seconds = int(metric.Seconds())
		w.ActiveEnd = a.lastActive
		if a.rttCount > 0 {
			w.RTTAvgUs = uint32(a.rttSum / a.rttCount)
		}
		e := graph.Edge{
			ID: id, Src: m.Src, Dst: m.Dst, DstPort: m.DstPort, Protocol: m.Protocol,
			Connections: w.Opens,
			ActiveConns: a.lastActive,
			BytesSent:   w.BytesSent,
			BytesRecv:   w.BytesRecv,
			Failures:    w.Failures,
			Resets:      w.Resets,
			Retransmits: w.Retransmits,
			LastRTTUs:   a.lastRTT,
			FirstSeen:   m.FirstSeen,
			LastSeen:    time.Unix(a.lastBucket, 0),
			Window:      &w,
		}
		if e.LastSeen.After(t) {
			e.LastSeen = t
		}
		snap.Edges = append(snap.Edges, e)
	}
	for id, lastEnd := range nodeIDs {
		n, ok := nodeMeta[id]
		if !ok {
			continue
		}
		last := time.Unix(lastEnd, 0)
		if last.After(t) {
			last = t
		}
		n.LastSeen = last
		// Listening state comes from this era's presence rows, never
		// from the node's latest metadata.
		n.ListenPorts = eraPorts[id]
		snap.Nodes = append(snap.Nodes, n)
	}
	sortSnapshot(&snap)
	return snap, nil
}

type edgeMetaRow struct {
	Src, Dst  string
	DstPort   uint16
	Protocol  string
	FirstSeen time.Time
	LastSeen  time.Time
}

func (s *Store) loadMeta() (map[string]edgeMetaRow, map[string]graph.Node, error) {
	edges := make(map[string]edgeMetaRow)
	rows, err := s.db.Query(`SELECT id, src, dst, dst_port, protocol, first_seen, last_seen FROM edges`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, src, dst, proto string
		var port int
		var first, last int64
		if err := rows.Scan(&id, &src, &dst, &port, &proto, &first, &last); err != nil {
			return nil, nil, err
		}
		edges[id] = edgeMetaRow{
			Src: src, Dst: dst, DstPort: uint16(port), Protocol: proto,
			FirstSeen: time.Unix(first, 0).UTC(), LastSeen: time.Unix(last, 0).UTC(),
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	nodes := make(map[string]graph.Node)
	nrows, err := s.db.Query(`
SELECT id, kind, label, exe, container_id, container_name, image,
       compose_project, compose_service, listen_ports, addrs, pids, first_seen, last_seen
FROM nodes`)
	if err != nil {
		return nil, nil, err
	}
	defer nrows.Close()
	for nrows.Next() {
		var n graph.Node
		var kind, ports, addrs, pids string
		var first, last int64
		if err := nrows.Scan(&n.ID, &kind, &n.Label, &n.Exe, &n.ContainerID,
			&n.ContainerName, &n.Image, &n.ComposeProject, &n.ComposeService,
			&ports, &addrs, &pids, &first, &last); err != nil {
			return nil, nil, err
		}
		n.Kind = graph.NodeKind(kind)
		_ = json.Unmarshal([]byte(ports), &n.ListenPorts)
		_ = json.Unmarshal([]byte(addrs), &n.Addrs)
		_ = json.Unmarshal([]byte(pids), &n.PIDs)
		n.FirstSeen = time.Unix(first, 0).UTC()
		n.LastSeen = time.Unix(last, 0).UTC()
		nodes[n.ID] = n
	}
	return edges, nodes, nrows.Err()
}

// TimelineBucket is one step of the activity timeline.
type TimelineBucket struct {
	Start    int64  `json:"start"` // unix seconds
	Opens    uint64 `json:"opens"`
	Closes   uint64 `json:"closes"`
	Failures uint64 `json:"failures"`
	Trouble  uint64 `json:"trouble"` // resets + retransmits
}

// Timeline aggregates activity between from and to into step-sized
// buckets, merging in-memory (unflushed and in-flight) buckets so the
// right edge of the timeline is current. A stored bucket overlapping the
// range is counted whole on the step containing its (clamped) start —
// sub-span distribution is not attempted, so timeline resolution equals
// the stored span.
func (s *Store) Timeline(from, to time.Time, step time.Duration) ([]TimelineBucket, error) {
	if step < s.fineSpan {
		step = s.fineSpan
	}
	stepS := int64(step.Seconds())
	fromU := from.Unix() / stepS * stepS
	toU := to.Unix()
	if toU < fromU {
		return nil, nil
	}

	out := make(map[int64]*TimelineBucket)
	fold := func(bucket int64, opens, closes, failures, trouble uint64) {
		start := bucket
		if start < fromU {
			start = fromU
		}
		start = start / stepS * stepS
		b, ok := out[start]
		if !ok {
			b = &TimelineBucket{Start: start}
			out[start] = b
		}
		b.Opens += opens
		b.Closes += closes
		b.Failures += failures
		b.Trouble += trouble
	}

	rows, err := s.db.Query(`
SELECT bucket, opens, closes, failures, resets + retrans
FROM edge_buckets
WHERE bucket + span > ? AND bucket <= ?`, fromU, toU)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucket int64
		var opens, closes, failures, trouble uint64
		if err := rows.Scan(&bucket, &opens, &closes, &failures, &trouble); err != nil {
			return nil, err
		}
		fold(bucket, opens, closes, failures, trouble)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	for _, m := range []map[bucketKey]*acc{s.buckets, s.flushing} {
		for k, a := range m {
			if k.start+int64(s.fineSpan.Seconds()) <= fromU || k.start > toU {
				continue
			}
			fold(k.start, a.opens, a.closes, a.failures, a.resets+a.retrans)
		}
	}
	s.mu.Unlock()

	series := make([]TimelineBucket, 0, (toU-fromU)/stepS+1)
	for start := fromU; start <= toU; start += stepS {
		if b, ok := out[start]; ok {
			series = append(series, *b)
		} else {
			series = append(series, TimelineBucket{Start: start})
		}
	}
	return series, nil
}

// WindowHealth returns recent per-edge health (DB buckets plus unflushed
// in-memory state) over the trailing window ending at now. Used to
// decorate the live snapshot.
func (s *Store) WindowHealth(now time.Time, window time.Duration) (map[string]graph.EdgeWindow, error) {
	if window <= 0 {
		window = DefaultMetricWindow
	}
	from := now.Add(-window).Unix()

	type sums struct {
		w        graph.EdgeWindow
		rttSum   uint64
		rttCount uint64
	}
	agg := make(map[string]*sums)
	get := func(id string) *sums {
		v, ok := agg[id]
		if !ok {
			v = &sums{}
			agg[id] = v
		}
		return v
	}

	rows, err := s.db.Query(`
SELECT edge_id, opens, closes, failures, resets, retrans, bytes_sent, bytes_recv,
       rtt_sum_us, rtt_count, rtt_max_us
FROM edge_buckets WHERE bucket + span > ?`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var opens, closes, failures, resets, retrans, bs, br, rttSum, rttCount uint64
		var rttMax uint32
		if err := rows.Scan(&id, &opens, &closes, &failures, &resets, &retrans,
			&bs, &br, &rttSum, &rttCount, &rttMax); err != nil {
			return nil, err
		}
		v := get(id)
		v.w.Opens += opens
		v.w.Closes += closes
		v.w.Failures += failures
		v.w.Resets += resets
		v.w.Retransmits += retrans
		v.w.BytesSent += bs
		v.w.BytesRecv += br
		v.rttSum += rttSum
		v.rttCount += rttCount
		if rttMax > v.w.RTTMaxUs {
			v.w.RTTMaxUs = rttMax
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	for _, m := range []map[bucketKey]*acc{s.buckets, s.flushing} {
		for k, a := range m {
			if k.start+int64(s.fineSpan.Seconds()) <= from {
				continue
			}
			v := get(k.edgeID)
			v.w.Opens += a.opens
			v.w.Closes += a.closes
			v.w.Failures += a.failures
			v.w.Resets += a.resets
			v.w.Retransmits += a.retrans
			v.w.BytesSent += a.bytesSent
			v.w.BytesRecv += a.bytesRecv
			v.rttSum += a.rttSumUs
			v.rttCount += a.rttCount
			if a.rttMaxUs > v.w.RTTMaxUs {
				v.w.RTTMaxUs = a.rttMaxUs
			}
		}
	}
	active := make(map[string]int64, len(s.active))
	for id, n := range s.active {
		active[id] = n
	}
	s.mu.Unlock()

	out := make(map[string]graph.EdgeWindow, len(agg))
	for id, v := range agg {
		if v.rttCount > 0 {
			v.w.RTTAvgUs = uint32(v.rttSum / v.rttCount)
		}
		v.w.Seconds = int(window.Seconds())
		v.w.ActiveEnd = active[id]
		out[id] = v.w
	}
	return out, nil
}

// Compact rolls fine buckets older than the fine retention into coarse
// buckets and drops coarse buckets past the coarse retention.
func (s *Store) Compact(now time.Time) error {
	fineCutoff := now.Add(-s.fineRetention).Unix()
	fineS := int64(s.fineSpan.Seconds())
	coarseS := int64(s.coarseSpan.Seconds())

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	// Edge buckets: aggregate in Go so active_end can take the value of
	// the last fine bucket in each coarse group.
	rows, err := tx.Query(`
SELECT edge_id, bucket, opens, closes, failures, resets, retrans,
       bytes_sent, bytes_recv, rtt_sum_us, rtt_count, rtt_max_us, active_end
FROM edge_buckets WHERE span = ? AND bucket < ? ORDER BY bucket`, fineS, fineCutoff)
	if err != nil {
		return err
	}
	type coarseAcc struct {
		acc
		activeEnd  int64
		lastBucket int64
	}
	coarse := make(map[bucketKey]*coarseAcc)
	for rows.Next() {
		var id string
		var bucket, activeEnd int64
		var a acc
		if err := rows.Scan(&id, &bucket, &a.opens, &a.closes, &a.failures, &a.resets,
			&a.retrans, &a.bytesSent, &a.bytesRecv, &a.rttSumUs, &a.rttCount,
			&a.rttMaxUs, &activeEnd); err != nil {
			rows.Close()
			return err
		}
		k := bucketKey{edgeID: id, start: bucket / coarseS * coarseS}
		c, ok := coarse[k]
		if !ok {
			c = &coarseAcc{}
			coarse[k] = c
		}
		c.opens += a.opens
		c.closes += a.closes
		c.failures += a.failures
		c.resets += a.resets
		c.retrans += a.retrans
		c.bytesSent += a.bytesSent
		c.bytesRecv += a.bytesRecv
		c.rttSumUs += a.rttSumUs
		c.rttCount += a.rttCount
		if a.rttMaxUs > c.rttMaxUs {
			c.rttMaxUs = a.rttMaxUs
		}
		if bucket >= c.lastBucket {
			c.lastBucket = bucket
			c.activeEnd = activeEnd
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for k, c := range coarse {
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
			k.edgeID, k.start, coarseS,
			c.opens, c.closes, c.failures, c.resets, c.retrans,
			c.bytesSent, c.bytesRecv, c.rttSumUs, c.rttCount, c.rttMaxUs, c.activeEnd,
		); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM edge_buckets WHERE span = ? AND bucket < ?`, fineS, fineCutoff); err != nil {
		return err
	}

	// Node presence: aggregated in Go so the per-era listen ports of the
	// latest listening fine row survive into the coarse row.
	type presAcc struct {
		listening  int
		ports      string
		lastBucket int64
	}
	prows, err := tx.Query(`
SELECT node_id, bucket, listening, listen_ports
FROM node_presence WHERE span = ? AND bucket < ? ORDER BY bucket`, fineS, fineCutoff)
	if err != nil {
		return err
	}
	pres := make(map[bucketKey]*presAcc)
	for prows.Next() {
		var id, ports string
		var bucket int64
		var listening int
		if err := prows.Scan(&id, &bucket, &listening, &ports); err != nil {
			prows.Close()
			return err
		}
		k := bucketKey{edgeID: id, start: bucket / coarseS * coarseS}
		p, ok := pres[k]
		if !ok {
			p = &presAcc{}
			pres[k] = p
		}
		if listening > p.listening {
			p.listening = listening
		}
		if listening > 0 && ports != "" && bucket >= p.lastBucket {
			p.ports = ports
			p.lastBucket = bucket
		}
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return err
	}
	for k, p := range pres {
		if _, err := tx.Exec(`
INSERT INTO node_presence (node_id, bucket, span, listening, listen_ports)
VALUES (?,?,?,?,?)
ON CONFLICT(node_id, bucket, span) DO UPDATE SET
  listening=MAX(listening, excluded.listening),
  listen_ports=CASE WHEN excluded.listening > 0 AND excluded.listen_ports != ''
                    THEN excluded.listen_ports ELSE listen_ports END`,
			k.edgeID, k.start, coarseS, p.listening, p.ports); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM node_presence WHERE span = ? AND bucket < ?`, fineS, fineCutoff); err != nil {
		return err
	}

	coarseCutoff := now.Add(-s.coarseRetention).Unix()
	if _, err := tx.Exec(`DELETE FROM edge_buckets WHERE bucket < ?`, coarseCutoff); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM node_presence WHERE bucket < ?`, coarseCutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// sortSnapshot applies the same deterministic ordering as
// graph.Store.Snapshot.
func sortSnapshot(s *graph.Snapshot) {
	slices.SortFunc(s.Nodes, func(a, b graph.Node) int {
		return strings.Compare(a.ID, b.ID)
	})
	slices.SortFunc(s.Edges, func(a, b graph.Edge) int {
		return strings.Compare(a.ID, b.ID)
	})
}
