package lens

import (
	"fmt"
	"slices"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/appview"
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/history"
)

// Store is the slice of the history store the Lens reads. Everything is
// recorded data; the Lens adds no collection of its own.
type Store interface {
	SnapshotAt(t time.Time, presence, metric time.Duration) (graph.Snapshot, error)
	EdgeBucketsRange(from, to time.Time) ([]history.EdgeBucketPoint, error)
	PresenceRange(from, to time.Time) ([]history.PresencePoint, error)
	NodeMetricsRange(from, to time.Time) ([]history.NodeMetricPoint, error)
	LifecycleRange(from, to time.Time, nodeID string) ([]history.LifeEvent, error)
}

// Run assembles the recorded evidence for (from, to] at service level
// and investigates it. service optionally focuses the investigation on
// one service's dependency component.
func Run(st Store, from, to time.Time, service string, opts appview.Options) (Report, error) {
	// One reconstruction whose presence window covers the whole
	// investigation range: every node and edge with any recorded
	// activity in the window appears, giving a complete raw→service
	// mapping (a node only alive mid-window is in neither endpoint's
	// default reconstruction).
	span := to.Sub(from) + history.DefaultPresenceWindow
	snap, err := st.SnapshotAt(to, span, span)
	if err != nil {
		return Report{}, fmt.Errorf("reconstructing window topology: %w", err)
	}
	view := appview.Project(snap, opts)
	members := view.MemberIndex()
	labels := view.LabelIndex()

	// The agent is the observer, not a subject: its own service — and
	// with it the API traffic of clients talking to it — is excluded
	// from the investigation.
	excluded := map[string]bool{}
	system := map[string]bool{}
	for _, n := range view.Nodes {
		if n.Category == appview.CategoryAtlas {
			excluded[n.ID] = true
		}
		if n.Category == appview.CategorySystem {
			system[n.ID] = true
		}
	}

	// Raw edge id → service edge identity, from the projection's
	// RawEdges lists.
	type svcEdge struct {
		id, src, dst string
		firstSeen    time.Time
	}
	rawToSvc := map[string]svcEdge{}
	for _, se := range view.Edges {
		for _, raw := range se.RawEdges {
			rawToSvc[raw] = svcEdge{id: se.ID, src: se.Src, dst: se.Dst, firstSeen: se.FirstSeen}
		}
	}

	in := Input{
		From: from, To: to, Labels: labels, Service: service,
		ExternalID: appview.ExternalID, SystemServices: system,
	}

	// Edge buckets, aggregated per service edge per bucket start.
	rows, err := st.EdgeBucketsRange(from, to)
	if err != nil {
		return Report{}, err
	}
	type ebKey struct {
		edge  string
		start int64
	}
	ebAgg := map[ebKey]*Bucket{}
	edgeMeta := map[string]svcEdge{}
	for _, r := range rows {
		se, ok := rawToSvc[r.EdgeID]
		if !ok {
			continue // e.g. intra-service raw edges the projection drops
		}
		if excluded[se.src] || excluded[se.dst] {
			continue
		}
		edgeMeta[se.id] = se
		k := ebKey{edge: se.id, start: r.Start}
		b, ok := ebAgg[k]
		if !ok {
			b = &Bucket{Start: r.Start, Span: r.Span}
			ebAgg[k] = b
		}
		if r.Span > b.Span {
			b.Span = r.Span
		}
		b.Opens += r.Opens
		b.Closes += r.Closes
		b.Failures += r.Failures
		b.Resets += r.Resets
		b.Retrans += r.Retrans
	}
	series := map[string]*EdgeSeries{}
	for k, b := range ebAgg {
		es, ok := series[k.edge]
		if !ok {
			m := edgeMeta[k.edge]
			es = &EdgeSeries{ID: m.id, Src: m.src, Dst: m.dst, FirstSeen: m.firstSeen}
			series[k.edge] = es
		}
		es.Buckets = append(es.Buckets, *b)
	}
	for _, es := range series {
		slices.SortFunc(es.Buckets, func(a, b Bucket) int {
			switch {
			case a.Start < b.Start:
				return -1
			case a.Start > b.Start:
				return 1
			}
			return 0
		})
		in.Edges = append(in.Edges, *es)
	}
	slices.SortFunc(in.Edges, func(a, b EdgeSeries) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	// Presence, aggregated per service: present when any member has a
	// row; listening when any member row listens.
	prows, err := st.PresenceRange(from, to)
	if err != nil {
		return Report{}, err
	}
	type pKey struct {
		svc   string
		start int64
	}
	pAgg := map[pKey]*PresenceBucket{}
	for _, r := range prows {
		svc, ok := members[r.NodeID]
		if !ok || excluded[svc] {
			continue
		}
		k := pKey{svc: svc, start: r.Start}
		b, ok := pAgg[k]
		if !ok {
			b = &PresenceBucket{Start: r.Start, Span: r.Span}
			pAgg[k] = b
		}
		if r.Span > b.Span {
			b.Span = r.Span
		}
		b.Listening = b.Listening || r.Listening
	}
	pres := map[string]*ServicePresence{}
	for k, b := range pAgg {
		sp, ok := pres[k.svc]
		if !ok {
			sp = &ServicePresence{ID: k.svc}
			pres[k.svc] = sp
		}
		sp.Buckets = append(sp.Buckets, *b)
	}
	for _, sp := range pres {
		slices.SortFunc(sp.Buckets, func(a, b PresenceBucket) int {
			switch {
			case a.Start < b.Start:
				return -1
			case a.Start > b.Start:
				return 1
			}
			return 0
		})
		in.Presence = append(in.Presence, *sp)
	}
	slices.SortFunc(in.Presence, func(a, b ServicePresence) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	// Lifecycle events, mapped onto the service graph.
	events, err := st.LifecycleRange(from, to, "")
	if err != nil {
		return Report{}, err
	}
	for _, ev := range events {
		svc, ok := members[ev.NodeID]
		if !ok || excluded[svc] {
			continue
		}
		in.Events = append(in.Events, LifeEvent{
			Service: svc, Kind: ev.Kind, PID: ev.PID, Detail: ev.Detail, Time: ev.Time,
		})
	}

	// Node metrics, aggregated per service per bucket (sums, like the
	// application view's member merge).
	mrows, err := st.NodeMetricsRange(from, to)
	if err != nil {
		return Report{}, err
	}
	mAgg := map[pKey]*MetricBucket{}
	for _, r := range mrows {
		svc, ok := members[r.NodeID]
		if !ok || excluded[svc] {
			continue
		}
		k := pKey{svc: svc, start: r.Start}
		b, ok := mAgg[k]
		if !ok {
			b = &MetricBucket{Start: r.Start, Span: r.Span}
			mAgg[k] = b
		}
		if r.Span > b.Span {
			b.Span = r.Span
		}
		b.OOMKills += r.OOMKills
		b.RSSMax += r.RSSMax
		b.MemLimit += r.MemLimit
		b.ThrottledUs += r.ThrottledUs
	}
	mets := map[string]*MetricSeries{}
	for k, b := range mAgg {
		ms, ok := mets[k.svc]
		if !ok {
			ms = &MetricSeries{ID: k.svc}
			mets[k.svc] = ms
		}
		ms.Buckets = append(ms.Buckets, *b)
	}
	for _, ms := range mets {
		slices.SortFunc(ms.Buckets, func(a, b MetricBucket) int {
			switch {
			case a.Start < b.Start:
				return -1
			case a.Start > b.Start:
				return 1
			}
			return 0
		})
		in.Metrics = append(in.Metrics, *ms)
	}
	slices.SortFunc(in.Metrics, func(a, b MetricSeries) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	return Investigate(in), nil
}
