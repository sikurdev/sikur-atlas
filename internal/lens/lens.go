// Package lens turns recorded history into a deterministic incident
// investigation: a chronological chain of findings (facts, each backed
// by recorded evidence), an origin named only when temporal and
// dependency evidence supports it, the observed blast radius, and
// recovery. There is no model, no scoring and no randomness — the rules
// are the fixed constants and functions in this file (rule set
// RuleSetID), and the same recorded inputs always produce the same
// report. Findings are facts; the origin and propagation entries are
// the only inferences, and they say which rule produced them.
package lens

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/collector"
)

// RuleSetID names the deterministic rule set; it changes when any rule
// or threshold changes, so a report is auditable against its docs.
const RuleSetID = "lens/v1"

// Rule thresholds. Documented in docs/architecture.md; changing any of
// these means a new RuleSetID.
const (
	// goneGap: a service that had listening presence and then produces
	// no presence rows for this long is gone (3 missed 30s listen scans;
	// presence is written at 10s flush granularity).
	goneGap = 90 * time.Second
	// trafficStopConfirm: an edge's silence must last this long (or to
	// the window end) before it counts as stopped rather than a pause.
	trafficStopConfirm = 90 * time.Second
	// trafficStopSteadyBuckets: the edge must have been active in at
	// least this many buckets inside the window before its silence can
	// count as a stop — a CLI-style burst edge falling silent is normal,
	// not an incident.
	trafficStopSteadyBuckets = 4
	// resetsSpikeFloor / retransSpikeFloor: minimum per-bucket counts
	// for a spike finding, matching the Compare floors.
	resetsSpikeFloor  = 1
	retransSpikeFloor = 3
	// rssPressurePct: RSS at or above this percentage of the memory
	// limit is memory pressure.
	rssPressurePct = 90
	// throttleFloor: cgroup CPU throttling per bucket above this is a
	// throttle finding.
	throttleFloor = 500 * time.Millisecond
	// pointEventSpan: lifecycle timestamps are stored at second
	// resolution; a point event occupies one second for ordering.
	pointEventSpan = time.Second
)

// Finding kinds. Every finding is a recorded fact.
const (
	// Terminal primaries: something stopped existing or was killed.
	KindOOM         = "oom"          // lifecycle: kernel OOM killer chose a process
	KindOOMCgroup   = "oom-cgroup"   // cgroup memory.events oom_kill delta
	KindCrash       = "crash"        // lifecycle: fatal-signal death
	KindExit        = "exit"         // lifecycle: process exit
	KindServiceGone = "service-gone" // presence ceased after listening
	KindListenLost  = "listen-lost"  // still present, stopped listening
	// Contributing pressure: can anchor an origin only when no terminal
	// primary exists.
	KindRSSPressure = "rss-pressure"
	KindThrottle    = "throttle"
	// Transitions: health of a dependency edge changed.
	KindFailuresStart = "failures-start"
	KindResetsSpike   = "resets-spike"
	KindRetransSpike  = "retrans-spike"
	KindTrafficStop   = "traffic-stop"
	// Neutral lifecycle: recorded, never a primary.
	KindExitClean = "exit-clean" // orderly exit(0): normal lifecycle
	// Recovery.
	KindFailuresEnd   = "failures-end"
	KindTrafficResume = "traffic-resume"
	KindServiceBack   = "service-back"
	KindExec          = "exec" // lifecycle: a process started (restart evidence)
	// Chronic context: degradation already present at window start.
	KindChronicFailure = "chronic-failure"
)

func isTerminal(kind string) bool {
	switch kind {
	case KindOOM, KindOOMCgroup, KindCrash, KindExit, KindServiceGone, KindListenLost:
		return true
	}
	return false
}

func isContributing(kind string) bool {
	return kind == KindRSSPressure || kind == KindThrottle
}

func isTransition(kind string) bool {
	switch kind {
	case KindFailuresStart, KindResetsSpike, KindRetransSpike, KindTrafficStop:
		return true
	}
	return false
}

// Evidence is one recorded row backing a finding: where it came from,
// when, and the recorded numbers.
type Evidence struct {
	Source   string `json:"source"` // edge-bucket | lifecycle-event | metric-bucket | presence
	Time     int64  `json:"time"`   // unix seconds (bucket start or event time)
	SpanSecs int64  `json:"spanSecs,omitempty"`
	Detail   string `json:"detail"` // the recorded values, verbatim
}

// Finding is one fact on the incident timeline. Its time is an interval
// [Time, End): bucket-derived findings span their bucket, lifecycle
// events span one second (storage resolution). Cross-finding order is
// only claimed when intervals do not overlap.
type Finding struct {
	Kind     string     `json:"kind"`
	Time     time.Time  `json:"time"`
	End      time.Time  `json:"end"`
	Service  string     `json:"service"`
	Label    string     `json:"label"`
	Edge     string     `json:"edge,omitempty"`
	EdgeSrc  string     `json:"edgeSrc,omitempty"`
	EdgeDst  string     `json:"edgeDst,omitempty"`
	Detail   string     `json:"detail"`
	Evidence []Evidence `json:"evidence"`
}

// precedes reports a strict temporal order: a ended at or before b
// began. Overlapping intervals have no knowable order (documented: the
// ordering of events within one bucket is not recorded).
func precedes(a, b Finding) bool {
	return !a.End.After(b.Time)
}

// Origin is the one inference the Lens makes about cause: which
// service's primary event anchors the incident. It exists only when the
// origin rule's temporal and dependency conditions all hold.
type Origin struct {
	Service     string    `json:"service"`
	Label       string    `json:"label"`
	Time        time.Time `json:"time"`
	FindingIdx  int       `json:"findingIndex"`
	Rule        string    `json:"rule"`
	Inference   bool      `json:"inference"` // always true, stated explicitly
	Explanation string    `json:"explanation"`
}

// Propagation links an effect finding to the origin it is consistent
// with — an inference, made only when an origin was resolved.
type Propagation struct {
	CauseIdx    int    `json:"causeIndex"`
	EffectIdx   int    `json:"effectIndex"`
	Inference   bool   `json:"inference"` // always true
	Explanation string `json:"explanation"`
}

// BlastRadius is the observed impact: services and edges with
// non-chronic findings in the window. Recorded facts, not reachability
// speculation.
type BlastRadius struct {
	Services []string `json:"services"`
	Edges    []string `json:"edges"`
}

// Recovery pairs a degradation finding with the recorded evidence of
// its recovery, when the window contains any.
type Recovery struct {
	Subject     string     `json:"subject"` // service id or edge id
	DegradedIdx int        `json:"degradedIndex"`
	RecoveredAt *time.Time `json:"recoveredAt"`   // nil = not within window
	RecoveryIdx int        `json:"recoveryIndex"` // -1 = none
	Detail      string     `json:"detail"`
}

// Report is one investigation over one recorded window.
type Report struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Service string    `json:"service,omitempty"` // focus filter, when given
	RuleSet string    `json:"ruleSet"`

	// Findings is the chronological chain of facts.
	Findings []Finding `json:"findings"`
	// Chronic lists degradation that predates the window: context, and
	// deliberately excluded from origin logic.
	Chronic []Finding `json:"chronic"`

	Origin       *Origin       `json:"origin"`
	Unresolved   string        `json:"unresolved,omitempty"`
	Propagations []Propagation `json:"propagations"`
	BlastRadius  BlastRadius   `json:"blastRadius"`
	Recovery     []Recovery    `json:"recovery"`

	// Labels maps every service id mentioned to its display label.
	Labels map[string]string `json:"labels"`
}

// ---- input (service-level, assembled by Build) ----

// Bucket is one recorded health bucket of a service edge.
type Bucket struct {
	Start    int64
	Span     int64
	Opens    uint64
	Closes   uint64
	Failures uint64
	Resets   uint64
	Retrans  uint64
}

// EdgeSeries is one service edge's recorded bucket series, sorted by
// Start with no duplicate starts.
type EdgeSeries struct {
	ID, Src, Dst string
	// FirstSeen: when this edge was first ever recorded (for the
	// born-failing rule).
	FirstSeen time.Time
	Buckets   []Bucket
}

// PresenceBucket is one recorded presence bucket of a service.
type PresenceBucket struct {
	Start     int64
	Span      int64
	Listening bool
}

// ServicePresence is one service's presence rows, sorted by Start.
type ServicePresence struct {
	ID      string
	Buckets []PresenceBucket
}

// LifeEvent is one recorded lifecycle event mapped to its service.
type LifeEvent struct {
	Service string
	Kind    string // exec | exit | crash | oom (collector kinds)
	PID     uint32
	Detail  string
	Time    time.Time
}

// MetricBucket is one recorded resource bucket of a service (members
// aggregated: deltas and sizes summed).
type MetricBucket struct {
	Start       int64
	Span        int64
	OOMKills    uint64
	RSSMax      uint64
	MemLimit    uint64
	ThrottledUs uint64
}

// MetricSeries is one service's resource buckets, sorted by Start.
type MetricSeries struct {
	ID      string
	Buckets []MetricBucket
}

// Input is everything Investigate reads: recorded, service-level, and
// already restricted to the window (plus edge FirstSeen metadata).
type Input struct {
	From, To time.Time
	Edges    []EdgeSeries
	Presence []ServicePresence
	Events   []LifeEvent
	Metrics  []MetricSeries
	Labels   map[string]string
	// Service restricts the investigation to this service's dependency
	// component (its transitive callers and dependencies); empty = all.
	Service string
	// ExternalID names the aggregate external service. Transitions on
	// edges toward it are recorded facts but neither gate nor support
	// the origin: what happens beyond the host can be neither explained
	// nor refuted by local evidence. Dependency reachability never
	// traverses through it (its members are unrelated endpoints).
	ExternalID string
}

// Investigate runs the rule set over one window of recorded evidence.
func Investigate(in Input) Report {
	rep := Report{
		From:    in.From,
		To:      in.To,
		Service: in.Service,
		RuleSet: RuleSetID,
		Labels:  map[string]string{},
	}

	keep := componentFilter(in)
	label := func(id string) string {
		if l, ok := in.Labels[id]; ok {
			return l
		}
		return id
	}
	note := func(ids ...string) {
		for _, id := range ids {
			if id != "" {
				rep.Labels[id] = label(id)
			}
		}
	}

	var findings, chronic []Finding
	add := func(f Finding) {
		f.Label = label(f.Service)
		note(f.Service, f.EdgeSrc, f.EdgeDst)
		findings = append(findings, f)
	}

	for _, es := range in.Edges {
		if !keep[es.Src] && !keep[es.Dst] {
			continue
		}
		edgeFindings, edgeChronic := edgeRules(es, in.From, in.To)
		for _, f := range edgeFindings {
			add(f)
		}
		for _, f := range edgeChronic {
			f.Label = label(f.Service)
			note(f.Service, f.EdgeSrc, f.EdgeDst)
			chronic = append(chronic, f)
		}
	}
	for _, sp := range in.Presence {
		if !keep[sp.ID] {
			continue
		}
		for _, f := range presenceRules(sp, in.To) {
			add(f)
		}
	}
	oomBuckets := map[string][]int64{} // service -> lifecycle-oom seconds (for dedup)
	for _, ev := range in.Events {
		if !keep[ev.Service] {
			continue
		}
		f, ok := lifecycleFinding(ev)
		if !ok {
			continue
		}
		if ev.Kind == "oom" {
			oomBuckets[ev.Service] = append(oomBuckets[ev.Service], ev.Time.Unix())
		}
		add(f)
	}
	for _, ms := range in.Metrics {
		if !keep[ms.ID] {
			continue
		}
		for _, f := range metricRules(ms, oomBuckets[ms.ID]) {
			add(f)
		}
	}

	sortFindings(findings)
	sortFindings(chronic)
	rep.Findings = findings
	rep.Chronic = chronic

	resolveOrigin(&rep, in, label)
	rep.BlastRadius = blastRadius(findings)
	rep.Recovery = matchRecovery(findings)
	return rep
}

// componentFilter returns the set of services to investigate: everything,
// or — when a focus service is given — that service plus its transitive
// callers and dependencies over the window's recorded edges.
func componentFilter(in Input) map[string]bool {
	keep := map[string]bool{}
	all := in.Service == ""
	for _, es := range in.Edges {
		if all {
			keep[es.Src], keep[es.Dst] = true, true
		}
	}
	if all {
		for _, sp := range in.Presence {
			keep[sp.ID] = true
		}
		for _, ev := range in.Events {
			keep[ev.Service] = true
		}
		for _, ms := range in.Metrics {
			keep[ms.ID] = true
		}
		return keep
	}
	out := map[string][]string{}
	rev := map[string][]string{}
	for _, es := range in.Edges {
		out[es.Src] = append(out[es.Src], es.Dst)
		rev[es.Dst] = append(rev[es.Dst], es.Src)
	}
	for _, adj := range []map[string][]string{out, rev} {
		frontier := []string{in.Service}
		seen := map[string]bool{in.Service: true}
		for len(frontier) > 0 {
			cur := frontier[0]
			frontier = frontier[1:]
			keep[cur] = true
			for _, next := range adj[cur] {
				if !seen[next] {
					seen[next] = true
					// The external aggregate joins the component but is
					// never traversed through: its members are unrelated
					// endpoints, not one service.
					if next == in.ExternalID {
						keep[next] = true
						continue
					}
					frontier = append(frontier, next)
				}
			}
		}
	}
	return keep
}

// edgeRules walks one edge's bucket series and emits health transitions.
func edgeRules(es EdgeSeries, from, to time.Time) (findings, chronic []Finding) {
	if len(es.Buckets) == 0 {
		return nil, nil
	}
	b0 := es.Buckets[0]
	failing := false
	if b0.Failures > 0 {
		if es.FirstSeen.Unix() >= from.Unix() {
			// Born failing inside the window: a real transition.
			findings = append(findings, edgeFinding(KindFailuresStart, es, b0,
				fmt.Sprintf("failed connects from the edge's first recorded bucket (%d failures); the edge first appeared inside the window", b0.Failures)))
		} else {
			chronic = append(chronic, edgeFinding(KindChronicFailure, es, b0,
				fmt.Sprintf("already failing at window start (%d failures in the first bucket); pre-existing degradation, excluded from origin analysis", b0.Failures)))
			// Chronic edges are context: no further rules, so their
			// steady failing/recovering noise cannot masquerade as this
			// incident's transitions.
			return findings, chronic
		}
		failing = true
	}

	lastResets, lastRetrans := b0.Resets, b0.Retrans
	resetsSpiked := b0.Resets >= resetsSpikeFloor
	retransSpiked := b0.Retrans >= retransSpikeFloor

	// Traffic-stop bookkeeping. Silence is usually a gap in bucket rows
	// (an idle edge writes nothing), but an edge with standing
	// connections keeps writing empty presence rows — both shapes count.
	need := int64(trafficStopConfirm.Seconds())
	var lastActive *Bucket
	activeBuckets := 0
	stopped := false
	trafficStop := func(silenceLen int64) Finding {
		silenceStart := lastActive.Start + lastActive.Span
		return Finding{
			Kind:    KindTrafficStop,
			Time:    time.Unix(silenceStart, 0).UTC(),
			End:     time.Unix(silenceStart+lastActive.Span, 0).UTC(),
			Service: es.Src,
			Edge:    es.ID,
			EdgeSrc: es.Src,
			EdgeDst: es.Dst,
			Detail: fmt.Sprintf("traffic ceased: no opens or closes for %ds after steady activity (%d opens in the last active bucket)",
				silenceLen, lastActive.Opens),
			Evidence: []Evidence{bucketEvidence(*lastActive)},
		}
	}

	for i := 0; i < len(es.Buckets); i++ {
		b := es.Buckets[i]

		if i > 0 {
			prev := es.Buckets[i-1]
			if !failing && b.Failures > 0 {
				failing = true
				f := edgeFinding(KindFailuresStart, es, b,
					fmt.Sprintf("failed connects appeared: %d in this bucket, none in the previous one", b.Failures))
				f.Evidence = append(f.Evidence, bucketEvidence(prev))
				findings = append(findings, f)
			}
			if failing && b.Failures == 0 && b.Opens > 0 {
				failing = false
				findings = append(findings, edgeFinding(KindFailuresEnd, es, b,
					fmt.Sprintf("failures ceased with traffic flowing again (%d opens, 0 failures)", b.Opens)))
			}
			if !resetsSpiked && b.Resets >= resetsSpikeFloor && lastResets == 0 {
				resetsSpiked = true
				findings = append(findings, edgeFinding(KindResetsSpike, es, b,
					fmt.Sprintf("connection resets appeared: %d RSTs received in this bucket", b.Resets)))
			}
			if !retransSpiked && b.Retrans >= retransSpikeFloor && lastRetrans < retransSpikeFloor {
				retransSpiked = true
				findings = append(findings, edgeFinding(KindRetransSpike, es, b,
					fmt.Sprintf("retransmissions spiked: %d segments in this bucket", b.Retrans)))
			}
			lastResets, lastRetrans = b.Resets, b.Retrans
		}

		if b.Opens > 0 || b.Closes > 0 {
			if lastActive != nil && !stopped && activeBuckets >= trafficStopSteadyBuckets {
				// The silence was a gap in the rows.
				if gap := b.Start - (lastActive.Start + lastActive.Span); gap >= need {
					findings = append(findings, trafficStop(gap))
					stopped = true
				}
			}
			if stopped {
				stopped = false
				findings = append(findings, edgeFinding(KindTrafficResume, es, b,
					fmt.Sprintf("traffic resumed: %d opens after the silence", b.Opens)))
			}
			c := b
			lastActive = &c
			activeBuckets++
			continue
		}

		// An explicit empty bucket: confirm the silence forward before
		// claiming a stop.
		if !stopped && lastActive != nil && activeBuckets >= trafficStopSteadyBuckets {
			if confirmed, gap := confirmSilence(es.Buckets[i+1:], lastActive.Start+lastActive.Span, to); confirmed {
				f := trafficStop(gap)
				f.Evidence = append(f.Evidence, bucketEvidence(b))
				findings = append(findings, f)
				stopped = true
			}
		}
	}

	// Tail silence: the series ends (in rows) before the window does.
	if !stopped && lastActive != nil && activeBuckets >= trafficStopSteadyBuckets {
		if gap := to.Unix() - (lastActive.Start + lastActive.Span); gap >= need {
			findings = append(findings, trafficStop(gap))
		}
	}
	return findings, chronic
}

// confirmSilence checks that a silence starting at silenceStart lasts at
// least trafficStopConfirm before the next active bucket (or the window
// end). Returns the silence length in seconds.
func confirmSilence(rest []Bucket, silenceStart int64, to time.Time) (bool, int64) {
	need := int64(trafficStopConfirm.Seconds())
	for _, b := range rest {
		if b.Opens > 0 || b.Closes > 0 {
			gap := b.Start - silenceStart
			return gap >= need, gap
		}
	}
	gap := to.Unix() - silenceStart
	return gap >= need, gap
}

func edgeFinding(kind string, es EdgeSeries, b Bucket, detail string) Finding {
	return Finding{
		Kind:     kind,
		Time:     time.Unix(b.Start, 0).UTC(),
		End:      time.Unix(b.Start+b.Span, 0).UTC(),
		Service:  edgeSubject(kind, es),
		Edge:     es.ID,
		EdgeSrc:  es.Src,
		EdgeDst:  es.Dst,
		Detail:   detail,
		Evidence: []Evidence{bucketEvidence(b)},
	}
}

// edgeSubject: failure-shaped findings describe the dependency (dst)
// being unreachable, but the observing service is the src; the src is
// the finding's subject (the service experiencing the problem).
func edgeSubject(_ string, es EdgeSeries) string { return es.Src }

func bucketEvidence(b Bucket) Evidence {
	return Evidence{
		Source:   "edge-bucket",
		Time:     b.Start,
		SpanSecs: b.Span,
		Detail: fmt.Sprintf("opens=%d closes=%d failures=%d resets=%d retrans=%d",
			b.Opens, b.Closes, b.Failures, b.Resets, b.Retrans),
	}
}

// presenceRules emits service-gone / service-back / listen-lost from
// one service's presence rows.
func presenceRules(sp ServicePresence, to time.Time) []Finding {
	if len(sp.Buckets) == 0 {
		return nil
	}
	var out []Finding
	gap := int64(goneGap.Seconds())
	everListening := false
	wasListening := false
	gone := false

	for i, b := range sp.Buckets {
		if b.Listening {
			everListening = true
		}
		if i > 0 {
			prevEnd := sp.Buckets[i-1].Start + sp.Buckets[i-1].Span
			if everListening && b.Start-prevEnd >= gap {
				out = append(out, presenceGone(sp, sp.Buckets[i-1], b.Start-prevEnd))
				out = append(out, Finding{
					Kind:    KindServiceBack,
					Time:    time.Unix(b.Start, 0).UTC(),
					End:     time.Unix(b.Start+b.Span, 0).UTC(),
					Service: sp.ID,
					Detail:  "presence resumed: the service is being observed again",
					Evidence: []Evidence{{
						Source: "presence", Time: b.Start, SpanSecs: b.Span,
						Detail: fmt.Sprintf("presence row, listening=%v", b.Listening),
					}},
				})
				gone = false
			}
			if wasListening && !b.Listening && !gone {
				out = append(out, Finding{
					Kind:    KindListenLost,
					Time:    time.Unix(b.Start, 0).UTC(),
					End:     time.Unix(b.Start+b.Span, 0).UTC(),
					Service: sp.ID,
					Detail:  "stopped listening: the service is still observed but its listening ports are gone",
					Evidence: []Evidence{{
						Source: "presence", Time: b.Start, SpanSecs: b.Span,
						Detail: "presence row, listening=false (previous row listening=true)",
					}},
				})
			}
		}
		wasListening = b.Listening
	}

	last := sp.Buckets[len(sp.Buckets)-1]
	lastEnd := last.Start + last.Span
	if everListening && to.Unix()-lastEnd >= gap {
		out = append(out, presenceGone(sp, last, to.Unix()-lastEnd))
	}
	return out
}

func presenceGone(sp ServicePresence, last PresenceBucket, gapSecs int64) Finding {
	end := last.Start + last.Span
	return Finding{
		Kind: KindServiceGone,
		// The disappearance happened somewhere after the last recorded
		// presence; the interval is that bucket's end plus one span of
		// flush uncertainty.
		Time:    time.Unix(end, 0).UTC(),
		End:     time.Unix(end+last.Span, 0).UTC(),
		Service: sp.ID,
		Detail:  fmt.Sprintf("presence ceased: last observed at %s, then nothing for %ds", time.Unix(end, 0).UTC().Format("15:04:05"), gapSecs),
		Evidence: []Evidence{{
			Source: "presence", Time: last.Start, SpanSecs: last.Span,
			Detail: fmt.Sprintf("last presence row, listening=%v; no rows for the following %ds", last.Listening, gapSecs),
		}},
	}
}

// lifecycleFinding maps one recorded lifecycle event to a finding.
func lifecycleFinding(ev LifeEvent) (Finding, bool) {
	var kind, detail string
	switch ev.Kind {
	case "oom":
		kind, detail = KindOOM, fmt.Sprintf("OOM-killed: %s", ev.Detail)
	case "crash":
		kind, detail = KindCrash, fmt.Sprintf("crashed: %s", ev.Detail)
	case "exit":
		if ev.Detail == collector.DetailExitClean {
			// exit(0) is normal lifecycle, recorded but never a primary:
			// every short-lived client would otherwise read as an incident.
			kind, detail = KindExitClean, "process exited cleanly"
			break
		}
		kind, detail = KindExit, fmt.Sprintf("process exited: %s", ev.Detail)
	case "exec":
		kind, detail = KindExec, fmt.Sprintf("process started: %s", ev.Detail)
	default:
		return Finding{}, false
	}
	return Finding{
		Kind:    kind,
		Time:    ev.Time.UTC(),
		End:     ev.Time.Add(pointEventSpan).UTC(),
		Service: ev.Service,
		Detail:  detail,
		Evidence: []Evidence{{
			Source: "lifecycle-event", Time: ev.Time.Unix(),
			Detail: fmt.Sprintf("kind=%s pid=%d %s", ev.Kind, ev.PID, ev.Detail),
		}},
	}, true
}

// metricRules emits oom-cgroup, rss-pressure and throttle findings from
// one service's resource buckets.
func metricRules(ms MetricSeries, lifecycleOOMs []int64) []Finding {
	var out []Finding
	pressured := false
	throttled := false
	for _, b := range ms.Buckets {
		if b.OOMKills > 0 && !oomAlreadyRecorded(lifecycleOOMs, b) {
			out = append(out, Finding{
				Kind:     KindOOMCgroup,
				Time:     time.Unix(b.Start, 0).UTC(),
				End:      time.Unix(b.Start+b.Span, 0).UTC(),
				Service:  ms.ID,
				Detail:   fmt.Sprintf("cgroup recorded %d OOM kill(s) (memory.events oom_kill)", b.OOMKills),
				Evidence: []Evidence{metricEvidence(b)},
			})
		}
		if b.MemLimit > 0 {
			pct := b.RSSMax * 100 / b.MemLimit
			if pct >= rssPressurePct && !pressured {
				pressured = true
				out = append(out, Finding{
					Kind:     KindRSSPressure,
					Time:     time.Unix(b.Start, 0).UTC(),
					End:      time.Unix(b.Start+b.Span, 0).UTC(),
					Service:  ms.ID,
					Detail:   fmt.Sprintf("memory pressure: RSS reached %d%% of the %d MiB limit", pct, b.MemLimit/(1024*1024)),
					Evidence: []Evidence{metricEvidence(b)},
				})
			} else if pct < rssPressurePct {
				pressured = false
			}
		}
		if b.ThrottledUs >= uint64(throttleFloor.Microseconds()) {
			if !throttled {
				throttled = true
				out = append(out, Finding{
					Kind:     KindThrottle,
					Time:     time.Unix(b.Start, 0).UTC(),
					End:      time.Unix(b.Start+b.Span, 0).UTC(),
					Service:  ms.ID,
					Detail:   fmt.Sprintf("CPU throttled: %dms of cgroup throttling in this bucket", b.ThrottledUs/1000),
					Evidence: []Evidence{metricEvidence(b)},
				})
			}
		} else {
			throttled = false
		}
	}
	return out
}

// oomAlreadyRecorded suppresses the cgroup counter when the lifecycle
// event for the same kill is present (same service, same bucket): one
// kill, one finding.
func oomAlreadyRecorded(lifecycleOOMs []int64, b MetricBucket) bool {
	for _, ts := range lifecycleOOMs {
		if ts >= b.Start-b.Span && ts < b.Start+2*b.Span {
			return true
		}
	}
	return false
}

func metricEvidence(b MetricBucket) Evidence {
	return Evidence{
		Source:   "metric-bucket",
		Time:     b.Start,
		SpanSecs: b.Span,
		Detail: fmt.Sprintf("oomKills=%d rssMax=%d memLimit=%d throttledUs=%d",
			b.OOMKills, b.RSSMax, b.MemLimit, b.ThrottledUs),
	}
}

// sortFindings orders chronologically, with a full deterministic
// tiebreak so equal inputs always yield byte-identical reports.
func sortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		if !a.Time.Equal(b.Time) {
			if a.Time.Before(b.Time) {
				return -1
			}
			return 1
		}
		if !a.End.Equal(b.End) {
			if a.End.Before(b.End) {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.Service, b.Service); c != 0 {
			return c
		}
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Edge, b.Edge)
	})
}

// resolveOrigin applies the origin rule (see RuleSetID docs): the
// earliest primary finding anchors the incident only when every other
// primary strictly follows it or is dependency-explained by it, and
// every transition neither precedes it nor points at an unrelated
// service.
func resolveOrigin(rep *Report, in Input, label func(string) string) {
	findings := rep.Findings
	var candidates []int
	for i, f := range findings {
		if isTerminal(f.Kind) {
			candidates = append(candidates, i)
		}
	}
	anchoredBy := "a terminal event (kill, crash, exit or disappearance)"
	if len(candidates) == 0 {
		for i, f := range findings {
			if isContributing(f.Kind) {
				candidates = append(candidates, i)
			}
		}
		anchoredBy = "a resource-pressure signal (no terminal event in the window)"
	}

	var transitions []int
	for i, f := range findings {
		if isTransition(f.Kind) {
			transitions = append(transitions, i)
		}
	}

	if len(candidates) == 0 {
		if len(transitions) > 0 {
			rep.Unresolved = "failures were recorded, but no primary event (lifecycle or resource pressure) exists in this window to anchor them; the cause may predate the window or be outside the host"
		}
		return
	}

	c0 := candidates[0]
	origin := findings[c0]

	deps := dependencyIndex(in.Edges, in.ExternalID)

	// Every other candidate must strictly follow the earliest one, and
	// candidates on other services must additionally be dependency-
	// explained (their service transitively depends on the origin).
	for _, ci := range candidates[1:] {
		f := findings[ci]
		if f.Service == origin.Service {
			continue
		}
		if !precedes(origin, f) {
			rep.Unresolved = fmt.Sprintf(
				"primary events on %s and %s fall inside the same recorded interval; their order is not knowable at this resolution",
				label(origin.Service), label(f.Service))
			return
		}
		if !deps.dependsOn(f.Service, origin.Service) {
			rep.Unresolved = fmt.Sprintf(
				"independent primary event on %s, which does not depend on %s; two unrelated incidents (or a shared external cause) cannot be reduced to one origin",
				label(f.Service), label(origin.Service))
			return
		}
	}

	var props []Propagation
	for _, ti := range transitions {
		f := findings[ti]
		if f.EdgeDst == in.ExternalID && in.ExternalID != "" {
			// A transition toward the external aggregate is a recorded
			// fact, but local evidence cannot tie it to (or against) any
			// local origin: it neither vetoes nor supports.
			continue
		}
		if precedes(f, origin) {
			rep.Unresolved = fmt.Sprintf(
				"%s on %s begins before the earliest primary event (%s on %s); the recorded evidence contradicts that candidate",
				f.Kind, f.Edge, origin.Kind, label(origin.Service))
			return
		}
		target := f.EdgeDst
		if target != origin.Service && !deps.dependsOn(target, origin.Service) {
			rep.Unresolved = fmt.Sprintf(
				"%s points at %s, which has no recorded dependency path to %s; the impact is not explained by that candidate",
				f.Kind, label(target), label(origin.Service))
			return
		}
		props = append(props, Propagation{
			CauseIdx:  c0,
			EffectIdx: ti,
			Inference: true,
			Explanation: fmt.Sprintf("%s → %s carries %s at/after the %s of %s, and %s is (or depends on) the origin — consistent with propagation",
				label(f.EdgeSrc), label(f.EdgeDst), f.Kind, origin.Kind, label(origin.Service), label(target)),
		})
	}
	// Later same-window primaries on dependent services are cascading
	// effects.
	for _, ci := range candidates[1:] {
		f := findings[ci]
		if f.Service != origin.Service {
			props = append(props, Propagation{
				CauseIdx:  c0,
				EffectIdx: ci,
				Inference: true,
				Explanation: fmt.Sprintf("%s on %s strictly follows the origin and %s depends on it — consistent with a cascade",
					f.Kind, label(f.Service), label(f.Service)),
			})
		}
	}

	rep.Origin = &Origin{
		Service:    origin.Service,
		Label:      label(origin.Service),
		Time:       origin.Time,
		FindingIdx: c0,
		Rule:       "earliest-primary-with-dependency-support",
		Inference:  true,
		Explanation: fmt.Sprintf(
			"%s is the earliest primary event, anchored by %s; every other primary strictly follows it on a dependent service, and every recorded transition points (directly or transitively) at %s",
			origin.Kind, anchoredBy, label(origin.Service)),
	}
	rep.Propagations = props
}

// depIndex answers transitive dependency questions over the window's
// recorded service edges (src depends on dst).
type depIndex struct {
	out      map[string][]string
	external string
}

func dependencyIndex(edges []EdgeSeries, externalID string) depIndex {
	out := map[string][]string{}
	for _, e := range edges {
		out[e.Src] = append(out[e.Src], e.Dst)
	}
	return depIndex{out: out, external: externalID}
}

// dependsOn reports whether from transitively depends on to.
func (d depIndex) dependsOn(from, to string) bool {
	if from == to {
		return true
	}
	seen := map[string]bool{from: true}
	frontier := []string{from}
	for len(frontier) > 0 {
		cur := frontier[0]
		frontier = frontier[1:]
		for _, next := range d.out[cur] {
			if next == to {
				return true
			}
			// Never a path *through* the external aggregate: its members
			// are unrelated endpoints.
			if !seen[next] && next != d.external {
				seen[next] = true
				frontier = append(frontier, next)
			}
		}
	}
	return false
}

// blastRadius lists the observed impact: subjects of every non-recovery
// finding.
func blastRadius(findings []Finding) BlastRadius {
	svc := map[string]bool{}
	edges := map[string]bool{}
	for _, f := range findings {
		switch f.Kind {
		case KindFailuresEnd, KindTrafficResume, KindServiceBack, KindExec, KindExitClean:
			continue
		}
		svc[f.Service] = true
		if f.Edge != "" {
			edges[f.Edge] = true
		}
	}
	br := BlastRadius{}
	for s := range svc {
		br.Services = append(br.Services, s)
	}
	for e := range edges {
		br.Edges = append(br.Edges, e)
	}
	slices.Sort(br.Services)
	slices.Sort(br.Edges)
	return br
}

// matchRecovery pairs each degradation with its recorded recovery.
func matchRecovery(findings []Finding) []Recovery {
	var out []Recovery
	recoveredEdge := func(edge string, after time.Time, kinds ...string) int {
		for i, f := range findings {
			if f.Edge == edge && slices.Contains(kinds, f.Kind) && !f.Time.Before(after) {
				return i
			}
		}
		return -1
	}
	recoveredService := func(svc string, after time.Time, kinds ...string) int {
		for i, f := range findings {
			if f.Service == svc && f.Edge == "" && slices.Contains(kinds, f.Kind) && !f.Time.Before(after) {
				return i
			}
		}
		return -1
	}

	for i, f := range findings {
		var idx int
		var subject, detail string
		switch f.Kind {
		case KindFailuresStart:
			subject = f.Edge
			idx = recoveredEdge(f.Edge, f.Time, KindFailuresEnd)
			detail = "failures ceased with traffic flowing"
		case KindTrafficStop:
			subject = f.Edge
			idx = recoveredEdge(f.Edge, f.Time, KindTrafficResume)
			detail = "traffic resumed"
		case KindServiceGone:
			subject = f.Service
			idx = recoveredService(f.Service, f.Time, KindServiceBack)
			detail = "presence resumed"
		case KindOOM, KindOOMCgroup, KindCrash, KindExit:
			subject = f.Service
			idx = recoveredService(f.Service, f.End, KindExec)
			detail = "a process started again (restart)"
		default:
			continue
		}
		r := Recovery{Subject: subject, DegradedIdx: i, RecoveryIdx: idx}
		if idx >= 0 {
			t := findings[idx].Time
			r.RecoveredAt = &t
			r.Detail = detail
		} else {
			r.Detail = "no recovery recorded within the window"
		}
		out = append(out, r)
	}
	return out
}
