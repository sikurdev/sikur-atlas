package lens

import (
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func at(secs int64) time.Time { return t0.Add(time.Duration(secs) * time.Second) }

// buckets10 builds a 10s-span series from per-bucket counters starting
// at t0+startOff.
type bspec struct {
	off      int64
	opens    uint64
	failures uint64
	resets   uint64
	retrans  uint64
}

func mkBuckets(specs []bspec) []Bucket {
	out := make([]Bucket, 0, len(specs))
	for _, s := range specs {
		out = append(out, Bucket{
			Start: t0.Unix() + s.off, Span: 10,
			Opens: s.opens, Closes: s.opens, Failures: s.failures,
			Resets: s.resets, Retrans: s.retrans,
		})
	}
	return out
}

// steady returns n active buckets (opens>0, clean) starting at off.
func steady(off int64, n int) []bspec {
	out := make([]bspec, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, bspec{off: off + int64(i)*10, opens: 5})
	}
	return out
}

func findKind(fs []Finding, kind string) *Finding {
	for i := range fs {
		if fs[i].Kind == kind {
			return &fs[i]
		}
	}
	return nil
}

// demoStopInput models the recorded evidence of `docker compose stop
// inventory` under steady load: inventory exits, its presence ceases,
// orders→inventory traffic stops (DNS fails before any TCP attempt),
// and users→cache:6380 has been failing since before the window.
func demoStopInput() Input {
	stop := int64(120) // inventory stopped at t0+120s
	ordersInv := EdgeSeries{
		ID: "svc:orders->svc:inventory:8000", Src: "svc:orders", Dst: "svc:inventory",
		FirstSeen: t0.Add(-time.Hour),
		Buckets:   mkBuckets(steady(0, 12)), // active until t0+120
	}
	chronicEdge := EdgeSeries{
		ID: "svc:users->svc:cache:6380", Src: "svc:users", Dst: "svc:cache",
		FirstSeen: t0.Add(-time.Hour),
	}
	var chronicSpecs []bspec
	for i := int64(0); i < 30; i++ {
		chronicSpecs = append(chronicSpecs, bspec{off: i * 10, opens: 0, failures: 2})
	}
	chronicEdge.Buckets = mkBuckets(chronicSpecs)
	gatewayOrders := EdgeSeries{
		ID: "svc:gateway->svc:orders:8000", Src: "svc:gateway", Dst: "svc:orders",
		FirstSeen: t0.Add(-time.Hour),
		Buckets:   mkBuckets(steady(0, 30)), // keeps flowing the whole window
	}

	var invPresence []PresenceBucket
	for i := int64(0); i < 12; i++ {
		invPresence = append(invPresence, PresenceBucket{Start: t0.Unix() + i*10, Span: 10, Listening: true})
	}

	return Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{ordersInv, chronicEdge, gatewayOrders},
		Presence: []ServicePresence{
			{ID: "svc:inventory", Buckets: invPresence},
		},
		Events: []LifeEvent{
			{Service: "svc:inventory", Kind: "exit", PID: 42, Detail: "killed by signal 15", Time: at(stop + 2)},
		},
		Labels: map[string]string{
			"svc:inventory": "inventory", "svc:orders": "orders",
			"svc:users": "users", "svc:cache": "cache", "svc:gateway": "gateway",
		},
	}
}

func TestDemoStopIncidentResolvesToInventory(t *testing.T) {
	rep := Investigate(demoStopInput())

	if rep.Origin == nil {
		t.Fatalf("origin unresolved: %q; findings: %+v", rep.Unresolved, rep.Findings)
	}
	if rep.Origin.Service != "svc:inventory" {
		t.Fatalf("origin = %s, want svc:inventory", rep.Origin.Service)
	}
	if !rep.Origin.Inference {
		t.Fatal("origin must be flagged as inference")
	}

	exit := findKind(rep.Findings, KindExit)
	if exit == nil || exit.Service != "svc:inventory" {
		t.Fatalf("exit finding missing: %+v", rep.Findings)
	}
	stop := findKind(rep.Findings, KindTrafficStop)
	if stop == nil || stop.Edge != "svc:orders->svc:inventory:8000" {
		t.Fatalf("traffic-stop finding missing: %+v", rep.Findings)
	}
	gone := findKind(rep.Findings, KindServiceGone)
	if gone == nil || gone.Service != "svc:inventory" {
		t.Fatalf("service-gone finding missing: %+v", rep.Findings)
	}
	if !exit.Time.Before(stop.End) {
		t.Fatalf("chain out of order: exit %v vs traffic-stop end %v", exit.Time, stop.End)
	}

	// The chronic edge is context, never part of the incident chain.
	if f := findKind(rep.Findings, KindFailuresStart); f != nil {
		t.Fatalf("chronic edge leaked a transition: %+v", f)
	}
	ch := findKind(rep.Chronic, KindChronicFailure)
	if ch == nil || ch.Edge != "svc:users->svc:cache:6380" {
		t.Fatalf("chronic finding missing: %+v", rep.Chronic)
	}

	// Blast radius: inventory (origin) and orders (its caller), with the
	// stopped edge. The healthy gateway edge stays out.
	wantSvcs := []string{"svc:inventory", "svc:orders"}
	if !reflect.DeepEqual(rep.BlastRadius.Services, wantSvcs) {
		t.Fatalf("blast radius services = %v, want %v", rep.BlastRadius.Services, wantSvcs)
	}
	wantEdges := []string{"svc:orders->svc:inventory:8000"}
	if !reflect.DeepEqual(rep.BlastRadius.Edges, wantEdges) {
		t.Fatalf("blast radius edges = %v, want %v", rep.BlastRadius.Edges, wantEdges)
	}

	// No recovery within the window.
	for _, r := range rep.Recovery {
		if r.RecoveredAt != nil {
			t.Fatalf("nothing recovered in this window: %+v", r)
		}
	}
	// Every finding must carry evidence.
	for _, f := range rep.Findings {
		if len(f.Evidence) == 0 {
			t.Fatalf("finding without evidence: %+v", f)
		}
	}
	// The traffic stop must be linked to the origin as an inference.
	if len(rep.Propagations) == 0 {
		t.Fatal("no propagation linking the stopped edge to the origin")
	}
	for _, p := range rep.Propagations {
		if !p.Inference {
			t.Fatalf("propagation must be flagged inference: %+v", p)
		}
	}
}

// oomInput models the users OOM episode: RSS climbs into the limit, the
// OOM killer fires, gateway→users briefly fails, docker restarts users,
// failures cease.
func oomInput() Input {
	gwUsers := EdgeSeries{
		ID: "svc:gateway->svc:users:8000", Src: "svc:gateway", Dst: "svc:users",
		FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 6) // clean until t0+60
	specs = append(specs, bspec{off: 60, opens: 2, failures: 3})
	specs = append(specs, bspec{off: 70, opens: 5}) // recovered
	specs = append(specs, steady(80, 4)...)
	gwUsers.Buckets = mkBuckets(specs)

	return Input{
		From: t0, To: at(120),
		Edges: []EdgeSeries{gwUsers},
		Events: []LifeEvent{
			{Service: "svc:users", Kind: "oom", PID: 7, Detail: "pid 7 chosen by the OOM killer", Time: at(61)},
			{Service: "svc:users", Kind: "exit", PID: 7, Detail: "killed by signal 9", Time: at(61)},
			{Service: "svc:users", Kind: "exec", PID: 99, Detail: "/usr/local/bin/python", Time: at(64)},
		},
		Metrics: []MetricSeries{{
			ID: "svc:users",
			Buckets: []MetricBucket{
				{Start: t0.Unix() + 40, Span: 10, RSSMax: 200 << 20, MemLimit: 256 << 20},
				{Start: t0.Unix() + 50, Span: 10, RSSMax: 250 << 20, MemLimit: 256 << 20},
				{Start: t0.Unix() + 60, Span: 10, RSSMax: 256 << 20, MemLimit: 256 << 20, OOMKills: 1},
			},
		}},
		Labels: map[string]string{"svc:gateway": "gateway", "svc:users": "users"},
	}
}

func TestOOMIncidentResolvesWithRecovery(t *testing.T) {
	rep := Investigate(oomInput())

	if rep.Origin == nil {
		t.Fatalf("origin unresolved: %q", rep.Unresolved)
	}
	if rep.Origin.Service != "svc:users" {
		t.Fatalf("origin = %s, want svc:users", rep.Origin.Service)
	}
	// rss-pressure precedes the OOM but is contributing-only: the
	// terminal OOM anchors, pressure corroborates.
	if pressure := findKind(rep.Findings, KindRSSPressure); pressure == nil {
		t.Fatal("rss-pressure finding missing")
	}
	if oom := findKind(rep.Findings, KindOOM); oom == nil {
		t.Fatal("oom finding missing")
	}
	// The lifecycle OOM suppresses the cgroup counter for the same kill.
	if dup := findKind(rep.Findings, KindOOMCgroup); dup != nil {
		t.Fatalf("cgroup OOM double-reported next to the lifecycle event: %+v", dup)
	}

	fs := findKind(rep.Findings, KindFailuresStart)
	fe := findKind(rep.Findings, KindFailuresEnd)
	if fs == nil || fe == nil {
		t.Fatalf("failure transition pair missing: %+v", rep.Findings)
	}

	// Recovery: the edge recovered, and the service restarted.
	var edgeRec, svcRec bool
	for _, r := range rep.Recovery {
		if r.Subject == "svc:gateway->svc:users:8000" && r.RecoveredAt != nil {
			edgeRec = true
		}
		if r.Subject == "svc:users" && r.RecoveredAt != nil {
			svcRec = true
		}
	}
	if !edgeRec || !svcRec {
		t.Fatalf("recovery not detected: %+v", rep.Recovery)
	}
}

func TestUnresolvedIndependentPrimaries(t *testing.T) {
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{{
			ID: "svc:a->svc:x:1", Src: "svc:a", Dst: "svc:x",
			FirstSeen: t0.Add(-time.Hour), Buckets: mkBuckets(steady(0, 30)),
		}},
		Events: []LifeEvent{
			{Service: "svc:a", Kind: "exit", Detail: "exited with status 1", Time: at(50)},
			{Service: "svc:b", Kind: "crash", Detail: "killed by SIGSEGV (signal 11)", Time: at(90)},
		},
	}
	rep := Investigate(in)
	if rep.Origin != nil {
		t.Fatalf("independent primaries must not resolve: %+v", rep.Origin)
	}
	if rep.Unresolved == "" {
		t.Fatal("unresolved reason missing")
	}
}

func TestUnresolvedSimultaneousPrimaries(t *testing.T) {
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{{
			ID: "svc:b->svc:a:1", Src: "svc:b", Dst: "svc:a",
			FirstSeen: t0.Add(-time.Hour), Buckets: mkBuckets(steady(0, 5)),
		}},
		Events: []LifeEvent{
			// Same recorded second: order not knowable, even though b
			// depends on a.
			{Service: "svc:a", Kind: "exit", Detail: "exited", Time: at(50)},
			{Service: "svc:b", Kind: "exit", Detail: "exited", Time: at(50)},
		},
	}
	rep := Investigate(in)
	if rep.Origin != nil {
		t.Fatalf("same-second primaries must not resolve: %+v", rep.Origin)
	}
}

func TestCascadeResolvesWhenDependentAndLater(t *testing.T) {
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{{
			ID: "svc:b->svc:a:1", Src: "svc:b", Dst: "svc:a",
			FirstSeen: t0.Add(-time.Hour), Buckets: mkBuckets(steady(0, 5)),
		}},
		Events: []LifeEvent{
			{Service: "svc:a", Kind: "exit", Detail: "exited", Time: at(50)},
			{Service: "svc:b", Kind: "crash", Detail: "killed by SIGSEGV (signal 11)", Time: at(80)},
		},
	}
	rep := Investigate(in)
	if rep.Origin == nil || rep.Origin.Service != "svc:a" {
		t.Fatalf("cascade should resolve to svc:a: origin=%+v unresolved=%q", rep.Origin, rep.Unresolved)
	}
	if len(rep.Propagations) == 0 {
		t.Fatal("cascading crash should be linked as propagation")
	}
}

func TestUnresolvedTransitionPrecedesPrimary(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:b->svc:a:1", Src: "svc:b", Dst: "svc:a", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 3)
	specs = append(specs, bspec{off: 30, opens: 2, failures: 4}) // failures at t0+30
	specs = append(specs, steady(40, 5)...)
	edge.Buckets = mkBuckets(specs)
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{edge},
		Events: []LifeEvent{
			{Service: "svc:a", Kind: "exit", Detail: "exited", Time: at(120)},
		},
	}
	rep := Investigate(in)
	if rep.Origin != nil {
		t.Fatalf("failures preceding the primary must not resolve: %+v", rep.Origin)
	}
}

func TestUnresolvedTransitionWithoutDependencyPath(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 6)
	specs = append(specs, bspec{off: 60, opens: 2, failures: 4})
	edge.Buckets = mkBuckets(specs)
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{edge},
		Events: []LifeEvent{
			// svc:a dies, but the failing edge points at svc:y which has
			// no dependency path to svc:a.
			{Service: "svc:a", Kind: "exit", Detail: "exited", Time: at(50)},
		},
	}
	rep := Investigate(in)
	if rep.Origin != nil {
		t.Fatalf("unrelated transition must not resolve: %+v", rep.Origin)
	}
}

func TestUnresolvedTransitionsWithoutPrimary(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 6)
	specs = append(specs, bspec{off: 60, opens: 2, failures: 4})
	edge.Buckets = mkBuckets(specs)
	rep := Investigate(Input{From: t0, To: at(300), Edges: []EdgeSeries{edge}})
	if rep.Origin != nil {
		t.Fatalf("no primary evidence must not resolve: %+v", rep.Origin)
	}
	if rep.Unresolved == "" {
		t.Fatal("unresolved reason missing")
	}
	if len(rep.BlastRadius.Edges) != 1 {
		t.Fatalf("blast radius must still list observed impact: %+v", rep.BlastRadius)
	}
}

func TestContributingAnchorsWhenNoTerminal(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 8)
	specs = append(specs, bspec{off: 80, opens: 5, retrans: 6})
	specs = append(specs, steady(90, 3)...)
	edge.Buckets = mkBuckets(specs)
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{edge},
		Metrics: []MetricSeries{{
			ID: "svc:y",
			Buckets: []MetricBucket{
				{Start: t0.Unix() + 70, Span: 10, ThrottledUs: 2_000_000},
			},
		}},
	}
	rep := Investigate(in)
	if rep.Origin == nil || rep.Origin.Service != "svc:y" {
		t.Fatalf("throttle should anchor when no terminal exists: origin=%+v unresolved=%q", rep.Origin, rep.Unresolved)
	}
	if findKind(rep.Findings, KindThrottle) == nil {
		t.Fatal("throttle finding missing")
	}
	if findKind(rep.Findings, KindRetransSpike) == nil {
		t.Fatal("retrans-spike finding missing")
	}
}

func TestQuietWindow(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
		Buckets: mkBuckets(steady(0, 30)),
	}
	rep := Investigate(Input{From: t0, To: at(300), Edges: []EdgeSeries{edge}})
	if rep.Origin != nil || rep.Unresolved != "" {
		t.Fatalf("quiet window must report nothing: %+v %q", rep.Origin, rep.Unresolved)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("quiet window produced findings: %+v", rep.Findings)
	}
}

func TestBornFailingEdgeIsATransition(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y",
		FirstSeen: at(60), // first ever seen inside the window
	}
	edge.Buckets = mkBuckets([]bspec{{off: 60, opens: 0, failures: 3}})
	rep := Investigate(Input{From: t0, To: at(300), Edges: []EdgeSeries{edge}})
	if findKind(rep.Findings, KindFailuresStart) == nil {
		t.Fatalf("edge born failing inside the window must be a transition: %+v", rep.Findings)
	}
	if len(rep.Chronic) != 0 {
		t.Fatalf("born-failing edge wrongly classed chronic: %+v", rep.Chronic)
	}
}

func TestShortPauseIsNotATrafficStop(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 5)
	// 20s pause (two empty buckets are simply absent), then resumes and
	// stays active through the window end.
	specs = append(specs, steady(70, 23)...)
	edge.Buckets = mkBuckets(specs)
	rep := Investigate(Input{From: t0, To: at(300), Edges: []EdgeSeries{edge}})
	if f := findKind(rep.Findings, KindTrafficStop); f != nil {
		t.Fatalf("a 20s pause must not be a traffic stop: %+v", f)
	}
}

func TestTrafficStopThenResume(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 5)                    // active until t0+50
	specs = append(specs, steady(200, 5)...) // silent 150s, then back
	edge.Buckets = mkBuckets(specs)
	rep := Investigate(Input{From: t0, To: at(300), Edges: []EdgeSeries{edge}})
	stop := findKind(rep.Findings, KindTrafficStop)
	resume := findKind(rep.Findings, KindTrafficResume)
	if stop == nil || resume == nil {
		t.Fatalf("stop+resume expected: %+v", rep.Findings)
	}
	if !stop.Time.Equal(at(50)) {
		t.Fatalf("stop at %v, want %v", stop.Time, at(50))
	}
	var rec *Recovery
	for i := range rep.Recovery {
		if rep.Recovery[i].Subject == edge.ID {
			rec = &rep.Recovery[i]
		}
	}
	if rec == nil || rec.RecoveredAt == nil || !rec.RecoveredAt.Equal(at(200)) {
		t.Fatalf("traffic-stop recovery not matched: %+v", rep.Recovery)
	}
}

func TestServiceGoneAndBack(t *testing.T) {
	var pb []PresenceBucket
	for i := int64(0); i < 5; i++ {
		pb = append(pb, PresenceBucket{Start: t0.Unix() + i*10, Span: 10, Listening: true})
	}
	// 150s gap, then back and present through the window end.
	for i := int64(20); i < 30; i++ {
		pb = append(pb, PresenceBucket{Start: t0.Unix() + i*10, Span: 10, Listening: true})
	}
	rep := Investigate(Input{
		From: t0, To: at(300),
		Presence: []ServicePresence{{ID: "svc:a", Buckets: pb}},
	})
	if findKind(rep.Findings, KindServiceGone) == nil {
		t.Fatalf("service-gone missing: %+v", rep.Findings)
	}
	back := findKind(rep.Findings, KindServiceBack)
	if back == nil || !back.Time.Equal(at(200)) {
		t.Fatalf("service-back missing/wrong: %+v", rep.Findings)
	}
	var rec *Recovery
	for i := range rep.Recovery {
		if rep.Recovery[i].Subject == "svc:a" {
			rec = &rep.Recovery[i]
		}
	}
	if rec == nil || rec.RecoveredAt == nil {
		t.Fatalf("gone/back recovery not matched: %+v", rep.Recovery)
	}
}

func TestListenLost(t *testing.T) {
	pb := []PresenceBucket{
		{Start: t0.Unix(), Span: 10, Listening: true},
		{Start: t0.Unix() + 10, Span: 10, Listening: true},
		{Start: t0.Unix() + 20, Span: 10, Listening: false},
		{Start: t0.Unix() + 30, Span: 10, Listening: false},
	}
	rep := Investigate(Input{
		From: t0, To: at(60),
		Presence: []ServicePresence{{ID: "svc:a", Buckets: pb}},
	})
	ll := findKind(rep.Findings, KindListenLost)
	if ll == nil || !ll.Time.Equal(at(20)) {
		t.Fatalf("listen-lost missing/wrong: %+v", rep.Findings)
	}
	// Only the transition, not every non-listening row.
	count := 0
	for _, f := range rep.Findings {
		if f.Kind == KindListenLost {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("listen-lost emitted %d times, want 1", count)
	}
}

func TestServiceFilterRestrictsToComponent(t *testing.T) {
	in := demoStopInput()
	// Unrelated incident elsewhere: svc:zeta crashes, disconnected from
	// the inventory component.
	in.Events = append(in.Events, LifeEvent{
		Service: "svc:zeta", Kind: "crash", Detail: "killed by SIGSEGV (signal 11)", Time: at(10),
	})

	// Unfocused: two independent primaries → unresolved.
	if rep := Investigate(in); rep.Origin != nil {
		t.Fatalf("unfocused investigation should be unresolved, got origin %+v", rep.Origin)
	}

	// Focused on orders: zeta is outside the component, inventory wins.
	in.Service = "svc:orders"
	rep := Investigate(in)
	if rep.Origin == nil || rep.Origin.Service != "svc:inventory" {
		t.Fatalf("focused investigation: origin=%+v unresolved=%q", rep.Origin, rep.Unresolved)
	}
	for _, f := range rep.Findings {
		if f.Service == "svc:zeta" {
			t.Fatalf("zeta finding leaked into the focused component: %+v", f)
		}
	}
}

func TestDeterminism(t *testing.T) {
	a := Investigate(demoStopInput())
	b := Investigate(demoStopInput())
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same input produced different reports")
	}
}

func TestFindingsAreChronological(t *testing.T) {
	rep := Investigate(demoStopInput())
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i].Time.Before(rep.Findings[i-1].Time) {
			t.Fatalf("findings out of order at %d: %v after %v",
				i, rep.Findings[i].Time, rep.Findings[i-1].Time)
		}
	}
}

func TestCleanExitIsNeverAPrimary(t *testing.T) {
	edge := EdgeSeries{
		ID: "svc:x->svc:y:1", Src: "svc:x", Dst: "svc:y", FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 6)
	specs = append(specs, bspec{off: 60, opens: 2, failures: 4})
	specs = append(specs, steady(70, 23)...)
	edge.Buckets = mkBuckets(specs)
	in := Input{
		From: t0, To: at(300),
		Edges: []EdgeSeries{edge},
		Events: []LifeEvent{
			// A short-lived client exiting cleanly before the failures:
			// normal lifecycle, must not be mistaken for the origin.
			{Service: "svc:tool", Kind: "exit", Detail: "exited cleanly", Time: at(30)},
		},
	}
	rep := Investigate(in)
	if rep.Origin != nil {
		t.Fatalf("a clean exit anchored an origin: %+v", rep.Origin)
	}
	f := findKind(rep.Findings, KindExitClean)
	if f == nil {
		t.Fatalf("clean exit should still be recorded as a fact: %+v", rep.Findings)
	}
	// And it must not pollute the blast radius.
	for _, s := range rep.BlastRadius.Services {
		if s == "svc:tool" {
			t.Fatalf("clean exit entered the blast radius: %+v", rep.BlastRadius)
		}
	}
}

func TestCleanExitDoesNotBlockRealOrigin(t *testing.T) {
	in := demoStopInput()
	// An unrelated tool exits cleanly before the incident.
	in.Events = append(in.Events, LifeEvent{
		Service: "svc:tool", Kind: "exit", Detail: "exited cleanly", Time: at(10),
	})
	rep := Investigate(in)
	if rep.Origin == nil || rep.Origin.Service != "svc:inventory" {
		t.Fatalf("clean exit blocked the origin: origin=%+v unresolved=%q", rep.Origin, rep.Unresolved)
	}
}

func TestExternalTransitionsDoNotVeto(t *testing.T) {
	in := demoStopInput()
	in.ExternalID = "svc:external"
	// Background host traffic to the outside world hiccups during the
	// incident — before the primary, even. Local evidence can neither
	// explain nor refute it, so it must not gate the origin.
	ext := EdgeSeries{
		ID: "svc:runner->svc:external:443", Src: "svc:runner", Dst: "svc:external",
		FirstSeen: t0.Add(-time.Hour),
	}
	specs := steady(0, 5)
	specs = append(specs, bspec{off: 50, opens: 1, failures: 2})
	specs = append(specs, steady(60, 24)...)
	ext.Buckets = mkBuckets(specs)
	in.Edges = append(in.Edges, ext)

	rep := Investigate(in)
	if rep.Origin == nil || rep.Origin.Service != "svc:inventory" {
		t.Fatalf("external transition vetoed the origin: origin=%+v unresolved=%q", rep.Origin, rep.Unresolved)
	}
	// The external failure is still a recorded fact.
	found := false
	for _, f := range rep.Findings {
		if f.Kind == KindFailuresStart && f.EdgeDst == "svc:external" {
			found = true
		}
	}
	if !found {
		t.Fatalf("external transition not recorded: %+v", rep.Findings)
	}
}

func TestNoDependencyPathThroughExternal(t *testing.T) {
	// a -> external and external -> b must not imply a depends on b.
	in := Input{
		From: t0, To: at(300),
		ExternalID: "svc:external",
		Edges: []EdgeSeries{
			{ID: "svc:a->svc:external:443", Src: "svc:a", Dst: "svc:external",
				FirstSeen: t0.Add(-time.Hour), Buckets: mkBuckets(steady(0, 30))},
			{ID: "svc:external->svc:b:22", Src: "svc:external", Dst: "svc:b",
				FirstSeen: t0.Add(-time.Hour), Buckets: mkBuckets(steady(0, 30))},
		},
		Events: []LifeEvent{
			{Service: "svc:b", Kind: "exit", Detail: "killed by signal 15", Time: at(50)},
			{Service: "svc:a", Kind: "crash", Detail: "killed by SIGSEGV (signal 11)", Time: at(90)},
		},
	}
	rep := Investigate(in)
	// svc:a's crash follows svc:b's exit but a's only "path" to b runs
	// through the external aggregate — not a real dependency, so the two
	// primaries are independent.
	if rep.Origin != nil {
		t.Fatalf("dependency path traversed the external aggregate: %+v", rep.Origin)
	}
}

func TestTrafficStopNeedsSteadyActivity(t *testing.T) {
	// Only 3 active buckets (a CLI burst), then silence to window end:
	// below the steadiness bar, no stop.
	edge := EdgeSeries{
		ID: "svc:cli->svc:daemon:1", Src: "svc:cli", Dst: "svc:daemon",
		FirstSeen: t0.Add(-time.Hour),
		Buckets:   mkBuckets(steady(0, 3)),
	}
	rep := Investigate(Input{From: t0, To: at(300), Edges: []EdgeSeries{edge}})
	if f := findKind(rep.Findings, KindTrafficStop); f != nil {
		t.Fatalf("burst edge produced a traffic stop: %+v", f)
	}
}

func TestSystemStatusExitIsNeutral(t *testing.T) {
	in := oomInput()
	// The CI runner's network tooling errors out (status 1) in the same
	// second as the OOM — recorded, but it must not contest the origin.
	in.SystemServices = map[string]bool{"svc:proc:networkctl": true}
	in.Events = append(in.Events, LifeEvent{
		Service: "svc:proc:networkctl", Kind: "exit",
		Detail: "exited with status 1", Time: at(61),
	})
	rep := Investigate(in)
	if rep.Origin == nil || rep.Origin.Service != "svc:users" {
		t.Fatalf("system tool status-exit contested the origin: origin=%+v unresolved=%q",
			rep.Origin, rep.Unresolved)
	}
	f := findKind(rep.Findings, KindExitStatus)
	if f == nil || f.Service != "svc:proc:networkctl" {
		t.Fatalf("status exit should still be recorded: %+v", rep.Findings)
	}
	for _, s := range rep.BlastRadius.Services {
		if s == "svc:proc:networkctl" {
			t.Fatalf("neutral status exit entered the blast radius: %+v", rep.BlastRadius)
		}
	}
	// An *app* service's status exit stays primary: only infrastructure
	// tools get the pass.
	in2 := oomInput()
	in2.Events = append(in2.Events, LifeEvent{
		Service: "svc:zeta", Kind: "exit",
		Detail: "exited with status 1", Time: at(10),
	})
	if rep2 := Investigate(in2); rep2.Origin != nil {
		t.Fatalf("app status exit must stay primary: %+v", rep2.Origin)
	}
}

func TestRecoveryAcceptsSameSecondRestart(t *testing.T) {
	in := oomInput()
	// The restart exec routinely lands within the same recorded second
	// as the kill; recovery pairing accepts the tie.
	for i := range in.Events {
		if in.Events[i].Kind == "exec" {
			in.Events[i].Time = at(61)
		}
	}
	rep := Investigate(in)
	var recovered bool
	for _, r := range rep.Recovery {
		if r.Subject == "svc:users" && r.RecoveredAt != nil {
			recovered = true
		}
	}
	if !recovered {
		t.Fatalf("same-second restart not matched as recovery: %+v", rep.Recovery)
	}
}
