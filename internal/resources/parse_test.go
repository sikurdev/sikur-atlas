package resources

import "testing"

func TestParseProcStat(t *testing.T) {
	// Real shape, including a comm with spaces and parens.
	line := "1234 (tricky (name) x) S 1 1234 1234 0 -1 4194560 2549 0 0 0 37 12 0 0 20 0 5 0 12345 123456789 4321 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
	ticks, threads, ok := ParseProcStat(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if ticks != 37+12 {
		t.Fatalf("cpu ticks = %d, want 49", ticks)
	}
	if threads != 5 {
		t.Fatalf("threads = %d, want 5", threads)
	}

	if _, _, ok := ParseProcStat("garbage"); ok {
		t.Fatal("garbage must not parse")
	}
}

func TestParseStatmRSS(t *testing.T) {
	if got := ParseStatmRSS("2500 1250 300 50 0 400 0", 4096); got != 1250*4096 {
		t.Fatalf("rss = %d", got)
	}
	if got := ParseStatmRSS("bad", 4096); got != 0 {
		t.Fatalf("bad statm = %d", got)
	}
}

func TestParseProcIO(t *testing.T) {
	content := "rchar: 999\nwchar: 888\nsyscr: 10\nsyscw: 5\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n"
	r, w := ParseProcIO(content)
	if r != 4096 || w != 8192 {
		t.Fatalf("io = %d/%d", r, w)
	}
}

func TestParseKeyedFile(t *testing.T) {
	m := ParseKeyedFile("usage_usec 5000000\nuser_usec 3000000\nnr_throttled 4\nthrottled_usec 250000\n")
	if m["usage_usec"] != 5000000 || m["throttled_usec"] != 250000 {
		t.Fatalf("cpu.stat = %v", m)
	}
	ev := ParseKeyedFile("low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\n")
	if ev["oom_kill"] != 2 {
		t.Fatalf("memory.events = %v", ev)
	}
}

func TestParseCgroupIOStat(t *testing.T) {
	content := "8:0 rbytes=1048576 wbytes=524288 rios=100 wios=50 dbytes=0 dios=0\n259:0 rbytes=2048 wbytes=4096 rios=2 wios=4 dbytes=0 dios=0\n"
	r, w := ParseCgroupIOStat(content)
	if r != 1048576+2048 || w != 524288+4096 {
		t.Fatalf("io.stat = %d/%d", r, w)
	}
}

func TestParseMemMax(t *testing.T) {
	if got := ParseMemMax("max\n"); got != 0 {
		t.Fatalf("unlimited = %d", got)
	}
	if got := ParseMemMax("268435456\n"); got != 268435456 {
		t.Fatalf("limit = %d", got)
	}
}

func TestParsePSISome(t *testing.T) {
	content := "some avg10=12.34 avg60=5.00 avg300=1.20 total=123456\nfull avg10=3.21 avg60=1.00 avg300=0.10 total=654\n"
	if got := ParsePSISome(content); got != 12.34 {
		t.Fatalf("psi = %v", got)
	}
	if got := ParsePSISome(""); got != 0 {
		t.Fatalf("empty psi = %v", got)
	}
}

func TestParseCgroupV2Path(t *testing.T) {
	content := "0::/system.slice/docker-abc.scope\n"
	if got := ParseCgroupV2Path(content); got != "/system.slice/docker-abc.scope" {
		t.Fatalf("cgroup path = %q", got)
	}
	// v1-only content has no 0:: line.
	if got := ParseCgroupV2Path("12:pids:/docker/abc\n"); got != "" {
		t.Fatalf("v1 content = %q", got)
	}
}
