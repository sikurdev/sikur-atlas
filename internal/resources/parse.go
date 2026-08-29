// Package resources samples per-service CPU, memory, IO, fd/thread
// counts, cgroup throttling/limits and PSI from procfs and cgroup v2.
// Parsers are portable and unit-tested; the sampling loop is Linux-only.
package resources

import (
	"strconv"
	"strings"
)

// ParseProcStat extracts utime+stime ticks and the thread count from
// /proc/<pid>/stat. The comm field may contain spaces and parentheses,
// so parsing anchors on the LAST ')'.
func ParseProcStat(content string) (cpuTicks uint64, threads int, ok bool) {
	end := strings.LastIndexByte(content, ')')
	if end < 0 || end+2 > len(content) {
		return 0, 0, false
	}
	fields := strings.Fields(content[end+2:])
	// After comm: field[0] = state (field 3 overall). utime is overall
	// field 14 → index 11 here; stime 15 → 12; num_threads 20 → 17.
	if len(fields) < 18 {
		return 0, 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	th, err3 := strconv.Atoi(fields[17])
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, false
	}
	return utime + stime, th, true
}

// ParseStatmRSS returns RSS in bytes from /proc/<pid>/statm (field 2 is
// resident pages).
func ParseStatmRSS(content string, pageSize uint64) uint64 {
	fields := strings.Fields(content)
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * pageSize
}

// ParseProcIO extracts read_bytes/write_bytes from /proc/<pid>/io.
func ParseProcIO(content string) (readBytes, writeBytes uint64) {
	for _, line := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(line, "read_bytes: "); ok {
			readBytes, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
		if v, ok := strings.CutPrefix(line, "write_bytes: "); ok {
			writeBytes, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return readBytes, writeBytes
}

// ParseKeyedFile parses "key value" lines (cpu.stat, memory.events).
func ParseKeyedFile(content string) map[string]uint64 {
	out := make(map[string]uint64)
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			out[k] = n
		}
	}
	return out
}

// ParseCgroupIOStat sums rbytes/wbytes across devices in io.stat.
func ParseCgroupIOStat(content string) (readBytes, writeBytes uint64) {
	for _, line := range strings.Split(content, "\n") {
		for _, kv := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(kv, "rbytes="); ok {
				n, _ := strconv.ParseUint(v, 10, 64)
				readBytes += n
			}
			if v, ok := strings.CutPrefix(kv, "wbytes="); ok {
				n, _ := strconv.ParseUint(v, 10, 64)
				writeBytes += n
			}
		}
	}
	return readBytes, writeBytes
}

// ParseMemMax parses memory.max: a byte count, or 0 for "max" (no
// limit).
func ParseMemMax(content string) uint64 {
	s := strings.TrimSpace(content)
	if s == "" || s == "max" {
		return 0
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// ParsePSISome extracts the "some avg10" percentage from a pressure
// file (works for /proc/pressure/* and cgroup *.pressure).
func ParsePSISome(content string) float64 {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, kv := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(kv, "avg10="); ok {
				f, err := strconv.ParseFloat(v, 64)
				if err == nil {
					return f
				}
			}
		}
	}
	return 0
}

// ParseCgroupV2Path returns the unified-hierarchy path from
// /proc/<pid>/cgroup ("0::/path"), or "".
func ParseCgroupV2Path(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return p
		}
	}
	return ""
}
