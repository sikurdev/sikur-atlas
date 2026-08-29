package ebpf

import (
	"embed"
	"fmt"
)

// The compiled BPF object is a build artifact (make bpf), deliberately
// not committed. The obj directory holds a .gitkeep so the embed pattern
// always resolves; ObjectBytes gives a actionable error when the object
// itself is missing.
//
//go:embed all:obj
var objFS embed.FS

// ObjectBytes returns the embedded BPF ELF.
func ObjectBytes() ([]byte, error) {
	b, err := objFS.ReadFile("obj/atlas.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("embedded BPF object missing — run `make bpf` before building: %w", err)
	}
	return b, nil
}
