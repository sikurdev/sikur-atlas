//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "the atlas agent uses eBPF and runs on Linux only")
	fmt.Fprintln(os.Stderr, "cross-compile with: GOOS=linux go build ./cmd/atlas")
	os.Exit(1)
}
