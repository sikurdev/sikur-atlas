//go:build !linux

package main

import (
	"fmt"
	"os"
)

func agentMain() {
	fmt.Fprintln(os.Stderr, "the atlas agent uses eBPF and runs on Linux only")
	fmt.Fprintln(os.Stderr, "cross-compile with: GOOS=linux go build ./cmd/atlas")
	fmt.Fprintln(os.Stderr, "(`atlas top` works from any OS against a running agent)")
	os.Exit(1)
}
