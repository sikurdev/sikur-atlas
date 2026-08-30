// Command atlas is the Sikur Atlas agent (Linux) and its terminal
// client. `atlas` runs the agent; `atlas top` opens the TUI against a
// running agent's API and works on any OS.
package main

import (
	"fmt"
	"os"

	"github.com/sikurdev/sikur-atlas/internal/tui"
)

var version = "0.3.0" // overridden via -ldflags at release build

func main() {
	if len(os.Args) > 1 && os.Args[1] == "top" {
		code, err := tui.Main(os.Args[2:], version)
		if err != nil {
			fmt.Fprintln(os.Stderr, "atlas top:", err)
		}
		os.Exit(code)
	}
	agentMain()
}
