package tui

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/term"
)

// Main runs `atlas top`. Returns the process exit code.
func Main(args []string, version string) (int, error) {
	fs := flag.NewFlagSet("atlas top", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:7171", "agent API base URL")
	once := fs.Bool("once", false, "print one frame and exit (for scripts/CI)")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval")
	if err := fs.Parse(args); err != nil {
		return 2, nil // flag package already printed usage
	}

	client := &Client{BaseURL: *url, HTTP: &http.Client{Timeout: 5 * time.Second}}
	state := &State{Sort: SortCPU, Width: 120, Height: 40, Plain: *once}
	_ = version

	refresh := func() {
		snap, err := client.Fetch()
		state.Err = err
		if err == nil {
			state.Snapshot = snap
		}
		state.Rows = BuildRows(state.Snapshot.Graph, state.Filter, state.ShowSystem, state.Focus)
		SortRows(state.Rows, state.Sort)
		if state.Selected >= len(state.Rows) {
			state.Selected = 0
		}
	}

	if *once {
		refresh()
		fmt.Print(Render(state))
		if state.Err != nil {
			return 1, state.Err
		}
		return 0, nil
	}

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return 1, fmt.Errorf("terminal raw mode (use --once for scripts): %w", err)
	}
	defer term.Restore(fd, oldState) //nolint:errcheck // best effort on exit

	if w, h, err := term.GetSize(fd); err == nil {
		state.Width, state.Height = w, h
	}
	state.Plain = false

	keys := make(chan byte, 16)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(keys)
				return
			}
			keys <- buf[0]
		}
	}()

	draw := func() {
		// Home + clear, then the frame.
		fmt.Print("\x1b[H\x1b[2J" + Render(state))
	}
	refresh()
	draw()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	var escSeq []byte
	for {
		select {
		case <-ticker.C:
			refresh()
			draw()
		case k, ok := <-keys:
			if !ok {
				return 0, nil
			}
			// Arrow keys arrive as ESC [ A/B.
			if len(escSeq) > 0 {
				escSeq = append(escSeq, k)
				if len(escSeq) == 3 {
					switch escSeq[2] {
					case 'A':
						k = 'k'
					case 'B':
						k = 'j'
					default:
						k = 0
					}
					escSeq = nil
					if k == 0 {
						continue
					}
				} else {
					continue
				}
			} else if k == 0x1b {
				escSeq = []byte{k}
				continue
			}

			if state.Filtering {
				switch k {
				case '\r', '\n':
					state.Filtering = false
				case 0x7f, 0x08: // backspace
					if len(state.Filter) > 0 {
						state.Filter = state.Filter[:len(state.Filter)-1]
					}
				default:
					if k >= 0x20 && k < 0x7f {
						state.Filter += string(k)
					}
				}
				state.Rows = BuildRows(state.Snapshot.Graph, state.Filter, state.ShowSystem, state.Focus)
				SortRows(state.Rows, state.Sort)
				if state.Selected >= len(state.Rows) {
					state.Selected = 0
				}
				draw()
				continue
			}

			switch k {
			case 'q', 3: // q or ctrl-c
				return 0, nil
			case '/':
				state.Filtering = true
				state.Filter = ""
			case 'j':
				if state.Selected < len(state.Rows)-1 {
					state.Selected++
				}
			case 'k':
				if state.Selected > 0 {
					state.Selected--
				}
			case '\r', '\n':
				state.Drill = !state.Drill
			case 'f':
				if state.Focus != "" {
					state.Focus = ""
				} else if state.Selected < len(state.Rows) {
					state.Focus = state.Rows[state.Selected].ID
				}
				state.Rows = BuildRows(state.Snapshot.Graph, state.Filter, state.ShowSystem, state.Focus)
				SortRows(state.Rows, state.Sort)
				state.Selected = 0
			case 's':
				state.Sort = NextSort(state.Sort)
				SortRows(state.Rows, state.Sort)
			case 'y':
				state.ShowSystem = !state.ShowSystem
				state.Rows = BuildRows(state.Snapshot.Graph, state.Filter, state.ShowSystem, state.Focus)
				SortRows(state.Rows, state.Sort)
			}
			draw()
		}
	}
}
