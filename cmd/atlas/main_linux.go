//go:build linux

// Command atlas runs the Sikur Atlas agent: it loads the eBPF programs,
// maintains the service topology graph and serves the API and web UI.
//
// Zero configuration: `sudo atlas` and open http://localhost:7171.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sikurdev/sikur-atlas/internal/api"
	"github.com/sikurdev/sikur-atlas/internal/collector"
	"github.com/sikurdev/sikur-atlas/internal/dockermeta"
	"github.com/sikurdev/sikur-atlas/internal/ebpf"
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/procfs"
	"github.com/sikurdev/sikur-atlas/internal/webui"
)

var version = "0.1.0-dev" // overridden via -ldflags at release build

func main() {
	listen := flag.String("listen", "127.0.0.1:7171", "HTTP listen address for API and UI")
	dockerSocket := flag.String("docker-socket", dockermeta.DefaultSocket, "Docker socket for container name enrichment (\"\" disables)")
	scanInterval := flag.Duration("scan-interval", 30*time.Second, "listening-socket rescan interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("atlas", version)
		return
	}
	if err := run(*listen, *dockerSocket, *scanInterval); err != nil {
		log.Fatalf("atlas: %v", err)
	}
}

func run(listen, dockerSocket string, scanInterval time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := graph.NewStore()
	resolver := procfs.NewResolver()

	// Optional Docker enrichment; Atlas is fully functional without it.
	var enricher *dockermeta.Enricher
	if dockerSocket != "" {
		if client := dockermeta.NewUnixClient(dockerSocket); client != nil {
			enricher = dockermeta.NewEnricher(client, func(cid string, meta dockermeta.Meta) {
				short := cid
				if len(short) > 12 {
					short = short[:12]
				}
				store.SetContainerMeta("container:"+short, meta.Name, meta.Image)
			})
			go enricher.Run(ctx)
			log.Printf("docker enrichment enabled via %s", dockerSocket)
		} else {
			log.Printf("docker socket %s not available; containers will show short ids", dockerSocket)
		}
	}

	opts := []collector.Option{}
	if enricher != nil {
		opts = append(opts, collector.WithContainerHook(enricher.Enqueue))
	}
	corr := collector.New(store, resolver, opts...)

	tracer, err := ebpf.NewTracer()
	if err != nil {
		return fmt.Errorf("%w\n\nAtlas needs root (or CAP_BPF+CAP_PERFMON) and a kernel >= 5.8 built with BTF (/sys/kernel/btf/vmlinux)", err)
	}
	defer tracer.Close()
	log.Printf("eBPF programs attached (tracepoint sock/inet_sock_set_state, kretprobe inet_csk_accept)")

	// Periodic work: correlator ticks and listening-socket scans.
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				corr.Tick(now)
			}
		}
	}()
	go func() {
		scan := func() {
			raw := procfs.ScanListeners()
			listeners := make([]collector.Listener, len(raw))
			for i, l := range raw {
				listeners[i] = collector.Listener{
					PID: l.PID, Comm: l.Comm, Addr: l.Addr, Port: l.Port,
				}
			}
			corr.SyncListeners(listeners, time.Now())
		}
		scan()
		t := time.NewTicker(scanInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				scan()
			}
		}
	}()

	var decodeErrors atomic.Uint64
	startedAt := time.Now().UTC()
	metaFn := func() api.Meta {
		drops, _ := tracer.Drops()
		return api.Meta{
			Version:          version,
			StartedAt:        startedAt,
			Kernel:           kernelVersion(),
			Collector:        corr.Stats(),
			KernelDrops:      drops,
			DecodeErrors:     decodeErrors.Load(),
			DockerEnrichment: enricher != nil,
		}
	}

	ui, uiOK := webui.Dist()
	if !uiOK {
		ui = nil
		log.Printf("web UI not embedded in this build; API only")
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           api.NewServer(store, metaFn, ui).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	serveErr := make(chan error, 1)
	go func() {
		log.Printf("atlas %s serving on http://%s", version, listen)
		serveErr <- srv.ListenAndServe()
	}()
	runErr := make(chan error, 1)
	go func() {
		runErr <- tracer.Run(ctx, corr.HandleEvent, func(error) {
			decodeErrors.Add(1)
		})
	}()

	// Whichever side fails first (e.g. the listen address is taken)
	// takes the whole agent down loudly instead of leaving it headless.
	var firstErr error
	select {
	case err := <-serveErr:
		firstErr = filterErr(err)
		stop()
		<-runErr
	case err := <-runErr:
		firstErr = filterErr(err)
		stop()
		if err := filterErr(<-serveErr); firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	log.Printf("shut down cleanly")
	return nil
}

// filterErr drops the errors that just mean "orderly shutdown".
func filterErr(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func kernelVersion() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Sysname[:]) + " " + unix.ByteSliceToString(uts.Release[:])
}
