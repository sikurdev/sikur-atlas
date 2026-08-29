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
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sikurdev/sikur-atlas/internal/api"
	"github.com/sikurdev/sikur-atlas/internal/collector"
	"github.com/sikurdev/sikur-atlas/internal/dockermeta"
	"github.com/sikurdev/sikur-atlas/internal/ebpf"
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/history"
	"github.com/sikurdev/sikur-atlas/internal/procfs"
	"github.com/sikurdev/sikur-atlas/internal/resources"
	"github.com/sikurdev/sikur-atlas/internal/unixdiag"
	"github.com/sikurdev/sikur-atlas/internal/webui"
)

func agentMain() {
	listen := flag.String("listen", "127.0.0.1:7171", "HTTP listen address for API and UI")
	dockerSocket := flag.String("docker-socket", dockermeta.DefaultSocket, "Docker socket for container name enrichment (\"\" disables)")
	scanInterval := flag.Duration("scan-interval", 30*time.Second, "listening-socket rescan interval")
	dbPath := flag.String("db", "/var/lib/sikur-atlas/history.db", "path of the topology history database")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("atlas", version)
		return
	}
	if err := run(*listen, *dockerSocket, *dbPath, *scanInterval); err != nil {
		log.Fatalf("atlas: %v", err)
	}
}

func run(listen, dockerSocket, dbPath string, scanInterval time.Duration) error {
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
				store.SetComposeIdentity("container:"+short, meta.ComposeProject, meta.ComposeService)
			})
			go enricher.Run(ctx)
			log.Printf("docker enrichment enabled via %s", dockerSocket)
		} else {
			log.Printf("docker socket %s not available; containers will show short ids", dockerSocket)
		}
	}

	// Topology history: the database behind Replay and Compare.
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("creating history directory: %w", err)
	}
	hist, err := history.Open(dbPath, store)
	if err != nil {
		return fmt.Errorf("opening history database: %w", err)
	}
	defer hist.Close()
	// LIFO: the final flush (including the open bucket) runs before the
	// deferred Close, so shutdown cannot race the last interval away.
	defer func() {
		if err := hist.FinalFlush(); err != nil {
			log.Printf("history: final flush: %v", err)
		}
	}()
	go hist.Run(ctx, func(err error) { log.Printf("history: %v", err) })
	log.Printf("topology history at %s", dbPath)

	opts := []collector.Option{collector.WithRecorder(hist)}
	if enricher != nil {
		opts = append(opts, collector.WithContainerHook(enricher.Enqueue))
	}
	corr := collector.New(store, resolver, opts...)

	tracer, err := ebpf.NewTracer()
	if err != nil {
		return fmt.Errorf("%w\n\nAtlas needs root (or CAP_BPF+CAP_PERFMON) and a kernel >= 5.8 built with BTF (/sys/kernel/btf/vmlinux)", err)
	}
	defer tracer.Close()
	log.Printf("eBPF programs attached (inet_sock_set_state, tcp_retransmit_skb, tcp_receive_reset, sched_process_exec/exit, oom mark_victim, kprobes inet_csk_accept + unix_stream_connect)")

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
			res := procfs.ScanSockets()
			listeners := make([]collector.Listener, len(res.Listeners))
			for i, l := range res.Listeners {
				listeners[i] = collector.Listener{
					PID: l.PID, Comm: l.Comm, Addr: l.Addr, Port: l.Port,
				}
			}
			corr.SyncListeners(listeners, time.Now())
			// AF_UNIX topology: exact peer pairing from the kernel's
			// own socket table, dumped in every network namespace
			// (container sockets are invisible from the host's).
			if socks, err := unixdiag.DumpAll(res.NetNSPids); err == nil {
				corr.SyncUnixTopology(socks, res.InodeToPID, time.Now())
			} else {
				log.Printf("unix diag: %v", err)
			}
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

	// Resource sampling: one bounded pass per history bucket.
	sampler := resources.NewSampler(store, hist)
	go sampler.Run(ctx.Done(), 10*time.Second)

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
			History:          true,
			HostPSI:          sampler.HostPressure(),
		}
	}

	ui, uiOK := webui.Dist()
	if !uiOK {
		ui = nil
		log.Printf("web UI not embedded in this build; API only")
	}
	selfExe, _ := os.Executable()
	srv := &http.Server{
		Addr: listen,
		Handler: api.NewServer(api.Config{
			Store:   store,
			History: hist,
			MetaFn:  metaFn,
			UI:      ui,
			SelfExe: selfExe,
		}).Handler(),
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
