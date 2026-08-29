import { useCallback, useEffect, useMemo, useState } from "react";

import {
  fetchAppViewAt,
  fetchCompare,
  fetchGraphAt,
  useGraphStream,
  useMeta,
  type AppGraph,
  type Diff,
  type GraphSnapshot,
} from "./api";
import { GraphCanvas } from "./components/GraphCanvas";
import { Inspector } from "./components/Inspector";
import { Timeline, type TimeMode } from "./components/Timeline";
import {
  applyFilters,
  computeFocus,
  fromApp,
  fromDiff,
  fromRaw,
  type DisplayGraph,
} from "./display";
import { formatCount } from "./format";
import type { Selection } from "./selection";

const STATUS_LABEL = {
  connecting: "connecting",
  live: "live",
  reconnecting: "reconnecting",
} as const;

type ViewMode = "app" | "raw";
type LayoutMode = "overview" | "explore";

interface UrlState {
  view: ViewMode;
  layout: LayoutMode;
  showSystem: boolean;
  at: number | null;
  compare: { a: number; b: number } | null;
}

function readURL(): UrlState {
  const p = new URLSearchParams(window.location.search);
  const num = (k: string) => {
    const v = Number(p.get(k));
    return Number.isFinite(v) && v > 0 ? Math.floor(v) : null;
  };
  const a = num("a");
  const b = num("b");
  return {
    view: p.get("view") === "raw" ? "raw" : "app",
    layout: p.get("layout") === "explore" ? "explore" : "overview",
    showSystem: p.get("sys") === "1",
    at: num("at"),
    compare: a != null && b != null ? { a, b } : null,
  };
}

function writeURL(s: UrlState) {
  const p = new URLSearchParams();
  if (s.view !== "app") p.set("view", s.view);
  if (s.layout !== "overview") p.set("layout", s.layout);
  if (s.showSystem) p.set("sys", "1");
  if (s.compare) {
    p.set("a", String(s.compare.a));
    p.set("b", String(s.compare.b));
  } else if (s.at != null) {
    p.set("at", String(s.at));
  }
  const qs = p.toString();
  window.history.replaceState(null, "", qs ? `?${qs}` : window.location.pathname);
}

export function App({ makeSource }: { makeSource?: () => EventSource }) {
  const { payload, status } = useGraphStream(makeSource);
  const meta = useMeta();
  const initial = useMemo(readURL, []);

  const [view, setView] = useState<ViewMode>(initial.view);
  const [layout, setLayout] = useState<LayoutMode>(initial.layout);
  const [showSystem, setShowSystem] = useState(initial.showSystem);
  const [at, setAt] = useState<number | null>(initial.at);
  const [compare, setCompare] = useState<{ a: number; b: number } | null>(
    initial.compare,
  );
  const [pinnedA, setPinnedA] = useState<number | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  // Fetched data for replay / compare modes.
  const [replayRaw, setReplayRaw] = useState<GraphSnapshot | null>(null);
  const [replayApp, setReplayApp] = useState<AppGraph | null>(null);
  const [diff, setDiff] = useState<Diff | null>(null);
  const [compareB, setCompareB] = useState<AppGraph | null>(null);

  useEffect(() => {
    writeURL({ view, layout, showSystem, at, compare });
  }, [view, layout, showSystem, at, compare]);

  useEffect(() => {
    if (at == null) {
      setReplayRaw(null);
      setReplayApp(null);
      return;
    }
    let stale = false;
    void Promise.all([fetchGraphAt(at), fetchAppViewAt(at)])
      .then(([raw, app]) => {
        if (!stale) {
          setReplayRaw(raw);
          setReplayApp(app);
        }
      })
      .catch(() => {
        // Never leave a previous moment's graph on screen under this
        // moment's header.
        if (!stale) {
          setReplayRaw(null);
          setReplayApp(null);
        }
      });
    return () => {
      stale = true;
    };
  }, [at]);

  useEffect(() => {
    if (compare == null) {
      setDiff(null);
      setCompareB(null);
      return;
    }
    let stale = false;
    void Promise.all([
      fetchCompare(compare.a, compare.b),
      fetchAppViewAt(compare.b),
    ])
      .then(([d, b]) => {
        if (!stale) {
          setDiff(d);
          setCompareB(b);
        }
      })
      .catch(() => {
        if (!stale) {
          setDiff(null);
          setCompareB(null);
        }
      });
    return () => {
      stale = true;
    };
  }, [compare]);

  const mode: TimeMode =
    compare != null
      ? { kind: "compare", ...compare }
      : at != null
        ? { kind: "at", at }
        : { kind: "live" };

  // Source display graph per mode/view.
  const display: DisplayGraph = useMemo(() => {
    if (mode.kind === "compare") {
      if (diff && compareB) return fromDiff(diff, compareB);
      return { nodes: [], edges: [] };
    }
    if (mode.kind === "at") {
      if (view === "raw") {
        return replayRaw ? fromRaw(replayRaw) : { nodes: [], edges: [] };
      }
      return replayApp ? fromApp(replayApp) : { nodes: [], edges: [] };
    }
    if (!payload) return { nodes: [], edges: [] };
    return view === "raw" ? fromRaw(payload.raw) : fromApp(payload.app);
  }, [mode.kind, view, payload, replayRaw, replayApp, diff, compareB]);

  const filtered = useMemo(
    () =>
      view === "app"
        ? applyFilters(display, { showSystem, query: "" })
        : display,
    [display, showSystem, view],
  );

  // Focus only applies while the focused node is on screen; a node id
  // from another view or era must not dim the whole graph.
  const focusSets = useMemo(() => {
    if (focusId == null) return null;
    if (!filtered.nodes.some((n) => n.id === focusId)) return null;
    return computeFocus(filtered, focusId);
  }, [filtered, focusId]);

  const refTimeMs =
    mode.kind === "live"
      ? Date.now()
      : mode.kind === "at"
        ? mode.at * 1000
        : mode.b * 1000;

  const onScrub = useCallback(
    (t: number) => {
      if (pinnedA != null && at != null && t !== pinnedA) {
        setCompare({ a: pinnedA, b: t });
        setPinnedA(null);
        setAt(null);
        setSelection(null);
        return;
      }
      setAt(t);
      setCompare(null);
    },
    [pinnedA, at],
  );

  const onLive = useCallback(() => {
    setAt(null);
    setCompare(null);
    setPinnedA(null);
  }, []);

  // Node/edge ids differ between the two views, so a selection or focus
  // cannot survive a view switch.
  const switchView = useCallback((v: ViewMode) => {
    setView(v);
    setSelection(null);
    setFocusId(null);
  }, []);

  const statusLabel =
    mode.kind === "live"
      ? STATUS_LABEL[status]
      : mode.kind === "at"
        ? "replay"
        : "compare";

  return (
    <div className="app">
      <header className="header">
        <span className="wordmark">
          <span className="mark">◇</span>SIKUR ATLAS
        </span>
        <span className="seg" data-testid="seg-view">
          <button
            className={view === "app" ? "on" : ""}
            onClick={() => switchView("app")}
            data-testid="btn-view-app"
          >
            Services
          </button>
          <button
            className={view === "raw" ? "on" : ""}
            onClick={() => switchView("raw")}
            data-testid="btn-view-raw"
          >
            Raw
          </button>
        </span>
        <span className="seg" data-testid="seg-layout">
          <button
            className={layout === "overview" ? "on" : ""}
            onClick={() => setLayout("overview")}
            data-testid="btn-layout-overview"
          >
            Overview
          </button>
          <button
            className={layout === "explore" ? "on" : ""}
            onClick={() => setLayout("explore")}
            data-testid="btn-layout-explore"
          >
            Explore
          </button>
        </span>
        {view === "app" && (
          <label className="sys-toggle">
            <input
              type="checkbox"
              checked={showSystem}
              onChange={(e) => setShowSystem(e.target.checked)}
              data-testid="chk-system"
            />
            system
          </label>
        )}
        <span className="spacer" />
        <input
          className="search"
          type="search"
          placeholder="Filter nodes…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter nodes"
        />
        <span className="counts" data-testid="counts">
          {filtered.nodes.length} nodes · {filtered.edges.length} edges
        </span>
        <span
          className={`status ${mode.kind === "live" ? status : "replay"}`}
          data-testid="status"
        >
          <span className="dot" />
          {statusLabel}
        </span>
      </header>

      <main className="main">
        <GraphCanvas
          graph={filtered}
          layout={layout}
          selection={selection}
          onSelect={setSelection}
          query={query}
          focus={focusSets}
          refTimeMs={refTimeMs}
        />
        <Inspector
          graph={filtered}
          selection={selection}
          onSelect={setSelection}
          meta={meta}
          mode={mode}
          diff={mode.kind === "compare" ? diff : null}
          focus={focusId}
          onFocus={setFocusId}
          onShowRaw={(q) => {
            switchView("raw");
            setQuery(q);
          }}
          rawView={view === "raw"}
        />
      </main>

      <Timeline
        mode={mode}
        pinnedA={pinnedA}
        historyEnabled={meta?.history ?? true}
        onScrub={onScrub}
        onLive={onLive}
        onPinA={() => setPinnedA(at)}
        onClearCompare={() => {
          setCompare(null);
          setSelection(null);
        }}
      />

      <footer className="footer">
        <span>agent {meta?.version ?? "–"}</span>
        <span>{meta?.kernel ?? ""}</span>
        <span>
          events {formatCount(meta?.collector?.events ?? 0)} · open{" "}
          {formatCount(meta?.collector?.openEvents ?? 0)} · close{" "}
          {formatCount(meta?.collector?.closeEvents ?? 0)} · failed{" "}
          {formatCount(meta?.collector?.failedConns ?? 0)}
        </span>
        {(meta?.kernelDrops ?? 0) > 0 && (
          <span className="warn">ring buffer drops: {meta?.kernelDrops}</span>
        )}
        {(meta?.decodeErrors ?? 0) > 0 && (
          <span className="warn">decode errors: {meta?.decodeErrors}</span>
        )}
      </footer>
    </div>
  );
}
