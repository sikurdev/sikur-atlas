import { useState } from "react";

import { useGraphStream, useMeta } from "./api";
import { GraphCanvas } from "./components/GraphCanvas";
import { Inspector } from "./components/Inspector";
import { formatCount } from "./format";
import type { Selection } from "./selection";

const STATUS_LABEL = {
  connecting: "connecting",
  live: "live",
  reconnecting: "reconnecting",
} as const;

export function App({
  makeSource,
}: {
  makeSource?: () => EventSource;
}) {
  const { snapshot, status } = useGraphStream(makeSource);
  const meta = useMeta();
  const [selection, setSelection] = useState<Selection | null>(null);
  const [query, setQuery] = useState("");

  return (
    <div className="app">
      <header className="header">
        <span className="wordmark">
          <span className="mark">◇</span>SIKUR ATLAS
        </span>
        <span className="tagline">service topology from live eBPF</span>
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
          {snapshot ? `${snapshot.nodes.length} nodes · ${snapshot.edges.length} edges` : "–"}
        </span>
        <span className={`status ${status}`} data-testid="status">
          <span className="dot" />
          {STATUS_LABEL[status]}
        </span>
      </header>

      <main className="main">
        <GraphCanvas
          snapshot={snapshot}
          selection={selection}
          onSelect={setSelection}
          query={query}
        />
        <Inspector
          snapshot={snapshot}
          meta={meta}
          selection={selection}
          onSelect={setSelection}
        />
      </main>

      <footer className="footer">
        <span>agent {meta?.version ?? "–"}</span>
        <span>{meta?.kernel ?? ""}</span>
        <span>
          events {formatCount(meta?.collector?.events ?? 0)} · open{" "}
          {formatCount(meta?.collector?.openEvents ?? 0)} · accept{" "}
          {formatCount(meta?.collector?.acceptEvents ?? 0)} · close{" "}
          {formatCount(meta?.collector?.closeEvents ?? 0)}
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
