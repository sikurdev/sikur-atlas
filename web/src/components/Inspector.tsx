import { useEffect, useState } from "react";

import {
  fetchCompare,
  fetchLifecycle,
  type Diff,
  type EdgeChange,
  type LifeEvent,
  type MetaData,
} from "../api";
import type { DisplayEdge, DisplayGraph, DisplayNode } from "../display";
import { formatAgo, formatBytes, formatCount, formatRTT, shortExe } from "../format";
import type { Selection } from "../selection";
import type { TimeMode } from "./Timeline";
import { Legend } from "./Legend";

interface Props {
  graph: DisplayGraph;
  selection: Selection | null;
  onSelect: (sel: Selection | null) => void;
  meta: MetaData | null;
  mode: TimeMode;
  diff: Diff | null;
  focus: string | null;
  onFocus: (id: string | null) => void;
  onShowRaw: (query: string) => void;
  rawView: boolean;
}

const KIND_TITLES: Record<string, string> = {
  compose: "compose service",
  container: "container",
  process: "host process",
  external: "external endpoints",
};

// A TCP edge is named by its server port; an AF_UNIX edge has no port,
// and rendering ":0" would be invented information.
function portSuffix(e: { protocol?: string; dstPort: number }): string {
  return e.protocol === "unix" ? " · unix" : `:${e.dstPort}`;
}

function edgeWhere(e: { protocol?: string; dstPort: number }): string {
  return e.protocol === "unix" ? "unix socket" : `:${e.dstPort}`;
}

export function Inspector(props: Props) {
  const { graph, selection, diff, meta } = props;

  if (selection?.type === "node") {
    const node = graph.nodes.find((n) => n.id === selection.id);
    if (node) {
      return (
        <aside className="inspector" data-testid="inspector-node">
          <NodeDetails node={node} {...props} />
        </aside>
      );
    }
  }
  if (selection?.type === "edge") {
    const edge = graph.edges.find((e) => e.id === selection.id);
    if (edge) {
      return (
        <aside className="inspector" data-testid="inspector-edge">
          <EdgeDetails edge={edge} {...props} />
        </aside>
      );
    }
  }
  if (diff != null) {
    return (
      <aside className="inspector" data-testid="inspector-diff">
        <DiffPanel diff={diff} onSelect={props.onSelect} />
      </aside>
    );
  }

  return (
    <aside className="inspector" data-testid="inspector-empty">
      <Legend />
      {meta && (
        <>
          <h3>agent</h3>
          <dl>
            <dt>events</dt>
            <dd>{formatCount(meta.collector?.events ?? 0)}</dd>
            <dt>failed conns</dt>
            <dd>{formatCount(meta.collector?.failedConns ?? 0)}</dd>
            <dt>retransmits</dt>
            <dd>{formatCount(meta.collector?.retransEvents ?? 0)}</dd>
            <dt>resets</dt>
            <dd>{formatCount(meta.collector?.resetEvents ?? 0)}</dd>
            <dt>ring drops</dt>
            <dd>{meta.kernelDrops}</dd>
            <dt>history</dt>
            <dd>{meta.history ? "recording" : "off"}</dd>
            <dt>docker names</dt>
            <dd>{meta.dockerEnrichment ? "on" : "off"}</dd>
          </dl>
        </>
      )}
    </aside>
  );
}

function healthChips(e: DisplayEdge): string {
  const w = e.window;
  const parts: string[] = [];
  if (w) {
    parts.push(`${formatCount(w.opens)}/${w.seconds}s`);
    if (w.rttAvgUs > 0) parts.push(formatRTT(w.rttAvgUs));
    if (w.failures > 0) parts.push(`${w.failures} fail`);
    if (w.resets > 0) parts.push(`${w.resets} rst`);
  } else {
    parts.push(`${formatCount(e.connections)} conn`);
    if (e.rttAvgUs > 0) parts.push(formatRTT(e.rttAvgUs));
    if (e.failures > 0) parts.push(`${e.failures} fail`);
  }
  return parts.join(" · ");
}

function NodeDetails({
  node,
  graph,
  onSelect,
  mode,
  focus,
  onFocus,
  onShowRaw,
  rawView,
}: Props & { node: DisplayNode }) {
  const outgoing = graph.edges.filter((e) => e.src === node.id);
  const incoming = graph.edges.filter((e) => e.dst === node.id);
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  // The compare endpoint speaks service ids, so the digest only makes
  // sense in the services view.
  const changes = useRecentChanges(node.id, mode, !rawView);
  const metrics = node.raw?.metrics ?? node.app?.metrics ?? null;
  const life = useNodeLifecycle(node, mode);

  const raw = node.raw;
  const app = node.app;

  return (
    <>
      <h2>{node.label}</h2>
      <div className="kind-tag">
        {KIND_TITLES[node.symbol] ?? node.symbol}
        {node.category === "system" && " · system"}
        {node.category === "atlas" && " · atlas itself"}
        {node.diff === "added" && " · added"}
        {node.diff === "removed" && " · removed"}
      </div>

      <div className="actions">
        <button
          className={`pill ${focus === node.id ? "on" : ""}`}
          onClick={() => onFocus(focus === node.id ? null : node.id)}
          data-testid="btn-focus"
        >
          {focus === node.id ? "Unfocus" : "Focus"}
        </button>
        {!rawView && (
          <button
            className="pill"
            onClick={() => onShowRaw(node.label)}
            data-testid="btn-raw"
          >
            Raw connections
          </button>
        )}
      </div>

      <dl>
        {app && app.memberCount > 1 && (
          <>
            <dt>members</dt>
            <dd>{app.memberCount}</dd>
          </>
        )}
        {(app?.image || raw?.image) && (
          <>
            <dt>image</dt>
            <dd>{app?.image || raw?.image}</dd>
          </>
        )}
        {(app?.exe || raw?.exe) && (
          <>
            <dt>executable</dt>
            <dd title={app?.exe || raw?.exe}>{shortExe(app?.exe || raw?.exe || "")}</dd>
          </>
        )}
        {raw?.containerId && (
          <>
            <dt>container id</dt>
            <dd>{raw.containerId.slice(0, 12)}</dd>
          </>
        )}
        {raw?.pids && raw.pids.length > 0 && (
          <>
            <dt>pids</dt>
            <dd>{raw.pids.join(", ")}</dd>
          </>
        )}
        {node.listenPorts.length > 0 && (
          <>
            <dt>listening</dt>
            <dd>{node.listenPorts.map((p) => `:${p}`).join(" ")}</dd>
          </>
        )}
        {raw?.addrs && raw.addrs.length > 0 && (
          <>
            <dt>addresses</dt>
            <dd>{raw.addrs.join(", ")}</dd>
          </>
        )}
        {(raw ?? app) && (
          <>
            <dt>first seen</dt>
            <dd>{formatAgo((raw ?? app)!.firstSeen)}</dd>
            <dt>last seen</dt>
            <dd>{formatAgo((raw ?? app)!.lastSeen)}</dd>
          </>
        )}
      </dl>

      {metrics && metrics.windowSecs > 0 && (
        <>
          <h3>resources (last {metrics.windowSecs}s)</h3>
          <dl data-testid="node-resources">
            <dt>cpu</dt>
            <dd>
              {((metrics.cpuMillis / 1000 / metrics.windowSecs) * 100).toFixed(1)}%
              {metrics.throttledUs > 0 &&
                ` · throttled ${(metrics.throttledUs / 1000).toFixed(0)}ms`}
            </dd>
            <dt>memory</dt>
            <dd className={metrics.oomKills > 0 ? "trouble" : ""}>
              {formatBytes(metrics.rssBytes)}
              {metrics.memLimit > 0 && ` / ${formatBytes(metrics.memLimit)}`}
              {metrics.oomKills > 0 && ` · ${metrics.oomKills} OOM kill${metrics.oomKills > 1 ? "s" : ""}`}
            </dd>
            <dt>disk io</dt>
            <dd>
              {formatBytes(metrics.ioReadBytes)} r / {formatBytes(metrics.ioWriteBytes)} w
            </dd>
            <dt>procs</dt>
            <dd>
              {metrics.procs} · {metrics.threads} thr · {metrics.fds} fds
            </dd>
            {((metrics.psiCpuSomePct ?? 0) > 0 || (metrics.psiMemSomePct ?? 0) > 0) && (
              <>
                <dt>pressure</dt>
                <dd>
                  cpu {(metrics.psiCpuSomePct ?? 0).toFixed(1)}% · mem{" "}
                  {(metrics.psiMemSomePct ?? 0).toFixed(1)}%
                </dd>
              </>
            )}
          </dl>
        </>
      )}

      {outgoing.length > 0 && (
        <>
          <h3>depends on</h3>
          <ul className="edge-list" data-testid="deps-out">
            {outgoing.map((e) => (
              <li key={e.id}>
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "edge", id: e.id })}
                >
                  <span className={`edge-peer ${e.failures > 0 || (e.window?.failures ?? 0) > 0 ? "trouble" : ""}`}>
                    {nodesById.get(e.dst)?.label ?? e.dst}
                    {portSuffix(e)}
                  </span>{" "}
                  <span className="edge-stats">{healthChips(e)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      {incoming.length > 0 && (
        <>
          <h3>called by</h3>
          <ul className="edge-list" data-testid="deps-in">
            {incoming.map((e) => (
              <li key={e.id}>
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "edge", id: e.id })}
                >
                  <span className="edge-peer">
                    {nodesById.get(e.src)?.label ?? e.src}
                  </span>{" "}
                  <span className="edge-stats">{healthChips(e)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}

      {life != null && life.length > 0 && (
        <>
          <h3>lifecycle (last 15 min)</h3>
          <ul className="change-list" data-testid="node-lifecycle">
            {life.map((ev, i) => (
              <li
                key={i}
                className={ev.kind === "oom" || ev.kind === "crash" ? "warn" : ""}
              >
                {new Date(ev.time).toLocaleTimeString()} {ev.kind} — {ev.detail}
              </li>
            ))}
          </ul>
        </>
      )}

      {changes != null && changes.length > 0 && (
        <>
          <h3>changes (last 10 min)</h3>
          <ul className="change-list" data-testid="node-changes">
            {changes.map((c, i) => (
              <li key={i} className={c.tone}>
                {c.text}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

/** Recent lifecycle events for a node: raw nodes match directly, app
 * nodes match through their members. Live mode only (replay uses
 * Compare's lifecycle section). */
function useNodeLifecycle(node: DisplayNode, mode: TimeMode): LifeEvent[] | null {
  const [events, setEvents] = useState<LifeEvent[] | null>(null);
  const members = node.app ? node.app.members.join(",") : node.id;
  useEffect(() => {
    if (mode.kind !== "live") {
      setEvents(null);
      return;
    }
    let stopped = false;
    const now = Math.floor(Date.now() / 1000);
    fetchLifecycle(now - 900, now)
      .then((res) => {
        if (stopped) return;
        const ids = new Set(members.split(","));
        const mine = (res.events ?? []).filter((e) => ids.has(e.node));
        setEvents(mine.slice(-8).reverse());
      })
      .catch(() => setEvents(null));
    return () => {
      stopped = true;
    };
  }, [members, mode.kind]);
  return events;
}

interface ChangeLine {
  text: string;
  tone: "add" | "remove" | "warn";
}

/** In live services view, a small deterministic "what changed recently"
 * digest for the selected node, computed by the compare endpoint. */
function useRecentChanges(
  nodeID: string,
  mode: TimeMode,
  enabled: boolean,
): ChangeLine[] | null {
  const [lines, setLines] = useState<ChangeLine[] | null>(null);
  useEffect(() => {
    if (mode.kind !== "live" || !enabled) {
      setLines(null);
      return;
    }
    let stopped = false;
    const now = Math.floor(Date.now() / 1000);
    fetchCompare(now - 600, now)
      .then((d) => {
        if (stopped) return;
        const out: ChangeLine[] = [];
        const touches = (src: string, dst: string) =>
          src === nodeID || dst === nodeID;
        for (const n of d.addedNodes ?? []) {
          if (n.id === nodeID) {
            out.push({ text: "+ appeared in this window", tone: "add" });
          }
        }
        for (const e of d.addedEdges ?? []) {
          if (touches(e.src, e.dst)) {
            out.push({ text: `+ edge → ${edgeWhere(e)}`, tone: "add" });
          }
        }
        for (const e of d.removedEdges ?? []) {
          if (touches(e.src, e.dst)) {
            out.push({ text: `− edge → ${edgeWhere(e)}`, tone: "remove" });
          }
        }
        for (const c of d.changedEdges ?? []) {
          if (touches(c.edge.src, c.edge.dst)) {
            out.push({
              text: `~ ${edgeWhere(c.edge)} ${c.changes.join(", ")}`,
              tone: "warn",
            });
          }
        }
        setLines(out.slice(0, 8));
      })
      .catch(() => setLines(null));
    return () => {
      stopped = true;
    };
  }, [nodeID, mode.kind, enabled]);
  return lines;
}

function EdgeDetails({ edge, graph }: Props & { edge: DisplayEdge }) {
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const w = edge.window;
  return (
    <>
      <h2>
        {nodesById.get(edge.src)?.label ?? edge.src} →{" "}
        {nodesById.get(edge.dst)?.label ?? edge.dst}
      </h2>
      <div className="kind-tag" data-testid="edge-kind">
        {edge.protocol === "unix"
          ? `unix socket · ${edge.path ?? ""}`
          : `observed communication · ${edge.protocol || "tcp"} :${edge.dstPort}`}
        {edge.diff ? ` · ${edge.diff}` : ""}
      </div>

      <h3>{w ? `last ${w.seconds}s` : "totals"}</h3>
      <dl data-testid="edge-health">
        <dt>connections</dt>
        <dd>{formatCount(w ? w.opens : edge.connections)}</dd>
        <dt>active now</dt>
        <dd>{edge.activeConns}</dd>
        <dt>failed</dt>
        <dd className={(w ? w.failures : edge.failures) > 0 ? "trouble" : ""}>
          {w ? w.failures : edge.failures}
        </dd>
        <dt>resets</dt>
        <dd>{w ? w.resets : edge.resets}</dd>
        <dt>retransmits</dt>
        <dd>{w ? w.retransmits : edge.retransmits}</dd>
        <dt>rtt avg</dt>
        <dd>{formatRTT(w ? w.rttAvgUs : edge.rttAvgUs)}</dd>
        {w && (
          <>
            <dt>rtt max</dt>
            <dd>{formatRTT(w.rttMaxUs)}</dd>
          </>
        )}
        <dt>bytes →</dt>
        <dd>{formatBytes(w ? w.bytesSent : edge.raw?.bytesSent ?? 0)}</dd>
        <dt>bytes ←</dt>
        <dd>{formatBytes(w ? w.bytesRecv : edge.raw?.bytesRecv ?? 0)}</dd>
      </dl>

      {edge.raw && (
        <>
          <h3>lifetime</h3>
          <dl>
            <dt>connections</dt>
            <dd>{formatCount(edge.raw.connections)}</dd>
            <dt>failed</dt>
            <dd>{edge.raw.failures ?? 0}</dd>
            <dt>bytes</dt>
            <dd>
              {formatBytes(edge.raw.bytesSent)} / {formatBytes(edge.raw.bytesRecv)}
            </dd>
            <dt>first seen</dt>
            <dd>{formatAgo(edge.raw.firstSeen)}</dd>
            <dt>last seen</dt>
            <dd>{formatAgo(edge.raw.lastSeen)}</dd>
          </dl>
        </>
      )}

      {edge.app && edge.app.rawEdges.length > 0 && (
        <>
          <h3>raw connections</h3>
          <ul className="edge-list">
            {edge.app.rawEdges.map((id) => (
              <li key={id} className="raw-edge-id">
                {id}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="legend-note">
        Bytes and final RTT are reported when connections close;
        retransmits and resets are counted live. Failed = connects that
        never established.
      </p>
    </>
  );
}

function DiffPanel({
  diff,
  onSelect,
}: {
  diff: Diff;
  onSelect: (sel: Selection | null) => void;
}) {
  const added = diff.addedNodes ?? [];
  const removed = diff.removedNodes ?? [];
  const addedE = diff.addedEdges ?? [];
  const removedE = diff.removedEdges ?? [];
  const changed = diff.changedEdges ?? [];
  const changedN = diff.changedNodes ?? [];
  const lifecycle = diff.lifecycle ?? [];
  const empty =
    added.length + removed.length + addedE.length + removedE.length +
      changed.length + changedN.length + lifecycle.length === 0;

  return (
    <>
      <h2>What changed</h2>
      <div className="kind-tag">
        {new Date(diff.a).toLocaleTimeString()} →{" "}
        {new Date(diff.b).toLocaleTimeString()}
      </div>
      {empty && (
        <p className="legend-note" data-testid="diff-empty">
          No topology or health changes between these two moments.
        </p>
      )}
      {removed.length > 0 && (
        <>
          <h3>removed</h3>
          <ul className="change-list" data-testid="diff-removed">
            {removed.map((n) => (
              <li key={n.id} className="remove">
                <button className="linkish" onClick={() => onSelect({ type: "node", id: n.id })}>
                  − {n.label}
                </button>
              </li>
            ))}
            {removedE.map((e) => (
              <li key={e.id} className="remove">
                <button className="linkish" onClick={() => onSelect({ type: "edge", id: e.id })}>
                  − {e.src.split(":").pop()} → {e.dst.split(":").pop()}
                  {portSuffix(e)}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      {added.length > 0 || addedE.length > 0 ? (
        <>
          <h3>added</h3>
          <ul className="change-list" data-testid="diff-added">
            {added.map((n) => (
              <li key={n.id} className="add">
                <button className="linkish" onClick={() => onSelect({ type: "node", id: n.id })}>
                  + {n.label}
                </button>
              </li>
            ))}
            {addedE.map((e) => (
              <li key={e.id} className="add">
                <button className="linkish" onClick={() => onSelect({ type: "edge", id: e.id })}>
                  + {e.src.split(":").pop()} → {e.dst.split(":").pop()}
                  {portSuffix(e)}
                </button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {changed.length > 0 && (
        <>
          <h3>changed</h3>
          <ul className="change-list" data-testid="diff-changed">
            {changed.map((c: EdgeChange) => (
              <li key={c.edge.id} className="warn">
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "edge", id: c.edge.id })}
                >
                  ~ {c.edge.src.split(":").pop()} → {c.edge.dst.split(":").pop()}
                  {portSuffix(c.edge)} · {c.changes.join(", ")}
                  {c.changes.includes("failures") &&
                    ` (${c.aFailures} → ${c.edge.failures ?? 0})`}
                  {c.changes.includes("rtt") &&
                    ` (${formatRTT(c.aRttAvgUs)} → ${formatRTT(c.edge.window?.rttAvgUs ?? 0)})`}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      {changedN.length > 0 && (
        <>
          <h3>resources moved</h3>
          <ul className="change-list" data-testid="diff-resources">
            {changedN.map((c) => (
              <li key={c.node.id} className="warn">
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "node", id: c.node.id })}
                >
                  ~ {c.node.label} · {c.changes.join(", ")}
                  {c.changes.includes("rss") &&
                    ` (${formatBytes(c.aRssBytes)} → ${formatBytes(c.node.metrics?.rssBytes ?? 0)})`}
                  {c.changes.includes("cpu") &&
                    ` (cpu ${c.aCpuMillis}ms → ${c.node.metrics?.cpuMillis ?? 0}ms)`}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      {lifecycle.length > 0 && (
        <>
          <h3>lifecycle</h3>
          <ul className="change-list" data-testid="diff-lifecycle">
            {lifecycle.map((e, i) => (
              <li
                key={i}
                className={e.kind === "oom" || e.kind === "crash" ? "warn" : ""}
              >
                {new Date(e.time).toLocaleTimeString()} {e.label} · {e.kind}
                {e.detail ? ` — ${e.detail}` : ""}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="legend-note">
        Every entry is computed from recorded connection, lifecycle and
        resource evidence; nothing here is inferred or guessed.
      </p>
    </>
  );
}
