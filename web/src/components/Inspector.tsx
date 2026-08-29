import type { GraphSnapshot, MetaData, NodeData } from "../api";
import { formatAgo, formatBytes, formatCount, shortExe } from "../format";
import type { Selection } from "../selection";
import { Legend } from "./Legend";

interface Props {
  snapshot: GraphSnapshot | null;
  meta: MetaData | null;
  selection: Selection | null;
  onSelect: (sel: Selection | null) => void;
}

const KIND_TITLES = {
  process: "host process",
  container: "container",
  external: "external endpoint",
} as const;

export function Inspector({ snapshot, meta, selection, onSelect }: Props) {
  const nodes = new Map((snapshot?.nodes ?? []).map((n) => [n.id, n]));
  const edges = snapshot?.edges ?? [];

  if (selection?.type === "node") {
    const node = nodes.get(selection.id);
    if (node) {
      return (
        <aside className="inspector" data-testid="inspector-node">
          <NodeDetails
            node={node}
            snapshot={snapshot!}
            onSelect={onSelect}
          />
        </aside>
      );
    }
  }
  if (selection?.type === "edge") {
    const edge = edges.find((e) => e.id === selection.id);
    if (edge) {
      const src = nodes.get(edge.src);
      const dst = nodes.get(edge.dst);
      return (
        <aside className="inspector" data-testid="inspector-edge">
          <h2>
            {src?.label ?? edge.src} → {dst?.label ?? edge.dst}
          </h2>
          <div className="kind-tag">
            observed communication · {edge.protocol} :{edge.dstPort}
          </div>
          <dl>
            <dt>connections</dt>
            <dd>{formatCount(edge.connections)}</dd>
            <dt>active now</dt>
            <dd>{edge.activeConns}</dd>
            <dt>bytes →</dt>
            <dd>{formatBytes(edge.bytesSent)}</dd>
            <dt>bytes ←</dt>
            <dd>{formatBytes(edge.bytesRecv)}</dd>
            <dt>first seen</dt>
            <dd>{formatAgo(edge.firstSeen)}</dd>
            <dt>last seen</dt>
            <dd>{formatAgo(edge.lastSeen)}</dd>
          </dl>
          <p className="legend-note">
            Byte counters accumulate when connections close; long-lived
            connections report on teardown.
          </p>
        </aside>
      );
    }
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
            <dt>live sockets</dt>
            <dd>{meta.collector?.liveSockets ?? 0}</dd>
            <dt>ring drops</dt>
            <dd>{meta.kernelDrops}</dd>
            <dt>docker names</dt>
            <dd>{meta.dockerEnrichment ? "on" : "off"}</dd>
          </dl>
        </>
      )}
    </aside>
  );
}

function NodeDetails({
  node,
  snapshot,
  onSelect,
}: {
  node: NodeData;
  snapshot: GraphSnapshot;
  onSelect: (sel: Selection | null) => void;
}) {
  const nodesById = new Map(snapshot.nodes.map((n) => [n.id, n]));
  const outgoing = snapshot.edges.filter((e) => e.src === node.id);
  const incoming = snapshot.edges.filter((e) => e.dst === node.id);

  return (
    <>
      <h2>{node.label}</h2>
      <div className="kind-tag">{KIND_TITLES[node.kind]}</div>
      <dl>
        {node.containerName && (
          <>
            <dt>container</dt>
            <dd>{node.containerName}</dd>
          </>
        )}
        {node.image && (
          <>
            <dt>image</dt>
            <dd>{node.image}</dd>
          </>
        )}
        {node.containerId && (
          <>
            <dt>id</dt>
            <dd>{node.containerId.slice(0, 12)}</dd>
          </>
        )}
        {node.exe && (
          <>
            <dt>executable</dt>
            <dd title={node.exe}>{shortExe(node.exe)}</dd>
          </>
        )}
        {node.pids && node.pids.length > 0 && (
          <>
            <dt>pids</dt>
            <dd>{node.pids.join(", ")}</dd>
          </>
        )}
        {node.listenPorts && node.listenPorts.length > 0 && (
          <>
            <dt>listening</dt>
            <dd>{node.listenPorts.map((p) => `:${p}`).join(" ")}</dd>
          </>
        )}
        {node.addrs && node.addrs.length > 0 && (
          <>
            <dt>addresses</dt>
            <dd>{node.addrs.join(", ")}</dd>
          </>
        )}
        <dt>first seen</dt>
        <dd>{formatAgo(node.firstSeen)}</dd>
        <dt>last seen</dt>
        <dd>{formatAgo(node.lastSeen)}</dd>
      </dl>

      {outgoing.length > 0 && (
        <>
          <h3>talks to</h3>
          <ul className="edge-list">
            {outgoing.map((e) => (
              <li key={e.id}>
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "edge", id: e.id })}
                >
                  <span className="edge-peer">
                    {nodesById.get(e.dst)?.label ?? e.dst}
                  </span>{" "}
                  <span className="edge-stats">
                    :{e.dstPort} · {formatCount(e.connections)} conn ·{" "}
                    {formatBytes(e.bytesSent + e.bytesRecv)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      {incoming.length > 0 && (
        <>
          <h3>called by</h3>
          <ul className="edge-list">
            {incoming.map((e) => (
              <li key={e.id}>
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "edge", id: e.id })}
                >
                  <span className="edge-peer">
                    {nodesById.get(e.src)?.label ?? e.src}
                  </span>{" "}
                  <span className="edge-stats">
                    :{e.dstPort} · {formatCount(e.connections)} conn ·{" "}
                    {formatBytes(e.bytesSent + e.bytesRecv)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}
