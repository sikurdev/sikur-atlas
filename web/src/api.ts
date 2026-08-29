// Types mirroring internal/graph JSON, plus the live stream hook.
import { useEffect, useRef, useState } from "react";

export type NodeKind = "process" | "container" | "external";

export interface NodeData {
  id: string;
  kind: NodeKind;
  label: string;
  exe?: string;
  containerId?: string;
  containerName?: string;
  image?: string;
  pids?: number[];
  listenPorts?: number[];
  addrs?: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface EdgeData {
  id: string;
  src: string;
  dst: string;
  dstPort: number;
  protocol: string;
  connections: number;
  activeConns: number;
  bytesSent: number;
  bytesRecv: number;
  firstSeen: string;
  lastSeen: string;
}

export interface GraphSnapshot {
  version: number;
  generatedAt: string;
  nodes: NodeData[];
  edges: EdgeData[];
}

export interface CollectorStats {
  events: number;
  openEvents: number;
  acceptEvents: number;
  establishedEvents: number;
  closeEvents: number;
  liveSockets: number;
  liveRecords: number;
}

export interface MetaData {
  version: string;
  startedAt: string;
  kernel?: string;
  collector: CollectorStats;
  kernelDrops: number;
  decodeErrors: number;
  dockerEnrichment: boolean;
}

export type StreamStatus = "connecting" | "live" | "reconnecting";

export interface GraphStream {
  snapshot: GraphSnapshot | null;
  status: StreamStatus;
}

/** Subscribes to /api/stream. The EventSource factory is injectable for
 * tests. */
export function useGraphStream(
  makeSource: () => EventSource = () => new EventSource("/api/stream"),
): GraphStream {
  const [snapshot, setSnapshot] = useState<GraphSnapshot | null>(null);
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const makeSourceRef = useRef(makeSource);

  useEffect(() => {
    const source = makeSourceRef.current();
    const onSnapshot = (ev: MessageEvent) => {
      setStatus("live");
      setSnapshot(JSON.parse(ev.data) as GraphSnapshot);
    };
    const onOpen = () => setStatus("live");
    const onError = () => setStatus("reconnecting");
    source.addEventListener("snapshot", onSnapshot);
    source.addEventListener("open", onOpen);
    source.addEventListener("error", onError);
    return () => {
      source.close();
    };
  }, []);

  return { snapshot, status };
}

/** Polls /api/meta. */
export function useMeta(intervalMs = 5000): MetaData | null {
  const [meta, setMeta] = useState<MetaData | null>(null);
  useEffect(() => {
    let stopped = false;
    const load = async () => {
      try {
        const res = await fetch("/api/meta");
        if (res.ok && !stopped) setMeta((await res.json()) as MetaData);
      } catch {
        // Backend briefly unreachable; keep the last value.
      }
    };
    void load();
    const t = setInterval(load, intervalMs);
    return () => {
      stopped = true;
      clearInterval(t);
    };
  }, [intervalMs]);
  return meta;
}
