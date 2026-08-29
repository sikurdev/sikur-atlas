// Types mirroring the Go API, plus the live stream hook and fetchers.
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
  composeProject?: string;
  composeService?: string;
  pids?: number[];
  listenPorts?: number[];
  addrs?: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface EdgeWindow {
  seconds: number;
  opens: number;
  closes: number;
  failures: number;
  resets: number;
  retransmits: number;
  bytesSent: number;
  bytesRecv: number;
  rttAvgUs: number;
  rttMaxUs: number;
  activeEnd: number;
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
  failures?: number;
  resets?: number;
  retransmits?: number;
  lastRttUs?: number;
  firstSeen: string;
  lastSeen: string;
  window?: EdgeWindow;
}

export interface GraphSnapshot {
  version: number;
  generatedAt: string;
  nodes: NodeData[];
  edges: EdgeData[];
}

export type AppCategory = "app" | "system" | "external" | "atlas";

export interface AppNode {
  id: string;
  label: string;
  category: AppCategory;
  kind: "compose" | "container" | "process" | "external";
  members: string[];
  memberCount: number;
  image?: string;
  exe?: string;
  listenPorts?: number[];
  firstSeen: string;
  lastSeen: string;
}

export interface AppEdge {
  id: string;
  src: string;
  dst: string;
  dstPort: number;
  protocol: string;
  connections: number;
  activeConns: number;
  bytesSent: number;
  bytesRecv: number;
  failures?: number;
  resets?: number;
  retransmits?: number;
  lastRttUs?: number;
  firstSeen: string;
  lastSeen: string;
  window?: EdgeWindow;
  rawEdges: string[];
}

export interface AppGraph {
  generatedAt: string;
  nodes: AppNode[];
  edges: AppEdge[];
}

export interface EdgeChange {
  edge: AppEdge;
  changes: string[];
  aConnections: number;
  aFailures: number;
  aResets: number;
  aRetransmits: number;
  aRttAvgUs: number;
  aBytesSent: number;
  aBytesRecv: number;
}

export interface Diff {
  a: string;
  b: string;
  addedNodes: AppNode[] | null;
  removedNodes: AppNode[] | null;
  addedEdges: AppEdge[] | null;
  removedEdges: AppEdge[] | null;
  changedEdges: EdgeChange[] | null;
}

export interface TimelineBucket {
  start: number;
  opens: number;
  closes: number;
  failures: number;
  trouble: number;
}

export interface TimelinePayload {
  from: number;
  to: number;
  step: number;
  buckets: TimelineBucket[];
}

export interface CollectorStats {
  events: number;
  openEvents: number;
  acceptEvents: number;
  establishedEvents: number;
  closeEvents: number;
  retransEvents: number;
  resetEvents: number;
  failedConns: number;
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
  history: boolean;
}

export interface StreamPayload {
  raw: GraphSnapshot;
  app: AppGraph;
}

export type StreamStatus = "connecting" | "live" | "reconnecting";

export interface GraphStream {
  payload: StreamPayload | null;
  status: StreamStatus;
}

/** Subscribes to /api/stream. The EventSource factory is injectable for
 * tests. */
export function useGraphStream(
  makeSource: () => EventSource = () => new EventSource("/api/stream"),
): GraphStream {
  const [payload, setPayload] = useState<StreamPayload | null>(null);
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const makeSourceRef = useRef(makeSource);

  useEffect(() => {
    const source = makeSourceRef.current();
    const onSnapshot = (ev: MessageEvent) => {
      setStatus("live");
      setPayload(JSON.parse(ev.data) as StreamPayload);
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

  return { payload, status };
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

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return (await res.json()) as T;
}

export function fetchGraphAt(at: number): Promise<GraphSnapshot> {
  return getJSON(`/api/graph?at=${at}`);
}

export function fetchAppViewAt(at: number): Promise<AppGraph> {
  return getJSON(`/api/appview?at=${at}`);
}

export function fetchCompare(a: number, b: number): Promise<Diff> {
  return getJSON(`/api/compare?a=${a}&b=${b}`);
}

export function fetchTimeline(from: number, to: number, step: number): Promise<TimelinePayload> {
  return getJSON(`/api/timeline?from=${from}&to=${to}&step=${step}`);
}
