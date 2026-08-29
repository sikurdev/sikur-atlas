#!/usr/bin/env node
// Phase-1 e2e assertions: a running Atlas agent has discovered the demo
// topology, its health signals, and a clean application view — all from
// real traffic. Exits non-zero with diagnostics on failure.
const base = process.argv[2] ?? "http://127.0.0.1:7171";

const graph = await getJSON(`${base}/api/graph`);
const app = await getJSON(`${base}/api/appview`);
const meta = await getJSON(`${base}/api/meta`);

const failures = [];
const found = [];

// ---- raw topology (v0.1 contract, unchanged) ----
const byName = new Map();
for (const node of graph.nodes) {
  const name = node.containerName || node.label;
  if (name?.startsWith("atlas-demo-")) byName.set(name, node);
}
const expectedEdges = [
  ["atlas-demo-loadgen", "atlas-demo-gateway", 8080],
  ["atlas-demo-gateway", "atlas-demo-orders", 8000],
  ["atlas-demo-gateway", "atlas-demo-users", 8000],
  ["atlas-demo-orders", "atlas-demo-inventory", 8000],
  ["atlas-demo-orders", "atlas-demo-cache", 6379],
  ["atlas-demo-users", "atlas-demo-cache", 6379],
];
for (const name of new Set(expectedEdges.flatMap(([a, b]) => [a, b]))) {
  if (!byName.has(name)) failures.push(`node missing: ${name}`);
}
let edgesWithBytes = 0;
let edgesWithRTT = 0;
for (const [srcName, dstName, port] of expectedEdges) {
  const src = byName.get(srcName);
  const dst = byName.get(dstName);
  if (!src || !dst) continue;
  const edge = graph.edges.find(
    (e) => e.src === src.id && e.dst === dst.id && e.dstPort === port,
  );
  if (!edge) {
    failures.push(`edge missing: ${srcName} -> ${dstName}:${port}`);
    continue;
  }
  if (!(edge.connections >= 1)) {
    failures.push(`edge has no connections: ${srcName} -> ${dstName}:${port}`);
  }
  if (edge.activeConns < 0 || edge.activeConns > edge.connections) {
    failures.push(
      `activeConns out of range on ${srcName} -> ${dstName}:${port}: ` +
        `${edge.activeConns} of ${edge.connections}`,
    );
  }
  if (edge.bytesSent > 0 || edge.bytesRecv > 0) edgesWithBytes++;
  if ((edge.window?.rttAvgUs ?? 0) > 0 || (edge.lastRttUs ?? 0) > 0) edgesWithRTT++;
  if (srcName === "atlas-demo-loadgen" && edge.bytesSent > 0 &&
      edge.bytesRecv <= edge.bytesSent) {
    failures.push(
      `byte direction suspicious on ${srcName} -> ${dstName}: ` +
        `sent=${edge.bytesSent} recv=${edge.bytesRecv}`,
    );
  }
  found.push(
    `${srcName} -> ${dstName}:${port}  conns=${edge.connections} ` +
      `active=${edge.activeConns} bytes=${edge.bytesSent}/${edge.bytesRecv} ` +
      `rtt=${edge.window?.rttAvgUs ?? 0}us fail=${edge.failures ?? 0}`,
  );
}
if (edgesWithBytes < 5 && failures.length === 0) {
  failures.push(`only ${edgesWithBytes} of 6 expected edges have byte counters`);
}

// ---- health signals ----
if (edgesWithRTT < 3) {
  failures.push(`only ${edgesWithRTT} of 6 expected edges carry RTT samples`);
}
// The deliberately broken users -> cache:6380 call must appear as a
// failure edge with zero successful connections.
const users = byName.get("atlas-demo-users");
const cache = byName.get("atlas-demo-cache");
if (users && cache) {
  const broken = graph.edges.find(
    (e) => e.src === users.id && e.dst === cache.id && e.dstPort === 6380,
  );
  if (!broken) {
    failures.push("failure edge users -> cache:6380 missing");
  } else {
    if (!(broken.failures >= 1)) {
      failures.push(`users -> cache:6380 has no failures: ${JSON.stringify(broken)}`);
    }
    if (broken.connections !== 0) {
      failures.push(`refused connects counted as connections: ${JSON.stringify(broken)}`);
    }
    if (!(broken.resets >= 1)) {
      failures.push(`refused connects produced no RST count: ${JSON.stringify(broken)}`);
    }
    found.push(
      `users -> cache:6380 (broken by design)  failures=${broken.failures} resets=${broken.resets}`,
    );
  }
}
if (!(meta.collector?.failedConns >= 1)) {
  failures.push(`collector saw no failed connects: ${JSON.stringify(meta.collector)}`);
}

// ---- application view ----
const appByLabel = new Map(app.nodes.map((n) => [n.label, n]));
for (const svc of ["gateway", "orders", "users", "inventory", "cache", "loadgen"]) {
  const n = appByLabel.get(svc);
  if (!n) {
    failures.push(`app view missing compose service: ${svc}`);
    continue;
  }
  if (n.kind !== "compose" || n.category !== "app") {
    failures.push(`app view misclassified ${svc}: ${n.kind}/${n.category}`);
  }
}
for (const n of app.nodes) {
  if (n.category === "system" && n.label === "dockerd") {
    found.push(`app view: dockerd classified system (hidden by default)`);
  }
}
const appGatewayOrders = app.edges.find(
  (e) =>
    e.src === "svc:compose:atlas-demo/gateway" &&
    e.dst === "svc:compose:atlas-demo/orders",
);
if (!appGatewayOrders) {
  failures.push("app view missing gateway -> orders service edge");
}
// The app view must be materially smaller than the raw view.
if (!(app.nodes.length < graph.nodes.length)) {
  failures.push(
    `app view not cleaner: ${app.nodes.length} service nodes vs ${graph.nodes.length} raw`,
  );
}

if (meta.kernelDrops > 0) failures.push(`ring buffer dropped ${meta.kernelDrops} events`);
if (meta.decodeErrors > 0) failures.push(`${meta.decodeErrors} events failed to decode`);
if (!(meta.collector?.events > 100)) {
  failures.push(`suspiciously few events: ${meta.collector?.events}`);
}

console.log("== agent meta ==");
console.log(JSON.stringify(meta, null, 2));
console.log("== discovered demo edges ==");
for (const line of found) console.log("  " + line);
console.log(
  `== raw: ${graph.nodes.length} nodes/${graph.edges.length} edges; ` +
    `app view: ${app.nodes.length} nodes/${app.edges.length} edges ==`,
);
console.log(JSON.stringify(app, null, 2));

if (failures.length > 0) {
  console.error("\nPHASE-1 FAILURES:");
  for (const f of failures) console.error("  ✗ " + f);
  console.error("\nfull raw graph for diagnosis:");
  console.error(JSON.stringify(graph, null, 2));
  process.exit(1);
}
console.log("\nPHASE 1 OK: topology, health signals and application view all check out");

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
