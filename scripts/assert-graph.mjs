#!/usr/bin/env node
// Asserts that a running Atlas agent has discovered the demo topology
// from real traffic. Exits non-zero with diagnostics on failure; prints
// the discovered graph as evidence on success.
const base = process.argv[2] ?? "http://127.0.0.1:7171";

const graph = await getJSON(`${base}/api/graph`);
const meta = await getJSON(`${base}/api/meta`);

// Map demo container names to node ids. Enrichment fills containerName
// asynchronously; fall back to matching the label.
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

const failures = [];
const found = [];

for (const name of new Set(expectedEdges.flatMap(([a, b]) => [a, b]))) {
  if (!byName.has(name)) failures.push(`node missing: ${name}`);
}

let edgesWithBytes = 0;
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
  if (edge.bytesSent > 0 || edge.bytesRecv > 0) edgesWithBytes++;
  found.push(
    `${srcName} -> ${dstName}:${port}  conns=${edge.connections} ` +
      `active=${edge.activeConns} bytes=${edge.bytesSent}/${edge.bytesRecv}`,
  );
}

if (edgesWithBytes === 0 && failures.length === 0) {
  failures.push("no expected edge accumulated byte counters");
}

console.log("== agent meta ==");
console.log(JSON.stringify(meta, null, 2));
console.log("== discovered demo edges ==");
for (const line of found) console.log("  " + line);
console.log(
  `== full graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges ==`,
);
console.log(JSON.stringify(graph, null, 2));

if (failures.length > 0) {
  console.error("\nE2E FAILURES:");
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log(`\nE2E OK: all ${expectedEdges.length} expected edges observed, ` +
  `${edgesWithBytes} with byte counters`);

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
