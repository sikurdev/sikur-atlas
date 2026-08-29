#!/usr/bin/env node
// Mid-run v0.3 assertions: the restart and OOM episodes produced real
// lifecycle evidence, and the memory-pressure climb landed in the
// resource history attributed to the right service.
//
// Usage: node scripts/assert-v3.mjs <base> <t1>
const [base, t1s] = process.argv.slice(2);
const t1 = Number(t1s);
if (!base || !t1) {
  console.error("usage: assert-v3.mjs <base> <t1>");
  process.exit(2);
}
const now = Math.floor(Date.now() / 1000);
const failures = [];

const graph = await getJSON(`${base}/api/graph`);
const nodeByName = (name) =>
  graph.nodes.find((n) => (n.containerName || n.label) === name);

// The users container was OOM-killed and restarted by docker: the
// service must be back (possibly as a new container id).
const users = nodeByName("atlas-demo-users");
const inventory = nodeByName("atlas-demo-inventory");
if (!users) failures.push("users service not back after OOM restart");
if (!inventory) failures.push("inventory service missing after restart");

// Lifecycle evidence recorded since T1.
const life = await getJSON(`${base}/api/lifecycle?from=${t1}&to=${now}`);
const events = life.events ?? [];
const kinds = new Set(events.map((e) => e.kind));
if (!kinds.has("oom")) {
  failures.push(`no OOM event recorded; kinds=${[...kinds]}`);
}
if (!kinds.has("exec")) {
  failures.push(`no exec event recorded (restarts produce them); kinds=${[...kinds]}`);
}
if (!kinds.has("exit")) {
  failures.push(`no exit event recorded; kinds=${[...kinds]}`);
}
const oomEvents = events.filter((e) => e.kind === "oom");
console.log("lifecycle kinds:", [...kinds].join(","), "events:", events.length);
console.log("oom events:", JSON.stringify(oomEvents));

// The RSS climb must be visible in the users service's history. The
// container id may have changed on restart, so check every node whose
// name matches, keeping the maximum observed RSS.
let maxRSS = 0;
for (const n of graph.nodes) {
  if ((n.containerName || n.label) !== "atlas-demo-users") continue;
  const met = await getJSON(
    `${base}/api/metrics?node=${encodeURIComponent(n.id)}&from=${t1}&to=${now}`,
  );
  for (const p of met.points ?? []) {
    if (p.metrics.rssBytes > maxRSS) maxRSS = p.metrics.rssBytes;
  }
}
console.log(`max users RSS in window: ${(maxRSS / 1048576).toFixed(0)}M`);
if (maxRSS < 120 * 1024 * 1024) {
  failures.push(
    `pressure episode not visible: max users RSS ${(maxRSS / 1048576).toFixed(0)}M < 120M`,
  );
}

// The OOM kill must also be visible via cgroup accounting on the edge
// of the metrics (oom_kills counter) OR the lifecycle event above; both
// paths are kernel evidence. (Informational output only.)
const meta = await getJSON(`${base}/api/meta`);
console.log("collector:", JSON.stringify(meta.collector));

if (failures.length > 0) {
  console.error("\nV3 MID-RUN FAILURES:");
  for (const f of failures) console.error("  ✗ " + f);
  console.error("lifecycle:", JSON.stringify(events, null, 2));
  process.exit(1);
}
console.log("\nV3 MID-RUN OK: lifecycle recorded, pressure attributed");

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
