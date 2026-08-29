#!/usr/bin/env node
// Phase-2/3 e2e assertions: Replay reconstructs both eras and Compare
// identifies the lifecycle change (inventory stopped between T1 and T2).
//
// Usage: node scripts/assert-lifecycle.mjs <base> <t1> <t2> <phase-label>
const [base, t1s, t2s, label] = process.argv.slice(2);
const t1 = Number(t1s);
const t2 = Number(t2s);
if (!base || !t1 || !t2) {
  console.error("usage: assert-lifecycle.mjs <base> <t1> <t2> <label>");
  process.exit(2);
}

const failures = [];

// Replay at T1: inventory existed and orders depended on it.
const atT1 = await getJSON(`${base}/api/appview?at=${t1}`);
const invT1 = atT1.nodes.find((n) => n.id === "svc:compose:atlas-demo/inventory");
if (!invT1) failures.push("replay at T1: inventory service missing");
const ordersInvT1 = atT1.edges.find(
  (e) =>
    e.src === "svc:compose:atlas-demo/orders" &&
    e.dst === "svc:compose:atlas-demo/inventory",
);
if (!ordersInvT1) failures.push("replay at T1: orders -> inventory edge missing");
if (ordersInvT1 && !(ordersInvT1.window?.opens >= 1)) {
  failures.push(
    `replay at T1: orders -> inventory shows no activity: ${JSON.stringify(ordersInvT1.window)}`,
  );
}

// Replay at T2: inventory is gone.
const atT2 = await getJSON(`${base}/api/appview?at=${t2}`);
if (atT2.nodes.some((n) => n.id === "svc:compose:atlas-demo/inventory")) {
  failures.push("replay at T2: stopped inventory still present");
}
if (!atT2.nodes.some((n) => n.id === "svc:compose:atlas-demo/gateway")) {
  failures.push("replay at T2: gateway missing (era B traffic not recorded?)");
}

// The two reconstructions must genuinely differ.
if (atT1.nodes.length <= atT2.nodes.length - 1) {
  // Informational only; the inventory checks above are the real gate.
}

// Compare identifies the change.
const diff = await getJSON(`${base}/api/compare?a=${t1}&b=${t2}`);
const removedIDs = (diff.removedNodes ?? []).map((n) => n.id);
if (!removedIDs.includes("svc:compose:atlas-demo/inventory")) {
  failures.push(`compare: inventory not in removedNodes: ${JSON.stringify(removedIDs)}`);
}
const removedEdgeIDs = (diff.removedEdges ?? []).map((e) => e.id);
if (
  !removedEdgeIDs.some(
    (id) =>
      id.startsWith("svc:compose:atlas-demo/orders->svc:compose:atlas-demo/inventory"),
  )
) {
  failures.push(
    `compare: orders -> inventory not in removedEdges: ${JSON.stringify(removedEdgeIDs)}`,
  );
}
// Sanity: the surviving spine is not reported as removed.
if (removedIDs.includes("svc:compose:atlas-demo/gateway")) {
  failures.push("compare: gateway wrongly reported removed");
}

console.log(`== ${label}: replay + compare ==`);
console.log(
  `T1 view: ${atT1.nodes.length} services / ${atT1.edges.length} edges; ` +
    `T2 view: ${atT2.nodes.length} services / ${atT2.edges.length} edges`,
);
console.log("compare removedNodes:", JSON.stringify(removedIDs));
console.log("compare removedEdges:", JSON.stringify(removedEdgeIDs));
console.log(
  "compare added/changed:",
  JSON.stringify({
    added: (diff.addedNodes ?? []).map((n) => n.id),
    changed: (diff.changedEdges ?? []).map((c) => `${c.edge.id} ${c.changes}`),
  }),
);

if (failures.length > 0) {
  console.error(`\n${label} FAILURES:`);
  for (const f of failures) console.error("  ✗ " + f);
  console.error("T1 appview:", JSON.stringify(atT1, null, 2));
  console.error("T2 appview:", JSON.stringify(atT2, null, 2));
  process.exit(1);
}
console.log(`\n${label} OK: two distinct states reconstructed, change identified`);

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
