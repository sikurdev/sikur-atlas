#!/usr/bin/env node
// Startup-state e2e assertions.
//
//   discover:  connections established BEFORE the agent started (one
//              container→container, one host-process→container) must be
//              on the map as seeded standing connections, with zero
//              observed opens — proof Atlas no longer starts blind and
//              needs no replacement traffic.
//   reconcile: after those connections actually close, their close
//              events must have released the seeded state (no stale
//              sockets, no inflated actives) and folded in the lifetime
//              byte counters the close event carries.
//
// Usage: node scripts/assert-seed.mjs <base> discover|reconcile
const [base, phase] = process.argv.slice(2);
if (!base || !["discover", "reconcile"].includes(phase)) {
  console.error("usage: assert-seed.mjs <base> discover|reconcile");
  process.exit(2);
}

const failures = [];
const found = [];

function findEdges(graph) {
  const cache = graph.nodes.find((n) => n.containerName === "atlas-demo-cache");
  const hold = graph.nodes.find((n) => n.containerName === "atlas-demo-holdconn");
  if (!cache) failures.push("cache node missing");
  if (!hold) failures.push("holdconn node missing");
  const containerEdge =
    cache && hold
      ? graph.edges.find(
          (e) => e.src === hold.id && e.dst === cache.id && e.dstPort === 6379,
        )
      : null;
  // The host half: a host python process holding a connection to cache.
  const hostEdge = cache
    ? graph.edges.find(
        (e) =>
          e.dst === cache.id &&
          e.dstPort === 6379 &&
          e.src.startsWith("proc:") &&
          e.src.includes("python"),
      )
    : null;
  return { containerEdge, hostEdge };
}

if (phase === "discover") {
  const graph = await getJSON(`${base}/api/graph`);
  const meta = await getJSON(`${base}/api/meta`);
  const { containerEdge, hostEdge } = findEdges(graph);

  check("container holdconn -> cache", containerEdge);
  check("host python -> cache", hostEdge);

  function check(name, edge) {
    if (!edge) {
      failures.push(`seeded edge missing: ${name}`);
      return;
    }
    if (!(edge.seededConns >= 1)) {
      failures.push(`${name}: not marked seeded: ${JSON.stringify(edge)}`);
    }
    if (!(edge.activeConns >= 1)) {
      failures.push(`${name}: not active: ${JSON.stringify(edge)}`);
    }
    if (edge.connections !== 0) {
      failures.push(
        `${name}: a pre-existing connection counted as an observed open: ${JSON.stringify(edge)}`,
      );
    }
    if ((edge.window?.opens ?? 0) !== 0) {
      failures.push(`${name}: window shows opens: ${JSON.stringify(edge.window)}`);
    }
    found.push(
      `${name}: active=${edge.activeConns} seeded=${edge.seededConns} ` +
        `observed-opens=${edge.connections}`,
    );
  }
  if (!(meta.collector?.seededConns >= 2)) {
    failures.push(
      `collector seeded fewer than 2 connections: ${JSON.stringify(meta.collector)}`,
    );
  }
  found.push(
    `collector: seeded=${meta.collector?.seededConns} ` +
      `heuristic-direction=${meta.collector?.seedDirHeuristic} live=${meta.collector?.liveSeeds}`,
  );
}

if (phase === "reconcile") {
  // The close events race the assertion by at most a moment; poll.
  let ok = false;
  let lastDiag = "";
  for (let i = 0; i < 30 && !ok; i++) {
    const graph = await getJSON(`${base}/api/graph`);
    const { containerEdge, hostEdge } = findEdges(graph);
    const settled = (e) => e && e.activeConns === 0 && !(e.seededConns > 0);
    lastDiag = JSON.stringify({ containerEdge, hostEdge });
    if (settled(containerEdge) && settled(hostEdge)) {
      ok = true;
      // The host client spoke one PING before Atlas started; its close
      // event carries the connection's lifetime byte counters, which
      // must have been folded into the seeded edge.
      if (!(hostEdge.bytesSent > 0 && hostEdge.bytesRecv > 0)) {
        failures.push(
          `host edge close carried no bytes: ${JSON.stringify(hostEdge)}`,
        );
      }
      found.push(
        `both seeded edges released by their close events; ` +
          `host edge bytes=${hostEdge.bytesSent}/${hostEdge.bytesRecv}`,
      );
      break;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!ok) {
    failures.push(`seeded edges not released after close: ${lastDiag}`);
  }
  const meta = await getJSON(`${base}/api/meta`);
  if (!(meta.collector?.seedClosed >= 1)) {
    failures.push(
      `no seed retired by an observed close: ${JSON.stringify(meta.collector)}`,
    );
  }
  found.push(
    `collector: seedClosed=${meta.collector?.seedClosed} seedExpired=${meta.collector?.seedExpired}`,
  );
}

for (const line of found) console.log("  " + line);
if (failures.length > 0) {
  console.error(`\nSEED (${phase}) FAILURES:`);
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log(`SEED ${phase.toUpperCase()} OK`);

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
