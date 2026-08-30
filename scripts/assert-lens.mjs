#!/usr/bin/env node
// Incident Lens e2e assertions against recorded, real-kernel evidence.
//
//   oom  <from> <to>: the users OOM episode. The Lens must name users
//        as the origin (anchored by the recorded OOM kill), keep every
//        finding evidence-backed and chronologically ordered, and show
//        the recovery (the restart exec).
//   stop <from> <to>: the inventory stop. The Lens must name inventory
//        (exit + disappearance), show the traffic stop on
//        orders→inventory as propagation, list orders in the blast
//        radius, keep the deliberately-broken users→cache:6380 edge in
//        chronic context, and report no recovery.
//
// Usage: node scripts/assert-lens.mjs <base> oom|stop <from> <to>
const [base, mode, fromS, toS] = process.argv.slice(2);
const from = Number(fromS);
const to = Number(toS);
if (!base || !["oom", "stop"].includes(mode) || !from || !to) {
  console.error("usage: assert-lens.mjs <base> oom|stop <from> <to>");
  process.exit(2);
}

const failures = [];
const found = [];
const svc = (name) => `svc:compose:atlas-demo/${name}`;

// Let the window's final buckets close and flush before investigating:
// a bucket still being written would make the determinism double-query
// below race live traffic rather than test the engine.
const settle = to - (Math.floor(Date.now() / 1000) - 15);
if (settle > 0) {
  await new Promise((r) => setTimeout(r, settle * 1000));
}

const report = await getJSON(`${base}/api/lens?from=${from}&to=${to}`);
const findings = report.findings ?? [];
const chronic = report.chronic ?? [];

// Universal report invariants: facts with evidence, chronological, and
// deterministic (a second run must produce the identical report).
if (report.ruleSet !== "lens/v1") {
  failures.push(`unexpected rule set: ${report.ruleSet}`);
}
for (const f of findings) {
  if (!f.evidence?.length) failures.push(`finding without evidence: ${JSON.stringify(f)}`);
  if (!f.time || !f.end) failures.push(`finding without timestamps: ${JSON.stringify(f)}`);
}
for (let i = 1; i < findings.length; i++) {
  if (new Date(findings[i].time) < new Date(findings[i - 1].time)) {
    failures.push(`findings out of order at index ${i}`);
  }
}
const again = await getJSON(`${base}/api/lens?from=${from}&to=${to}`);
if (JSON.stringify(again) !== JSON.stringify(report)) {
  failures.push("two identical lens queries produced different reports");
}

const kinds = (k, s) =>
  findings.filter((f) => f.kind === k && (!s || f.service === s));

if (mode === "oom") {
  if (!report.origin) {
    failures.push(`origin unresolved: ${report.unresolved}`);
  } else {
    if (report.origin.service !== svc("users")) {
      failures.push(`origin = ${report.origin.service}, want users`);
    }
    if (report.origin.inference !== true) {
      failures.push("origin not flagged as inference");
    }
    found.push(`origin: ${report.origin.label} — ${report.origin.explanation}`);
  }
  const oom = kinds("oom", svc("users"));
  if (oom.length < 1) {
    failures.push(`no recorded OOM finding for users: ${summarize()}`);
  } else {
    found.push(`oom fact: ${oom[0].time} ${oom[0].detail}`);
  }
  const exec = kinds("exec", svc("users"));
  if (exec.length < 1) {
    failures.push(`no restart exec recorded for users: ${summarize()}`);
  }
  const rec = (report.recovery ?? []).find(
    (r) => r.subject === svc("users") && r.recoveredAt,
  );
  if (!rec) {
    failures.push(`users restart not matched as recovery: ${JSON.stringify(report.recovery)}`);
  } else {
    found.push(`recovery: users ${rec.detail} at ${rec.recoveredAt}`);
  }
  if (!(report.blastRadius.services ?? []).includes(svc("users"))) {
    failures.push(`users missing from blast radius: ${JSON.stringify(report.blastRadius)}`);
  }
}

if (mode === "stop") {
  if (!report.origin) {
    failures.push(`origin unresolved: ${report.unresolved}`);
  } else {
    if (report.origin.service !== svc("inventory")) {
      failures.push(`origin = ${report.origin.service}, want inventory`);
    }
    found.push(`origin: ${report.origin.label} — ${report.origin.explanation}`);
  }
  // The chain: a primary on inventory (the SIGTERM exit and/or the
  // disappearance), then the dependency edge falling silent.
  const primary = [...kinds("exit", svc("inventory")), ...kinds("service-gone", svc("inventory"))];
  if (primary.length < 1) {
    failures.push(`no primary finding for inventory: ${summarize()}`);
  } else {
    found.push(`primary: ${primary[0].kind} at ${primary[0].time} — ${primary[0].detail}`);
  }
  const stops = findings.filter(
    (f) =>
      f.kind === "traffic-stop" &&
      f.edgeSrc === svc("orders") &&
      f.edgeDst === svc("inventory"),
  );
  if (stops.length < 1) {
    failures.push(`orders→inventory traffic stop not found: ${summarize()}`);
  } else {
    found.push(`impact: ${stops[0].detail}`);
    // Temporal sanity: the primary does not come after the silence.
    if (primary.length > 0 && new Date(primary[0].time) >= new Date(stops[0].end)) {
      failures.push(
        `chain out of order: primary ${primary[0].time} vs stop end ${stops[0].end}`,
      );
    }
  }
  const br = report.blastRadius;
  if (!(br.services ?? []).includes(svc("orders"))) {
    failures.push(`orders missing from blast radius: ${JSON.stringify(br)}`);
  }
  if (!(br.edges ?? []).some((e) => e.startsWith(`${svc("orders")}->${svc("inventory")}`))) {
    failures.push(`orders→inventory edge missing from blast radius: ${JSON.stringify(br)}`);
  }
  // The deliberately-broken users→cache:6380 call predates the window:
  // chronic context, never part of this incident's chain.
  const chronicBroken = chronic.some(
    (f) => f.edge?.startsWith(`${svc("users")}->${svc("cache")}:6380`),
  );
  if (!chronicBroken) {
    failures.push(
      `users→cache:6380 not classified chronic: ${JSON.stringify(chronic)}`,
    );
  } else {
    found.push("chronic: users→cache:6380 correctly held out of the incident");
  }
  if (
    findings.some(
      (f) => f.kind === "failures-start" && f.edge?.includes(":6380"),
    )
  ) {
    failures.push("chronic 6380 failures leaked into the incident chain");
  }
  // Propagation is inference, linked to the origin.
  const props = report.propagations ?? [];
  if (report.origin && !props.some((p) => p.inference === true)) {
    failures.push(`no propagation inference recorded: ${JSON.stringify(props)}`);
  }
  // Nothing recovered among the demo services: inventory stays down in
  // this window (background host edges may come and go; they are not
  // this incident).
  const recovered = (report.recovery ?? []).filter(
    (r) => r.recoveredAt != null && r.subject.includes("atlas-demo"),
  );
  if (recovered.length > 0) {
    failures.push(`unexpected recovery in stop window: ${JSON.stringify(recovered)}`);
  }
}

function summarize() {
  return JSON.stringify(
    findings.map((f) => ({ k: f.kind, s: f.service, e: f.edge, t: f.time })),
  );
}

console.log(`== lens ${mode} report (${from} → ${to}) ==`);
for (const line of found) console.log("  " + line);
if (failures.length > 0) {
  console.error(`\nLENS (${mode}) FAILURES:`);
  for (const f of failures) console.error("  ✗ " + f);
  console.error("full report:");
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}
console.log(`LENS ${mode.toUpperCase()} OK`);

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
