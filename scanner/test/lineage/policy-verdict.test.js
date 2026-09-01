//
// policy-verdict.test.js — Milestone 2, Sub-project G, increment 1
// (FR-408/AC-09, closes the PRD's own worked example: "a policy allows
// masked PII to a named analytics provider").
//
// Proves `flow.policyVerdict` — real computed logic, replacing the
// `'not_evaluated'` literal `graph-builder.js`'s flow-construction loop
// previously hardcoded — reusing `dataflow/privacy-sink-policy.js`'s
// `isSinkPermitted`/`permittingRules` UNMODIFIED, mirroring
// `dataflow/privacy-taint.js`'s own real usage precedent exactly (see
// `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-g1-plan.md`
// and the scoping doc it was built from).
//
// Every case runs real parsed JS/TS through the real pipeline
// (`buildGraphWithCoverage`/`buildLineageGraph`), mirroring
// `at-rest-protection.test.js`'s own real-code proof style — this
// increment's own logic is a loop-local computation with no interesting
// internal shape to probe in isolation; the interesting property is
// end-to-end behavior on real code.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { validateGraph } from '../../src/lineage/validate.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

// `req.body.email` (PII) reaching `analytics.track(...)` — a real
// `thirdPartySdk` privacy-catalog match, reclassified to the lineage
// `SINK_CATEGORIES` value `'analytics'` (`sink-registry.js`'s own
// `thirdPartySdk` row) — matches AC-09's own worked example verbatim.
// `analytics.track`'s destination never resolves to a literal (measured
// directly against `resolve-destination.js`'s real output), which is also
// exactly what case 5 below needs.
function analyticsFixture(field = 'email') {
  return irOf({
    'a.js': `
      function track(req, analytics) {
        const ${field} = req.body.${field};
        analytics.track('signup', { ${field} });
      }
    `,
  });
}

function build(cg, opts = {}) {
  const { graph } = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '2026-08-31T00:00:00.000Z', ...opts });
  const v = validateGraph(graph);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
  assert.equal(graph.flows.length, 1, 'exactly one flow: the seeded field -> the analytics sink');
  return { graph, flow: graph.flows[0] };
}

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-policy-verdict-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

async function writeSinkPolicy(dir, obj) {
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-policy.json'), JSON.stringify(obj, null, 2));
}

// ── 1. No policy at all → not_evaluated ─────────────────────────────────

test('G1/1a: opts.privacySinkPolicy omitted entirely — every flow reads not_evaluated', () => {
  const { flow } = build(analyticsFixture());
  assert.equal(flow.policyVerdict, 'not_evaluated');
  assert.deepEqual(flow.evidenceRefs, []);
});

test('G1/1b: buildLineageGraph with a scanRoot that has NO privacy-policy.json — not_evaluated end to end', async () => {
  const dir = await tmpProject();
  try {
    const r = buildLineageGraph(analyticsFixture(), { repository: 'r', scanRoot: dir, environment: 'production' });
    assert.equal(r.status, 'complete');
    assert.equal(r.graph.flows.length, 1);
    assert.equal(r.graph.flows[0].policyVerdict, 'not_evaluated',
      'a genuinely missing policy file must never be coerced to the loader\'s own {allow: []} default and misread as prohibited');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('G1/1c: buildLineageGraph with no scanRoot at all — not_evaluated (mirrors 1a at the index.js entry point)', () => {
  const r = buildLineageGraph(analyticsFixture(), { repository: 'r' });
  assert.equal(r.status, 'complete');
  assert.equal(r.graph.flows[0].policyVerdict, 'not_evaluated');
});

// ── 2. A matching permit rule → permitted, with real evidence ───────────

test('G1/2: a matching allow rule (AC-09\'s own worked example) — permitted, with {sink,class,reason,environment,destination} evidence', () => {
  const policy = { allow: [{ sink: 'analytics', class: 'PII', environment: 'production', reason: 'GDPR-approved segment export' }] };
  const { graph, flow } = build(analyticsFixture(), { privacySinkPolicy: policy, environment: 'production' });
  assert.equal(flow.policyVerdict, 'permitted');
  assert.equal(flow.evidenceRefs.length, 1);
  const ev = graph.evidence.find((e) => e.id === flow.evidenceRefs[0]);
  assert.ok(ev, 'the referenced evidence entry must exist in graph.evidence[]');
  assert.equal(ev.evidenceType, 'policy');
  assert.match(ev.id, /^evidence:[0-9a-f]{12}$/);
  assert.match(ev.claim, /PII/);
  assert.match(ev.claim, /"analytics"/);
  assert.match(ev.claim, /"production"/);
  assert.match(ev.claim, /GDPR-approved segment export/);
  assert.equal(ev.location.file, 'a.js');
  assert.equal(typeof ev.location.line, 'number');
});

// ── 3. A policy that exists but does not cover this flow → prohibited ───

test('G1/3: policy present, empty allow — prohibited (deny-by-default)', () => {
  const { flow } = build(analyticsFixture(), { privacySinkPolicy: { allow: [] } });
  assert.equal(flow.policyVerdict, 'prohibited');
  assert.deepEqual(flow.evidenceRefs, []);
});

test('G1/3b: policy present, a rule for an unrelated sink — prohibited', () => {
  const policy = { allow: [{ sink: 'database', class: 'PII' }] };
  const { flow } = build(analyticsFixture(), { privacySinkPolicy: policy, environment: 'production' });
  assert.equal(flow.policyVerdict, 'prohibited');
});

// ── 4. FR-408 environment fail-closed proof ──────────────────────────────

test('G1/4a: environment-scoped rule, wrong environment supplied — stays prohibited, never permitted by accident', () => {
  const policy = { allow: [{ sink: 'analytics', class: 'PII', environment: 'production' }] };
  const { flow } = build(analyticsFixture(), { privacySinkPolicy: policy, environment: 'staging' });
  assert.equal(flow.policyVerdict, 'prohibited');
});

test('G1/4b: environment-scoped rule, no environment supplied at all (opts.environment omitted, AGENTIC_SECURITY_ENVIRONMENT unset) — stays prohibited', () => {
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'AGENTIC_SECURITY_ENVIRONMENT');
  const savedEnvVar = process.env.AGENTIC_SECURITY_ENVIRONMENT;
  delete process.env.AGENTIC_SECURITY_ENVIRONMENT;
  try {
    const policy = { allow: [{ sink: 'analytics', class: 'PII', environment: 'production' }] };
    const { flow } = build(analyticsFixture(), { privacySinkPolicy: policy });
    assert.equal(flow.policyVerdict, 'prohibited', 'an unknown environment must not satisfy an environment-scoped rule');
  } finally {
    if (hadEnvVar) process.env.AGENTIC_SECURITY_ENVIRONMENT = savedEnvVar; else delete process.env.AGENTIC_SECURITY_ENVIRONMENT;
  }
});

// ── 5. FR-408 destination fail-closed proof ──────────────────────────────

test('G1/5: destination-scoped rule, the sink\'s own destination never resolved to a literal — stays prohibited', () => {
  // analyticsFixture()'s sink (`analytics.track(...)`) is confirmed (via
  // resolve-destination.js's real output) to resolve destination.literalValue
  // to null — there is no literal receiver/arg0 to name a destination from.
  const policy = { allow: [{ sink: 'analytics', class: 'PII', destination: 'mixpanel\\.com' }] };
  const { graph, flow } = build(analyticsFixture(), { privacySinkPolicy: policy, environment: 'production' });
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  assert.equal(sinkNode.destination.literalValue, null, 'sanity: this fixture genuinely has no literal destination');
  assert.equal(flow.policyVerdict, 'prohibited', 'a destination-scoped rule must not match a flow with no resolved destination');
});

// ── 6. No recognized data class on the flow's own data element ──────────

test('G1/6: a flow whose data element has no recognized data class stays not_evaluated, even under a policy that would otherwise permit', () => {
  // 'theme' classifies to zero data classes (classification.js, confirmed
  // directly) — an ordinary, non-sensitive field. The policy below has an
  // unconditional (class-unset) rule for the 'analytics' sink, which WOULD
  // permit any class if isSinkPermitted were even consulted — proving this
  // case is gated on classes.length, not on the policy's own content.
  const policy = { allow: [{ sink: 'analytics', reason: 'would permit anything, if reached' }] };
  const { graph, flow } = build(analyticsFixture('theme'), { privacySinkPolicy: policy, environment: 'production' });
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  assert.deepEqual(de.dataClasses, [], 'sanity: this fixture genuinely has no recognized data class');
  assert.equal(flow.policyVerdict, 'not_evaluated',
    'a policy engine has nothing meaningful to say about a flow it was never asked to gate — prohibited would overstate a judgment that never happened');
  assert.deepEqual(flow.evidenceRefs, []);
});

// ── 7. Full end-to-end wiring: buildLineageGraph with a real policy file ─

test('G1/7: buildLineageGraph end to end — a real privacy-policy.json on disk is loaded once and drives a real permitted verdict', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'analytics', class: 'PII', environment: 'production', reason: 'segment export' }] });
    const r = buildLineageGraph(analyticsFixture(), { repository: 'r', scanRoot: dir, environment: 'production' });
    assert.equal(r.status, 'complete');
    assert.equal(r.graph.flows.length, 1);
    assert.equal(r.graph.flows[0].policyVerdict, 'permitted');
    assert.equal(r.graph.flows[0].evidenceRefs.length, 1);
    assert.deepEqual(validateGraph(r.graph).errors, []);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('G1/7b: buildLineageGraph end to end — a real, present-but-empty privacy-policy.json reads prohibited, not not_evaluated', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [] });
    const r = buildLineageGraph(analyticsFixture(), { repository: 'r', scanRoot: dir, environment: 'production' });
    assert.equal(r.status, 'complete');
    assert.equal(r.graph.flows[0].policyVerdict, 'prohibited');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
