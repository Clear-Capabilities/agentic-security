// E5-01: the integration audit is real (entry points exist, identity classified), current, and its resolved conflicts are resolved in code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './helpers.js';
import { annotateRuntimeCorrelation, findingObservedInRuntime } from '../../src/posture/runtime-correlation.js';
import { render, validate } from '../../../scripts/engineering-excellence/runtime-audit.mjs';

const DOC = JSON.parse(fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/runtime-integration.json'), 'utf8'));

test('every cited entry point exists in its file, and every identity field is classified exactly once per source', () => {
  assert.deepEqual(validate(DOC), []);
  assert.deepEqual(DOC.areas.map((a) => a.id), ['runtime-lineage', 'runtime-ebpf-trace', 'static-graph', 'dependency-reachability', 'service-topology', 'git-provenance', 'artifact-attestation']);
  for (const a of DOC.areas) assert.equal(a.carries.length + a.missing.length, DOC.identityVocabulary.length, a.id);
});

test('the audit says what the PRD needs said: no runtime source carries a commit, build hash or image digest', () => {
  for (const id of ['runtime-lineage', 'runtime-ebpf-trace']) { const a = DOC.areas.find((x) => x.id === id); for (const k of ['commit', 'buildHash', 'imageDigest']) assert.ok(a.missing.includes(k), `${id} misses ${k}`); }
  const art = DOC.areas.find((x) => x.id === 'artifact-attestation'); assert.ok(art.carries.includes('imageDigest') && art.carries.includes('commit'));
  assert.ok(DOC.sourceOfTruth.some((s) => /Which build is this observation about/.test(s.question) && /unknown, not corroborated/.test(s.rule)));
});

test('the document is current and every conflict is resolved or decided with the task that implements it', () => {
  const r = spawnSync(process.execPath, [path.join(REPO, 'scripts/engineering-excellence/runtime-audit.mjs'), '--check'], { cwd: REPO, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/RUNTIME_PROVENANCE_AUDIT.md'), 'utf8'), render(DOC));
  assert.ok(DOC.conflicts.every((c) => ['resolved', 'decided'].includes(c.status)));
  assert.deepEqual(DOC.conflicts.filter((c) => c.status === 'resolved').map((c) => c.id), ['C1', 'C2', 'C8']);
  const tasks = new Set(JSON.parse(fs.readFileSync(path.join(REPO, 'scripts/engineering-excellence/tasks.json'), 'utf8')).tasks.map((t) => t.id));
  for (const c of DOC.conflicts.filter((x) => x.status === 'decided')) assert.ok(tasks.has(c.closedBy), c.id);
});

// ---- C1 and C2 resolved in code ----------------------------------------------------------------------------------------------

function traceRoot(lines) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5a-'));
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(root, '.agentic-security', 'runtime-trace.jsonl'), lines.map((l) => JSON.stringify({ ts: new Date().toISOString(), ...l })).join('\n'));
  return root;
}
const many = (n, rec) => Array.from({ length: n }, () => rec);

test('C1: a finding that was not observed keeps its severity, says why that proves nothing, and is not removed', async () => {
  const root = traceRoot(many(300, { kind: 'function-call', qid: 'other', fileRel: 'src/other.js', line: 3 }));
  try {
    const findings = [{ id: 'f', severity: 'high', file: 'src/other.js', line: 90 }, { id: 'g', severity: 'critical', file: 'src/never-traced.js', line: 5 }];
    const r = await annotateRuntimeCorrelation(root, findings);
    assert.equal(findings.length, 2);
    for (const f of findings) { assert.equal(f.runtimeObserved === true, false); assert.equal(f._runtimeDemoted, undefined); }
    assert.equal(findings[0].severity, 'high'); assert.equal(findings[1].severity, 'critical');
    assert.equal(r.demoted, 0);
    assert.equal(findings[1].runtimeEvidence.state, 'not_observed_in_window');
    assert.match(findings[1].runtimeEvidence.meaning, /not evidence that the code is unreachable or safe/);
    assert.equal(findings[0].runtimeEvidence.state, 'unknown', 'the file appears with no matching line: still unknown');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('C1/C2: demotion is opt-in, needs enough records and route-level traffic, cites its evidence, and still keeps the finding', async () => {
  const traffic = traceRoot([...many(300, { kind: 'route-hit', route: '/other' }), ...many(5, { kind: 'file-touch', fileRel: 'src/r.js' })]);
  const mk = () => [
    { id: 'routeNotHit', severity: 'high', file: 'src/q.js', line: 7, _inRoute: { path: '/x' } },
    { id: 'fileSeenNoLine', severity: 'high', file: 'src/r.js', line: 7, _inRoute: { path: '/x' } },
    { id: 'routeHit', severity: 'high', file: 'src/s.js', line: 8, _inRoute: { path: '/other' } },
    { id: 'noRoute', severity: 'high', file: 'src/zzz.js', line: 7 },
    { id: 'uninstrumented', severity: 'critical', file: 'src/zzz.js', line: 9, _inRoute: { path: '/y' } },
  ];
  try {
    const off = mk(); const r0 = await annotateRuntimeCorrelation(traffic, off);
    assert.deepEqual(off.map((f) => f.severity), ['high', 'high', 'high', 'high', 'critical'], 'off by default'); assert.equal(r0.demoted, 0);
    const on = mk(); const r1 = await annotateRuntimeCorrelation(traffic, on, { demote: true });
    const by = Object.fromEntries(on.map((f) => [f.id, f]));
    assert.equal(by.routeNotHit.severity, 'medium'); assert.equal(by.routeNotHit._runtimeDemoted, 'high');
    assert.equal(by.routeNotHit._runtimeDemotionEvidence.basis, 'route-rooted finding whose route was not hit while other routes were');
    assert.ok(by.routeNotHit._runtimeDemotionEvidence.recordCount >= 100 && by.routeNotHit._runtimeDemotionEvidence.routesObserved >= 1);
    assert.equal(by.routeHit.severity, 'high', 'a route that was hit is observed, not demoted'); assert.equal(by.routeHit.runtimeObserved, true);
    assert.equal(by.noRoute.severity, 'high', 'no route, nothing to cite'); assert.equal(by.noRoute._runtimeDemoted, undefined);
    assert.equal(by.uninstrumented.severity, 'high', 'a route-rooted finding whose route was not hit is demoted one tier whatever its file'); assert.equal(by.uninstrumented._runtimeDemoted, 'critical');
    assert.equal(by.fileSeenNoLine.severity, 'high', 'the file appears in the trace with no matching line: unknown, which is never demoted'); assert.equal(by.fileSeenNoLine.runtimeObserved, 'unknown');
    assert.equal(r1.demoted, 2); assert.equal(on.length, 5, 'nothing is removed');
    const env = mk(); process.env.AGENTIC_SECURITY_RUNTIME_DEMOTE = '1';
    try { await annotateRuntimeCorrelation(traffic, env); assert.equal(env[0].severity, 'medium', 'the environment switch is the same policy'); } finally { delete process.env.AGENTIC_SECURITY_RUNTIME_DEMOTE; }
  } finally { fs.rmSync(traffic, { recursive: true, force: true }); }
  const few = traceRoot([...many(3, { kind: 'route-hit', route: '/other' })]);
  try {
    const c = mk(); await annotateRuntimeCorrelation(few, c, { demote: true });
    assert.deepEqual(c.map((f) => f.severity), ['high', 'high', 'high', 'high', 'critical'], 'a three-record trace is not evidence');
  } finally { fs.rmSync(few, { recursive: true, force: true }); }
});

test('with no trace at all every finding is unknown and nothing changes', async () => {
  const f = [{ id: 'a', severity: 'high', file: 'x.js', line: 1 }];
  const r = await annotateRuntimeCorrelation('/tmp/no-such-dir-ee', f);
  assert.equal(f[0].runtimeObserved, 'unknown'); assert.equal(f[0].severity, 'high'); assert.equal(f[0].runtimeEvidence.state, 'unknown'); assert.equal(r.demoted, 0);
});
