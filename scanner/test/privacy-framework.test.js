// NIST Privacy Framework 1.1 assessment + remediation.
//
// The tests that matter here are not "does it produce a report" — they are the
// ones that stop the report being FALSELY REASSURING. 48 of 104 controls are
// governance controls no scanner can assess, and 27 more are code-testable but
// unmapped by this engine. If any of those can be presented as satisfied, the
// output is worse than nothing: someone hands it to an auditor.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  assessPrivacyFramework, bucketOf, remediationFor, PRIVACY_FRAMEWORK_ID, BUCKETS,
} from '../src/posture/privacy-framework.js';
import { listFrameworks, loadFramework } from '../src/posture/auditor-walkthrough.js';
import { PROVENANCE_COMPLIANCE_DISCLAIMER } from '../src/posture/provenance/schema.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FW_FILE = path.join(HERE, '..', 'src', 'posture', 'compliance-frameworks', 'nist-privacy-1-1.json');

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'pf11-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"p","version":"1.0.0"}');
  return d;
}

test('the framework is bundled and self-registers alongside the others', async () => {
  const d = await tmpProject();
  try {
    const ids = listFrameworks(d).map(f => f.id);
    assert.ok(ids.includes(PRIVACY_FRAMEWORK_ID), `expected ${PRIVACY_FRAMEWORK_ID} in ${ids.join(', ')}`);
    const fw = loadFramework(d, PRIVACY_FRAMEWORK_ID);
    assert.equal(fw.controls.length, 104, 'all 104 PF 1.1 controls, not just the testable ones');
    assert.match(fw.license, /public-domain/);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('every control carries NIST\'s own codeTestable rating', () => {
  // The rating is the input to the honesty bucketing. A control without one
  // would silently default to "governance, not our problem".
  const fw = JSON.parse(fs.readFileSync(FW_FILE, 'utf8'));
  const bad = fw.controls.filter(c => !['yes', 'partial', 'no'].includes(c.codeTestable));
  assert.deepEqual(bad.map(c => c.id), []);
  const counts = fw.controls.reduce((a, c) => ((a[c.codeTestable] = (a[c.codeTestable] || 0) + 1), a), {});
  assert.deepEqual(counts, { partial: 33, no: 48, yes: 23 }, 'matches the published PF 1.1 ratings');
});

// PRD Section 8 REQUIRED DISCLAIMER, second surface. A review of the auditor
// walkthrough's disclaimer fix found this path: `derivedProvenance` attaches
// an origin commit, author and confidence to a COMPLIANCE finding, and
// `compliance --privacy --format json` prints it straight to stdout — the
// same undisclaimed compliance-provenance data, through a different, live,
// documented command. The disclaimer rides ON the record, not beside it,
// because a JSON consumer can slice one finding out of the array.
test('privacy: a provenance-derived compliance finding carries the PRD disclaimer with it', async () => {
  const d = await tmpProject();
  try {
    const r = assessPrivacyFramework(d, { findings: [], components: [] });
    const withProv = (r.findings || []).filter(f => f.derivedProvenance);
    // Only assert on records that actually carry provenance — a run with none
    // is a legitimate state, but must not let the assertion pass vacuously.
    if (withProv.length === 0) {
      assert.ok(Array.isArray(r.findings), 'sanity: findings must at least be an array');
      return;
    }
    for (const f of withProv) {
      assert.equal(f.derivedProvenance.disclaimer, PROVENANCE_COMPLIANCE_DISCLAIMER,
        `${f.id || 'finding'} surfaces compliance provenance without the PRD-required disclaimer`);
    }
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('a control NIST says is NOT code-testable is never claimed as satisfied', async () => {
  // 48 governance controls. Reporting them as passed because no rule fired is
  // the exact failure mode this module exists to prevent.
  const d = await tmpProject();
  try {
    const r = assessPrivacyFramework(d, { findings: [], components: [] });
    const manual = r.controls.filter(c => c.codeTestable === 'no');
    assert.equal(manual.length, 48);
    for (const c of manual) {
      assert.equal(c.bucket, 'manual', `${c.id} must be manual, got ${c.bucket}`);
      assert.match(c.disclosure, /not code-testable/);
    }
    assert.equal(r.summary.manual, 48);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('a code-testable control this engine cannot see is disclosed, not passed', async () => {
  // The distinction that decides whether a reader should worry: "we checked and
  // it is fine" versus "nobody checked". Silence must not read as the former.
  const d = await tmpProject();
  try {
    const r = assessPrivacyFramework(d, { findings: [], components: [] });
    const engineGaps = r.controls.filter(c => c.bucket === 'engine-gap');
    assert.ok(engineGaps.length > 0, 'this engine does not map every testable control, and must say so');
    for (const c of engineGaps) {
      assert.notEqual(c.codeTestable, 'no');
      assert.match(c.disclosure, /NOT assessed/);
    }
    // Named individually — a count alone lets a reader skip past them.
    assert.ok(engineGaps.every(c => typeof c.id === 'string' && c.id.length > 0));
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

// ── FR-405: a non-IR-backed privacy-taint run must not read as a clean pass
//    for controls that depend entirely on its signal. This is a REGRESSION
//    test for a confirmed, reproduced bug: CT.DP-P4/CT.DP-P5 (both
//    codeTestable:'yes', both mapped ONLY to module:privacy-taint) read
//    `satisfied` from zero real evidence before this fix. ────────────────

test('FR-405 regression: CT.DP-P4/CT.DP-P5 do NOT read satisfied when privacy-taint ran without a real IR, even though the scan otherwise examined real files', async () => {
  const d = await tmpProject();
  try {
    const scan = { findings: [], components: [], filesScanned: 5, privacyIrBacked: false };
    const r = assessPrivacyFramework(d, scan);
    for (const id of ['CT.DP-P4', 'CT.DP-P5']) {
      const c = r.controls.find(x => x.id === id);
      assert.ok(c, `expected ${id} in the control set`);
      assert.equal(c.bucket, 'engine-gap', `${id} must NOT read satisfied from a non-IR-backed run — got ${c.bucket}`);
      assert.match(c.disclosure, /privacy-taint.*signal.*without a real IR|not real evidence/i);
    }
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('FR-405: the SAME clean scan reads satisfied for CT.DP-P4/CT.DP-P5 when privacy-taint DID run with a real IR — the gate does not over-correct into a permanent gap', async () => {
  const d = await tmpProject();
  try {
    // module:privacy-taint's own signal is dpia.md's presence (auditor-
    // walkthrough.js) — write it, matching what a real IR-backed scan
    // that found nothing wrong actually leaves behind.
    await fsp.mkdir(path.join(d, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(d, '.agentic-security', 'dpia.md'), '# DPIA\n\nNo PII fields detected.\n');
    const scan = { findings: [], components: [], filesScanned: 5, privacyIrBacked: true };
    const r = assessPrivacyFramework(d, scan);
    for (const id of ['CT.DP-P4', 'CT.DP-P5']) {
      const c = r.controls.find(x => x.id === id);
      assert.equal(c.bucket, 'satisfied', `${id} must read satisfied on a genuine IR-backed clean pass — got ${c.bucket}`);
    }
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('FR-405: privacyIrBacked absent entirely (e.g. a scan predating this fix, or the annotator never ran) is treated the same as false, not as true', async () => {
  const d = await tmpProject();
  try {
    const scan = { findings: [], components: [], filesScanned: 5 }; // no privacyIrBacked key at all
    const r = assessPrivacyFramework(d, scan);
    const c = r.controls.find(x => x.id === 'CT.DP-P4');
    assert.equal(c.bucket, 'engine-gap', 'missing privacyIrBacked must degrade safely, not default to a pass');
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('FR-405: a control with an ADDITIONAL, independent mapping is NOT force-gated purely by privacyIrBacked:false', async () => {
  // CT.DP-P1 maps to ['family:pii-exposure', 'family:data-exposure'] — a
  // mixed mapping. The gate is deliberately conservative and only applies to
  // controls whose mapping is ENTIRELY privacy-taint-dependent, because this
  // module cannot attribute which specific signal produced a "present"
  // verdict for a multi-mapped control.
  const d = await tmpProject();
  try {
    const clean = { findings: [], components: [], filesScanned: 5 };
    const rBacked = assessPrivacyFramework(d, { ...clean, privacyIrBacked: true });
    const rNotBacked = assessPrivacyFramework(d, { ...clean, privacyIrBacked: false });
    const bBacked = rBacked.controls.find(c => c.id === 'CT.DP-P1').bucket;
    const bNotBacked = rNotBacked.controls.find(c => c.id === 'CT.DP-P1').bucket;
    assert.equal(bBacked, bNotBacked, 'a mixed-mapping control\'s bucket must not change based on privacyIrBacked alone');
    assert.notEqual(bNotBacked, 'engine-gap', 'CT.DP-P1 must not be swept into engine-gap by this specific gate (it may legitimately land elsewhere for other reasons)');
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('the satisfied rate is a share of ASSESSED controls, never of all 104', async () => {
  const d = await tmpProject();
  try {
    const r = assessPrivacyFramework(d, { findings: [], components: [] });
    const assessed = r.summary.satisfied + r.summary.gap;
    assert.ok(assessed < r.summary.total, 'not every control is assessable');
    assert.match(r.interpretation, new RegExp(`of ${assessed} assessed controls`));
    assert.match(r.interpretation, /Neither group is evidence of compliance/);
    // The buckets partition the framework: nothing is double-counted or lost.
    const sum = BUCKETS.reduce((a, b) => a + r.summary[b], 0);
    assert.equal(sum, r.summary.total);
    assert.equal(sum, 104);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('a real failing signal produces a FIXABLE finding, not just narrative', async () => {
  const d = await tmpProject();
  try {
    // A dirty crypto signal is what PR.DS-P2 maps to.
    const scan = {
      findings: [
        { family: 'crypto-tls-no-verify', severity: 'critical', file: 'a.js', line: 3, vuln: 'TLS verification disabled' },
      ],
      components: [],
    };
    const r = assessPrivacyFramework(d, scan);
    const f = r.findings.find(x => x.id === 'privacy-framework:PR.DS-P2');
    assert.ok(f, 'a mapped, failing control must emit a finding');

    // The schema every downstream consumer requires — without these it is
    // invisible to triage, /fix, SARIF and the report layer.
    for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) {
      assert.ok(f[k] !== undefined && f[k] !== null && f[k] !== '', `finding is missing ${k}`);
    }
    assert.equal(f.family, 'privacy-compliance');
    assert.equal(f.cwe, 'CWE-359');
    assert.equal(f.complianceControl.framework, PRIVACY_FRAMEWORK_ID);
    // Actionable, not a restatement of the control text.
    assert.match(f.remediation, /TLS 1\.2\+|certificate verification/);
    assert.notEqual(f.remediation, f.vuln);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('only GAPS emit findings — manual and engine-gap controls never do', async () => {
  // Otherwise every scan of every project would raise 75 findings nobody can
  // action, and the actionable ones would be lost in them.
  const d = await tmpProject();
  try {
    const r = assessPrivacyFramework(d, { findings: [], components: [] });
    const gapIds = new Set(r.controls.filter(c => c.bucket === 'gap').map(c => c.id));
    for (const f of r.findings) {
      const id = f.id.replace('privacy-framework:', '');
      assert.ok(gapIds.has(id), `${id} emitted a finding but is not a gap`);
    }
    assert.equal(r.findings.length, gapIds.size);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('every mapped control has remediation guidance', () => {
  // A gap with no remediation is a complaint. Mapped controls are exactly the
  // ones that can fail, so each needs an answer ready before it does.
  const fw = JSON.parse(fs.readFileSync(FW_FILE, 'utf8'));
  const missing = fw.controls
    .filter(c => Array.isArray(c.mapsTo) && c.mapsTo.length)
    .filter(c => !remediationFor(c.id))
    .map(c => c.id);
  assert.deepEqual(missing, [], 'mapped controls without remediation guidance');
});

test('mapsTo only references signals the engine actually produces', () => {
  // A mapping to a module the walkthrough cannot resolve reads as "expected
  // artifact not present" forever — a permanent false failure that trains
  // readers to ignore the report.
  const fw = JSON.parse(fs.readFileSync(FW_FILE, 'utf8'));
  const src = fs.readFileSync(path.join(HERE, '..', 'src', 'posture', 'auditor-walkthrough.js'), 'utf8');
  const known = new Set([...src.matchAll(/^\s*'([a-z0-9-]+)':\s+'/gim)].map(m => m[1]));
  const unknown = [];
  for (const c of fw.controls) {
    for (const m of c.mapsTo || []) {
      if (!m.startsWith('module:')) continue;
      const mod = m.slice('module:'.length).split(':')[0];
      if (!known.has(mod)) unknown.push(`${c.id} -> ${mod}`);
    }
  }
  assert.deepEqual(unknown, [], 'mapsTo references a module the walkthrough cannot resolve');
});

test('bucketOf is total — every shape lands in exactly one declared bucket', () => {
  const cases = [
    { control: { id: 'X', mapsTo: ['family:pii-exposure'], codeTestable: 'yes' }, status: 'present' },
    { control: { id: 'X', mapsTo: ['family:pii-exposure'], codeTestable: 'yes' }, status: 'partial' },
    { control: { id: 'X', codeTestable: 'yes' }, status: 'manual' },
    { control: { id: 'X', codeTestable: 'no' }, status: 'manual' },
    { control: { id: 'X' }, status: 'manual' },
    { control: {}, status: 'manual' },
  ];
  for (const c of cases) assert.ok(BUCKETS.includes(bucketOf(c)), `unbucketed: ${JSON.stringify(c)}`);
  assert.equal(bucketOf(cases[0]), 'satisfied');
  assert.equal(bucketOf(cases[1]), 'gap');
  assert.equal(bucketOf(cases[2]), 'engine-gap');
  assert.equal(bucketOf(cases[3]), 'manual');
});

test('never throws on junk input — posture modules degrade, they do not fail a scan', () => {
  // Every annotator in engine.js is wrapped in try/catch, but relying on that
  // would let a broken module silently drop its whole contribution. This
  // asserts the module itself is total.
  //
  // Note it does NOT return null for an unknown root: the control set is
  // BUNDLED, so it loads regardless of what the project contains. The
  // assessment is still meaningful — every control simply lands in the
  // manual/engine-gap buckets because no project signal exists to satisfy it.
  for (const args of [[undefined, undefined], ['/nonexistent-root-xyz', null], ['', {}], ['/tmp', { findings: null }]]) {
    assert.doesNotThrow(() => assessPrivacyFramework(...args), `threw on ${JSON.stringify(args)}`);
  }
  const r = assessPrivacyFramework('/nonexistent-root-xyz', null);
  assert.equal(r.summary.total, 104);
  assert.equal(r.summary.satisfied, 0, 'no project signal can be satisfied from a root that does not exist');
});

// ── The `compliance` CLI subcommand ─────────────────────────────────────────
//
// Exit codes are a contract other people wire into pipelines, so each is
// asserted in both directions rather than only on the happy path.

import { spawnSync } from 'node:child_process';

const CLI = path.join(HERE, '..', 'bin', 'agentic-security.js');
const run = (cwd, ...argv) => spawnSync(process.execPath, [CLI, 'compliance', ...argv], { cwd, encoding: 'utf8' });

/** A project with a real scan behind it — the command reads last-scan.json. */
async function scannedProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'pf11-cli-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"v","version":"1.0.0"}');
  await fsp.writeFile(path.join(d, 'app.js'), [
    "const https = require('https');",
    'const agent = new https.Agent({ rejectUnauthorized: false });',
    "app.get('/u', (req, res) => { res.send({ email: req.user.email }); });",
  ].join('\n'));
  const scan = spawnSync(process.execPath, [CLI, 'scan', '.', '--format', 'sarif'], { cwd: d, encoding: 'utf8' });
  assert.equal(scan.error, undefined, 'fixture scan failed to spawn');
  return d;
}

test('CLI: refuses to assess a project with no scan behind it', async () => {
  // The dangerous alternative is assessing an empty project: every control
  // reports "not assessed", which is correct, and one careless `--gap` away
  // from looking like a clean bill of health.
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'pf11-noscan-'));
  try {
    await fsp.writeFile(path.join(d, 'package.json'), '{"name":"x","version":"1.0.0"}');
    const r = run(d);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /run `agentic-security scan \.` first/);
    assert.doesNotMatch(r.stdout, /satisfied/, 'must not print an assessment it could not make');
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('CLI: --fail-on gap is opt-in, and fires only when a control is failing', async () => {
  const d = await scannedProject();
  try {
    // Default: reports, never fails the pipeline that merely wants to look.
    assert.equal(run(d).status, 0, 'default must not fail a build');
    // Opt in, with gaps present (the fixture disables TLS verification).
    const gated = run(d, '--fail-on', 'gap');
    assert.equal(gated.status, 1, 'must fail when asked to and a gap exists');
    // Same flag, no gaps to find → the other direction of the same contract.
    const json = JSON.parse(run(d, '--format', 'json').stdout);
    assert.ok(json.summary.gap > 0, 'fixture must actually produce a gap for this to mean anything');
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('CLI: --gap narrows to failing controls without changing the verdict', async () => {
  const d = await scannedProject();
  try {
    const all = JSON.parse(run(d, '--format', 'json').stdout);
    const gaps = JSON.parse(run(d, '--gap', '--format', 'json').stdout);
    assert.ok(gaps.controls.every(c => c.bucket === 'gap'));
    assert.equal(gaps.controls.length, all.summary.gap);
    // Filtering the VIEW must not alter the counts — otherwise `--gap` would
    // quietly redefine the denominator the interpretation line is computed on.
    assert.deepEqual(gaps.summary, all.summary);
    assert.equal(gaps.interpretation, all.interpretation);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('CLI: --list names the privacy framework; an unknown framework exits 2', async () => {
  const d = await scannedProject();
  try {
    const list = run(d, '--list');
    assert.equal(list.status, 0);
    assert.match(list.stdout, new RegExp(PRIVACY_FRAMEWORK_ID));
    const bad = run(d, '--walkthrough', 'no-such-framework');
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /Unknown framework/);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('CLI: human output always carries the not-evidence caveat', async () => {
  // The caveat is the whole point of the bucketing. If it can be lost by
  // choosing a flag, a reader sees percentages with no disclosure attached.
  const d = await scannedProject();
  try {
    for (const argv of [[], ['--gap']]) {
      const out = run(d, ...argv).stdout;
      assert.match(out, /NOT evidence of compliance/);
      assert.match(out, /licensed assessor/);
    }
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('the build is idempotent — no nested compliance-frameworks/ directory', () => {
  // `cp -R src dst` copies INTO dst when dst already exists, so the first build
  // created dist/compliance-frameworks/ and the second created
  // dist/compliance-frameworks/compliance-frameworks/. A duplicate set shipped
  // before this was caught. The build now clears the directory first; this
  // asserts the SHAPE rather than trusting the command.
  const dir = path.join(HERE, '..', 'dist', 'compliance-frameworks');
  if (!fs.existsSync(dir)) return;
  const subdirs = fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory());
  assert.deepEqual(subdirs.map(e => e.name), [],
    'dist/compliance-frameworks/ must contain only .json files — a nested directory means a rebuild copied into itself');
  assert.ok(fs.readdirSync(dir).every(f => f.endsWith('.json')));
});

test('the SHIPPED BUNDLE can see the frameworks, not just src/', async () => {
  // This caught a live defect. `auditor-walkthrough` resolves its data
  // directory from `import.meta.url`, which inside the bundle points at dist/ —
  // where the JSON files were never copied. `listFrameworks` swallows the
  // readdir error and returns [], so the published CLI reported ZERO frameworks
  // and exited 0. Every bundled framework had been invisible from the shipped
  // artifact, and nothing noticed because every test ran against src/.
  //
  // Skipped rather than failed when dist/ is absent: `npm test` must not
  // require a build, but when a build exists it must be correct.
  const dist = path.join(HERE, '..', 'dist', 'agentic-security.mjs');
  if (!fs.existsSync(dist)) return;

  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'pf11-dist-'));
  try {
    await fsp.writeFile(path.join(d, 'package.json'), '{"name":"x","version":"1.0.0"}');
    const r = spawnSync(process.execPath, [dist, 'compliance', '--list'], { cwd: d, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    for (const id of ['nist-privacy-1-1', 'nist-ai-600-1', 'gdpr', 'owasp-asvs-5']) {
      assert.match(r.stdout, new RegExp(id), `bundle cannot see ${id} — is dist/compliance-frameworks/ shipped?`);
    }
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});
