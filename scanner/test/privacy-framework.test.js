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
