// S7 — commands/compliance.md's Implementation section named backing
// modules in prose ("Routes to the posture modules ... and the scanner
// CLI") without a single concrete invocation for --report, --attestation,
// --audit, --pr, or --gap <framework>. --walkthrough and bare --gap/
// --privacy already passed through to the real `agentic-security
// compliance` CLI subcommand.
//
// Wiring --pr surfaced posture/pr-augment.js#augmentPrBody/persistBaseline —
// a fully real, independently unit-tested module (test/pr-augment.test.js)
// with ZERO prior callers anywhere in bin/agentic-security.js or engine.js.
// Wiring --attestation surfaced two real, previously-uninvoked-from-here
// scripts: scripts/security-onepager.py and scripts/trust-page.py.
//
// `--format oscal` was documented here for a long time before anything
// implemented it, and the doc was corrected to say so rather than left
// aspirational. It is now real (scanner/src/report/oscal.js) and this file
// checks the COMMAND SURFACE reaches it — the document's own structure is
// pinned by test/oscal-conformance.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = path.join(REPO_ROOT, 'scanner', 'test', 'fixtures', 'vulnerable-js');
const CLI = path.join(REPO_ROOT, 'scanner', 'dist', 'agentic-security.mjs');

function extractImplementationBlock() {
  const md = fs.readFileSync(path.join(REPO_ROOT, 'commands', 'compliance.md'), 'utf8');
  const lines = md.split('\n');
  const headingIdx = lines.findIndex((l) => l.trim() === '## Implementation');
  const fenceStart = lines.findIndex((l, i) => i > headingIdx && l.trim() === '```bash');
  const fenceEnd = lines.findIndex((l, i) => i > fenceStart && l.trim() === '```');
  assert.ok(fenceStart > headingIdx && fenceEnd > fenceStart, 'expected a fenced bash block under ## Implementation');
  return lines.slice(fenceStart + 1, fenceEnd).join('\n');
}

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'compliance-cmd-'));
  fs.cpSync(FIXTURE, dir, { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function runMode(script, args, cwd) {
  const scriptPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-run-')), 'run.sh');
  fs.writeFileSync(scriptPath, script);
  try {
    const out = execFileSync('bash', [scriptPath, ...args], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: REPO_ROOT },
      timeout: 30000,
    });
    return { status: 0, stdout: out };
  } catch (e) {
    return { status: e.status, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

async function scannedProject() {
  const p = await mkProject();
  const r = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
  assert.ok(r.status <= 3, `scan must exit <=3; got ${r.status}: ${r.stderr}`);
  return p;
}

test('S7: compliance.md --report with no prior scan exits 2 honestly', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject();
  try {
    const r = runMode(script, ['--report', 'nist'], p.dir);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /run a scan first/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --report nist --format json returns a real evaluation with alias resolved', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--report', 'nist', '--format', 'json'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.framework.id, 'nist-ai-600-1');
    assert.ok(Array.isArray(parsed.evaluation) && parsed.evaluation.length > 0);
    // `absent` is the fourth status evaluateFramework can return (signals
    // exist, none cleared). It happens not to occur on this fixture, so
    // omitting it here passed — and the same omission in the OSCAL adapter
    // silently relabelled real control failures as "needs human review".
    for (const e of parsed.evaluation) assert.match(e.status, /^(present|partial|absent|manual)$/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --report --format oscal emits a real OSCAL assessment-results document', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--report', 'nist', '--format', 'oscal'], p.dir);
    assert.equal(r.status, 0, r.stderr);
    const doc = JSON.parse(r.stdout);
    // Enough to prove the command reached the exporter and produced the right
    // MODEL, not a json evaluation with a different name. Field-level
    // conformance is test/oscal-conformance.test.js's job, not this file's.
    assert.match(doc.metadata['oscal-version'], /^1\./);
    assert.ok(doc['import-ap'], 'assessment-results requires import-ap');
    const result = doc.results[0];
    assert.ok(result['reviewed-controls']['control-selections'][0]['include-controls'].length > 0,
      'a control assessment must name the controls it reviewed');
    // The doctrine, checked at the surface a user actually invokes: a control
    // nobody could decide must not appear as a finding.
    const unassessed = result.observations.filter(
      (o) => o.props.some((x) => x.name === 'assessment-status' && x.value === 'manual'));
    const targets = new Set((result.findings || []).map((f) => f.target['target-id']));
    for (const o of unassessed) {
      const id = o.props.find((x) => x.name === 'source-control-id').value;
      assert.ok(!targets.has(id), `unassessed control ${id} was published as a finding`);
    }
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --report with an unknown framework exits 2', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--report', 'not-a-real-framework'], p.dir);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /Unknown framework/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --walkthrough renders the real auditor narrative for a bundled framework', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--walkthrough', 'owasp-asvs-5'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /Auditor walkthrough/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --attestation --format badge renders a real SVG', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--attestation', '--format', 'badge'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /<svg/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --attestation --format onepager writes a real Markdown one-pager', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--attestation', '--format', 'onepager'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /# How .* Keeps Your Data Safe/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --audit db filters real matching findings', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--audit', 'db'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.target, 'db');
    assert.ok(parsed.matchedCount > 0, 'the vulnerable-js fixture has a real SQL injection finding');
    for (const f of parsed.findings) assert.match(f.vuln.toLowerCase(), /sql|database/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --audit deploy runs the real /secure readiness check, not a findings filter', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--audit', 'deploy'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const jsonStart = r.stdout.indexOf('{');
    const parsed = JSON.parse(r.stdout.slice(jsonStart));
    assert.ok(parsed.action, `expected a real router decision object, got: ${r.stdout}`);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --audit with an unknown target lists the valid ones', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--audit', 'not-a-real-target'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.match(parsed.message, /Unknown --audit target/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --pr with no baseline shows the whole scan as added', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--pr'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /Baseline against `main` not found/);
    assert.match(r.stdout, /Findings delta vs `main`/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --pr --persist-baseline writes a real baseline, then diffs cleanly against it', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const persistResult = runMode(script, ['--pr', '--persist-baseline', 'main'], p.dir);
    assert.equal(persistResult.status, 0, `stderr: ${persistResult.stderr}`);
    const persisted = JSON.parse(persistResult.stdout);
    assert.ok(fs.existsSync(persisted.persisted), 'persistBaseline must write a real file');

    const diffResult = runMode(script, ['--pr'], p.dir);
    assert.equal(diffResult.status, 0, `stderr: ${diffResult.stderr}`);
    assert.match(diffResult.stdout, /No new findings vs baseline/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --gap with no framework runs the real privacy-framework CLI gap filter', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--gap'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /NIST Privacy Framework/);
  } finally { await p.cleanup(); }
});

test('S7: compliance.md --gap nist filters a real framework evaluation to non-present controls', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, ['--gap', 'nist'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.framework, 'nist-ai-600-1');
    assert.ok(parsed.gapCount >= 0);
    for (const g of parsed.gaps) assert.notEqual(g.status, 'present');
  } finally { await p.cleanup(); }
});

test('S7: compliance.md bare (no flag) runs the real privacy-framework assessment', async () => {
  const script = extractImplementationBlock();
  const p = await scannedProject();
  try {
    const r = runMode(script, [], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /NIST Privacy Framework/);
  } finally { await p.cleanup(); }
});
