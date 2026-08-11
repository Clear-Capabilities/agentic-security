// S2 — scripts/predeploy-gate.sh: the pre-deploy gate must fail CLOSED when
// it cannot determine safety, and its KEV check must actually observe KEV
// exposure from the scan it reads.
//
// Two bugs, reproduced live before being fixed:
//
// (a) `read -r crit high med <<< $(python3 -c "...")` leaves crit/high/med
//     EMPTY (not "0") when python3 is missing or the JSON is unreadable.
//     `[ "$crit" -gt 0 ]` then errors ("integer expression expected"); that
//     error makes the `&&` chain evaluate to false, `blocking` stays 0, and
//     the gate prints "✅ Safe to deploy." — fail-open on exactly the
//     condition ("I could not read the scan") that should refuse loudest.
//
// (b) The KEV check reads `data.get('kev', []) or data.get('kevExposure', [])`
//     — a top-level array that last-scan.json never has. KEV status is a
//     per-finding boolean (`f.kev === true`, see report/index.js:310). The
//     branch was therefore permanently dead: `block_on_kev` could never fire
//     regardless of what the scan actually found.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'predeploy-gate.sh');

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'predeploy-'));
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function writeScan(dir, scan) {
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify(scan));
}

// Runs `bash predeploy-gate.sh check` against a fixture dir. `envOverrides`
// lets a case break python3's availability by pointing PATH at a directory
// with no python3 on it, without touching the real host PATH.
function runGate(dir, envOverrides = {}) {
  try {
    const out = execFileSync('bash', [SCRIPT, 'check'], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, ...envOverrides },
    });
    return { status: 0, output: out };
  } catch (e) {
    return { status: e.status, output: (e.stdout || '') + (e.stderr || '') };
  }
}

test('S2: a clean, fresh scan passes', async () => {
  const p = await mkProject();
  try {
    writeScan(p.dir, { findings: [], logicVulns: [], supplyChain: [] });
    const r = runGate(p.dir);
    assert.equal(r.status, 0, r.output);
    assert.match(r.output, /Safe to deploy/);
  } finally { await p.cleanup(); }
});

test('S2: a critical finding still blocks (regression pin)', async () => {
  const p = await mkProject();
  try {
    writeScan(p.dir, { findings: [{ severity: 'critical' }], logicVulns: [], supplyChain: [] });
    const r = runGate(p.dir);
    assert.notEqual(r.status, 0);
    assert.match(r.output, /BLOCKED/);
  } finally { await p.cleanup(); }
});

test('S2: a KEV-listed dependency blocks when block_on_kev is set', async () => {
  const p = await mkProject();
  try {
    writeScan(p.dir, { findings: [], logicVulns: [], supplyChain: [{ severity: 'medium', kev: true, name: 'left-pad' }] });
    const r = runGate(p.dir);
    assert.notEqual(r.status, 0, r.output);
    assert.match(r.output, /KEV/i);
  } finally { await p.cleanup(); }
});

test('S2: an unparseable scan file fails CLOSED, never reports safe', async () => {
  const p = await mkProject();
  try {
    fs.mkdirSync(path.join(p.dir, '.agentic-security'), { recursive: true });
    // Malformed JSON — this is what a python3-missing host reduces to as
    // well: `python3 -c "json.load(...)"` produces nothing on stdout either
    // way, so this reproduces the exact bug without depending on manipulating
    // PATH (which affects resolving `bash`/coreutils themselves, not just
    // python3, and so cannot reliably isolate this condition).
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'last-scan.json'), '{not valid json');
    const r = runGate(p.dir);
    assert.notEqual(r.status, 0, `must not report success when it could not read the scan; got: ${r.output}`);
    assert.doesNotMatch(r.output, /Safe to deploy/);
  } finally { await p.cleanup(); }
});
