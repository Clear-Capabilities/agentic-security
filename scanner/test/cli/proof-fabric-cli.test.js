// End-to-end CLI coverage for the Universal Exploit Proof Fabric (PRD 1): `proof show|replay|doctor`,
// `triage exploit --prove`, `triage list --evidence`, and `fix --require-proof`. Every invocation runs the real,
// spawned CLI with stdin closed — nothing here waits on a prompt.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { signLastScan } from '../../src/posture/integrity.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const run = (args, opts = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'], ...opts });
const runIn = (dir, args, opts = {}) => run(args, { cwd: dir, ...opts });

function mkProject(findings = [], { signed = false } = {}) {
  const dir = mkTestTmp('pf-cli-');
  fs.mkdirSync(path.join(dir, '.git'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  const body = JSON.stringify({ findings });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), body);
  if (signed) fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
  fs.writeFileSync(path.join(dir, '.agentic-security', 'findings.json'), body);
  return dir;
}

const REPRODUCER = { schema: 'agentic-security/reproducer', version: 1, findingId: 'F1', lang: 'javascript', files: { 'a.mjs': "import fs from 'node:fs'; fs.writeFileSync('{{CANARY:command}}','x');" }, run: ['{{NODE}}', 'a.mjs'], oracle: { type: 'command_execution', params: { canary: 'command' } } };
const FINDING = { id: 'F1', stableId: 'F1', severity: 'critical', vuln: 'command injection', file: 'app.js', line: 1, parser: 'IR-TAINT' };

test('proof doctor runs non-interactively and exits 0 or 1, never hangs', () => {
  const r = run(['proof', 'doctor']);
  assert.ok(r.status === 0 || r.status === 1, r.stderr);
  assert.match(r.stdout, /Proof fabric doctor/);
});

test('triage exploit without --prove refuses, no execution', () => {
  const dir = mkProject([FINDING]);
  const r = runIn(dir, ['triage', 'exploit', 'F1']);
  assert.equal(r.status, 4);
  assert.match(r.stderr, /--prove/);
});

test('triage exploit --prove with no reproducer refuses cleanly', () => {
  const dir = mkProject([FINDING]);
  const r = runIn(dir, ['triage', 'exploit', 'F1', '--prove']);
  assert.equal(r.status, 4);
  assert.match(r.stderr, /No reproducer/);
});

test('triage exploit --prove with a real reproducer confirms the exploit and stores a proof', { skip: !sandboxAvailable() && 'no confinement backend on this host' }, () => {
  const dir = mkProject([FINDING]);
  const reproFile = path.join(dir, 'repro.json');
  fs.writeFileSync(reproFile, JSON.stringify(REPRODUCER));
  const r = runIn(dir, ['triage', 'exploit', 'F1', '--prove', '--reproducer', reproFile]);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /EXPLOIT_CONFIRMED/);
  assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'proofs')));

  const show = runIn(dir, ['proof', 'show', 'F1']);
  assert.equal(show.status, 0, show.stderr);
  assert.match(show.stdout, /EXPLOIT_CONFIRMED/);

  const replay = runIn(dir, ['proof', 'replay', 'F1']);
  assert.equal(replay.status, 0, replay.stderr + replay.stdout);
  assert.match(replay.stdout, /EXPLOIT_CONFIRMED/);
});

test('triage list --evidence shows the stored evidence state without altering default output', { skip: !sandboxAvailable() && 'no confinement backend on this host' }, () => {
  const dir = mkProject([FINDING]);
  assert.equal(runIn(dir, ['profile', 'set', 'pro']).status, 0);
  const reproFile = path.join(dir, 'repro.json');
  fs.writeFileSync(reproFile, JSON.stringify(REPRODUCER));
  runIn(dir, ['triage', 'exploit', 'F1', '--prove', '--reproducer', reproFile]);
  const plain = runIn(dir, ['triage', 'list']);
  assert.equal(plain.status, 0, plain.stderr);
  assert.ok(!plain.stdout.includes('Evidence'));
  const withEvidence = runIn(dir, ['triage', 'list', '--evidence']);
  assert.equal(withEvidence.status, 0, withEvidence.stderr);
  assert.match(withEvidence.stdout, /EXPLOIT_CONFIRMED/);
});

test('fix --require-proof refuses to apply without a reproducer; nothing is written', () => {
  const dir = mkProject([{ ...FINDING, fix: { replaceLine: 'safe();' } }], { signed: true });
  fs.writeFileSync(path.join(dir, 'app.js'), 'vulnerable();\n');
  const r = runIn(dir, ['fix', '--finding', 'F1', '--apply', '--require-proof']);
  assert.equal(r.status, 4, r.stderr + r.stdout);
  assert.match(r.stderr, /no reproducer/i);
  assert.equal(fs.readFileSync(path.join(dir, 'app.js'), 'utf8'), 'vulnerable();\n');
});
