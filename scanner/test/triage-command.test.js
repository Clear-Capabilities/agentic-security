// S6 — commands/triage.md must work with the non-interactive stdin the
// harness actually provides.
//
// The default `/triage` walk used a Node `readline` interface blocking on
// `rl.question()`. Reproduced live before fixing: run with stdin closed
// (`< /dev/null`, the real condition — nothing types into this subprocess's
// stdin because the "terminal" is the conversation, not this process), it
// printed the `[t]p ... ?` prompt once, recorded nothing, and exited 0 in
// ~65ms — `rl.question`'s callback never fires on a closed/EOF stdin. The
// primary triage surface and the only feeder of the active-learning loop
// (FR-PREC-4) were inoperable inside the product that ships them.
//
// Fixed by splitting the readline loop into two non-interactive one-shot
// steps: Step 1 lists findings as JSON (no prompt, no blocking read); Step 2
// records exactly one verdict per invocation from argv, driven by the
// assistant conversing with the user instead of a subprocess reading a TTY.
// These tests extract both fenced bash blocks from the actual command
// markdown (not a hand-copied duplicate) and run them for real, stdin closed
// throughout, pinning both the "does not hang" property and the write
// behavior itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function extractStep(stepHeading) {
  const md = fs.readFileSync(path.join(REPO_ROOT, 'commands', 'triage.md'), 'utf8');
  const lines = md.split('\n');
  const headingIdx = lines.findIndex((l) => l.trim() === stepHeading);
  assert.ok(headingIdx >= 0, `expected to find "${stepHeading}" in commands/triage.md`);
  const fenceStart = lines.findIndex((l, i) => i > headingIdx && l.trim() === '```bash');
  const fenceEnd = lines.findIndex((l, i) => i > fenceStart && l.trim() === '```');
  assert.ok(fenceStart > headingIdx && fenceEnd > fenceStart, `expected a fenced bash block after "${stepHeading}"`);
  return lines.slice(fenceStart + 1, fenceEnd).join('\n');
}

async function mkProject(findings) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'triage-cmd-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings }));
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function runStep(script, { cwd, env = {}, arg = '' }) {
  const scriptPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'triage-step-')), 'run.sh');
  fs.writeFileSync(scriptPath, script);
  try {
    const out = execFileSync('bash', [scriptPath, arg], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], // 'ignore' stdin = closed, the exact original failure condition
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: REPO_ROOT, ...env },
      timeout: 10000,
    });
    return { status: 0, stdout: out };
  } catch (e) {
    return { status: e.status, stdout: e.stdout || '', stderr: e.stderr || '', signal: e.signal };
  }
}

test('S6: neither triage.md step uses a blocking readline interface', () => {
  // Scoped to the two fenced bash blocks specifically, not the surrounding
  // prose — the prose legitimately NAMES rl.question() once, to document
  // what the old, broken design did and why it was replaced.
  const step1 = extractStep('### Step 1 — list findings needing triage');
  const step2 = extractStep('### Step 2 — record one verdict');
  for (const [label, script] of [['Step 1', step1], ['Step 2', step2]]) {
    assert.doesNotMatch(script, /require\(['"]readline['"]\)/, `${label}: readline blocks on stdin the harness never provides input on`);
    assert.doesNotMatch(script, /rl\.question/, `${label} must not block on rl.question`);
  }
});

test('S6: Step 1 (list) does not hang on closed stdin and returns the findings as JSON', async () => {
  const script = extractStep('### Step 1 — list findings needing triage');
  const p = await mkProject([
    { id: 'F1', stableId: 'S1', vuln: 'SQL injection', severity: 'high', file: 'a.js', line: 5, exploitability: 0.8, confidence: 0.9 },
  ]);
  try {
    const r = runStep(script, { cwd: p.dir });
    assert.equal(r.status, 0, `must exit 0 with closed stdin; stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0].stableId, 'S1');
  } finally { await p.cleanup(); }
});

test('S6: Step 2 (record) does not hang on closed stdin and persists the verdict when LEARN is enabled', async () => {
  const script = extractStep('### Step 2 — record one verdict');
  const p = await mkProject([]);
  try {
    const r = runStep(script, {
      cwd: p.dir,
      env: {
        AGENTIC_SECURITY_LEARN: '1',
        STABLE_ID: 'S1', VULN: 'SQL injection', FILE: 'a.js', LINE: '5', FAMILY: 'sqli', SNIPPET: '-',
        VERDICT: 'tp', REASON: 'confirmed via manual review',
      },
    });
    assert.equal(r.status, 0, `must exit 0 with closed stdin; stderr: ${r.stderr}`);
    const feedback = JSON.parse(fs.readFileSync(path.join(p.dir, '.agentic-security', 'triage-feedback.json'), 'utf8'));
    assert.equal(feedback.entries.length, 1);
    assert.equal(feedback.entries[0].stableId, 'S1');
    assert.equal(feedback.entries[0].verdict, 'tp');
    assert.equal(feedback.entries[0].file, 'a.js');
    assert.equal(feedback.entries[0].line, 5);
  } finally { await p.cleanup(); }
});

test('S6: Step 2 does not persist a verdict when AGENTIC_SECURITY_LEARN is unset', async () => {
  const script = extractStep('### Step 2 — record one verdict');
  const p = await mkProject([]);
  try {
    const r = runStep(script, { cwd: p.dir, env: { STABLE_ID: 'S1', VERDICT: 'fp' } });
    assert.equal(r.status, 0);
    assert.ok(!fs.existsSync(path.join(p.dir, '.agentic-security', 'triage-feedback.json')),
      'read-only mode (no LEARN flag) must not write triage-feedback.json');
  } finally { await p.cleanup(); }
});

// Stage 2 measurement-completeness audit: posture/calibration-drift.js needs
// each triage-feedback.json entry's reportedConfidence to compare against
// realized accuracy, but nothing ever captured it — Step 1 now emits it
// (preferring calibrated_confidence over the raw ordinal confidence) and
// Step 2 now threads it through into the persisted entry.
test('S6: Step 1 emits reportedConfidence, preferring calibrated_confidence over the raw ordinal confidence', async () => {
  const script = extractStep('### Step 1 — list findings needing triage');
  const p = await mkProject([
    { id: 'F1', stableId: 'S1', vuln: 'SQLi', confidence: 0.9, calibrated_confidence: 0.42 },
    { id: 'F2', stableId: 'S2', vuln: 'XSS', confidence: 0.7 },
  ]);
  try {
    const r = runStep(script, { cwd: p.dir });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    const f1 = parsed.find((f) => f.stableId === 'S1');
    const f2 = parsed.find((f) => f.stableId === 'S2');
    assert.equal(f1.reportedConfidence, 0.42, 'must prefer calibrated_confidence when present');
    assert.equal(f2.reportedConfidence, 0.7, 'falls back to the raw ordinal confidence when no calibration exists');
  } finally { await p.cleanup(); }
});

test('S6: Step 2 records reportedConfidence when passed through', async () => {
  const script = extractStep('### Step 2 — record one verdict');
  const p = await mkProject([]);
  try {
    const r = runStep(script, {
      cwd: p.dir,
      env: {
        AGENTIC_SECURITY_LEARN: '1',
        STABLE_ID: 'S1', VULN: 'SQL injection', FILE: 'a.js', LINE: '5', FAMILY: 'sqli', SNIPPET: '-',
        REPORTED_CONFIDENCE: '0.42', VERDICT: 'tp', REASON: 'confirmed via manual review',
      },
    });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const feedback = JSON.parse(fs.readFileSync(path.join(p.dir, '.agentic-security', 'triage-feedback.json'), 'utf8'));
    assert.equal(feedback.entries[0].reportedConfidence, 0.42);
  } finally { await p.cleanup(); }
});

test('S6: Step 2 records reportedConfidence as null when omitted (no false precision)', async () => {
  const script = extractStep('### Step 2 — record one verdict');
  const p = await mkProject([]);
  try {
    const r = runStep(script, {
      cwd: p.dir,
      env: { AGENTIC_SECURITY_LEARN: '1', STABLE_ID: 'S1', VERDICT: 'tp' },
    });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const feedback = JSON.parse(fs.readFileSync(path.join(p.dir, '.agentic-security', 'triage-feedback.json'), 'utf8'));
    assert.equal(feedback.entries[0].reportedConfidence, null);
  } finally { await p.cleanup(); }
});

test('S6: Step 2 rejects an invalid verdict rather than recording garbage', async () => {
  const script = extractStep('### Step 2 — record one verdict');
  const p = await mkProject([]);
  try {
    const r = runStep(script, { cwd: p.dir, env: { AGENTIC_SECURITY_LEARN: '1', STABLE_ID: 'S1', VERDICT: 'bogus' } });
    assert.notEqual(r.status, 0);
  } finally { await p.cleanup(); }
});
