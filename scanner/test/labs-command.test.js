// S7 — commands/labs.md's Implementation section named backing modules in
// prose ("Routes to existing posture modules: claude-authorship.js,
// model-rescan.js, ...") without a single concrete invocation. Six of the
// seven modes (--claude-audit, --cross-repo, --risk-dollars, --time-to-fix,
// --synthesize-rule, --llm) are now fixed with real, verified commands.
// --model-rescan stays disclosed as genuinely unwired: posture/model-rescan.js
// expects a {model, results} run file that nothing in the codebase produces.
//
// Wiring --claude-audit / --cross-repo / --risk-dollars / --time-to-fix
// surfaced a real bug: posture/git-history.js#annotateGitHistory (aiAuthored,
// originatingPrompt, introducedBy/In/At/InMessage), posture/risk-dollars.js#
// annotateRiskDollars (riskDollars), and posture/time-to-fix.js#
// annotateTimeToFix (estimatedFixHours) are all wired into engine.js's
// annotation pipeline and stamp real fields on every finding — but
// report/index.js's normalizeFindings() per-finding allowlist dropped every
// one of them, so last-scan.json (what every /labs mode and every downstream
// consumer reads) never carried this data. Fixed alongside this file — see
// test/annotator-errors.test.js.
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
const LLM_FIXTURE = path.join(REPO_ROOT, 'scanner', 'test', 'fixtures', 'llm-owasp');
const CLI = path.join(REPO_ROOT, 'scanner', 'dist', 'agentic-security.mjs');

function extractImplementationBlock() {
  const md = fs.readFileSync(path.join(REPO_ROOT, 'commands', 'labs.md'), 'utf8');
  const lines = md.split('\n');
  const headingIdx = lines.findIndex((l) => l.trim() === '## Implementation');
  const fenceStart = lines.findIndex((l, i) => i > headingIdx && l.trim() === '```bash');
  const fenceEnd = lines.findIndex((l, i) => i > fenceStart && l.trim() === '```');
  assert.ok(fenceStart > headingIdx && fenceEnd > fenceStart, 'expected a fenced bash block under ## Implementation');
  return lines.slice(fenceStart + 1, fenceEnd).join('\n');
}

async function mkProject(srcDir) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'labs-cmd-'));
  fs.cpSync(srcDir, dir, { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function runMode(script, args, cwd) {
  const scriptPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'labs-run-')), 'run.sh');
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

function initGit(dir, message) {
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['add', '-A'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-m', message], { cwd: dir });
}

test('S7: labs.md --claude-audit reports "no prior scan" honestly when none exists', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const r = runMode(script, ['--claude-audit'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.match(parsed.message, /No prior scan/);
  } finally { await p.cleanup(); }
});

test('S7: labs.md --claude-audit detects a real AI-authored finding via the Claude co-author trailer', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    initGit(p.dir, 'initial');
    fs.appendFileSync(path.join(p.dir, 'app.js'), '\nconst x = eval(req.body.expr2);\n');
    execFileSync('git', ['add', '-A'], { cwd: p.dir });
    execFileSync('git', ['-c', 'user.email=t@t.com', '-c', 'user.name=t', 'commit', '-q', '-m',
      'add eval endpoint\n\nCo-Authored-By: Claude <noreply@anthropic.com>'], { cwd: p.dir });

    const scanResult = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(scanResult.status <= 3, `scan must exit <=3; got ${scanResult.status}: ${scanResult.stderr}`);

    const r = runMode(script, ['--claude-audit'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.ok(parsed.analysis.ai >= 1, `expected at least 1 AI-authored finding, got: ${JSON.stringify(parsed.analysis)}`);
  } finally { await p.cleanup(); }
});

test('S7: labs.md --risk-dollars ranks real findings by expected-value USD', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const scanResult = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(scanResult.status <= 3, `scan must exit <=3; got ${scanResult.status}: ${scanResult.stderr}`);

    const r = runMode(script, ['--risk-dollars', '--top', '3'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.ok(parsed.total > 0, 'expected real findings with riskDollars attached');
    assert.ok(parsed.top.length > 0 && parsed.top.length <= 3);
    for (let i = 1; i < parsed.top.length; i++) {
      assert.ok(parsed.top[i - 1].evUsd >= parsed.top[i].evUsd, 'top must be sorted descending by evUsd');
    }
  } finally { await p.cleanup(); }
});

test('S7: labs.md --time-to-fix rolls up real estimatedFixHours per family', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const scanResult = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(scanResult.status <= 3, `scan must exit <=3; got ${scanResult.status}: ${scanResult.stderr}`);

    const r = runMode(script, ['--time-to-fix'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.ok(parsed.perFinding > 0);
    assert.ok(parsed.totalHours > 0);
    assert.match(parsed.summary, /engineering hours/);
  } finally { await p.cleanup(); }
});

test('S7: labs.md --cross-repo looks up a real finding by id and reports empty sibling signals honestly', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const scanResult = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(scanResult.status <= 3, `scan must exit <=3; got ${scanResult.status}: ${scanResult.stderr}`);
    const scan = JSON.parse(fs.readFileSync(path.join(p.dir, '.agentic-security', 'last-scan.json'), 'utf8'));
    const id = scan.findings[0].id;

    const r = runMode(script, ['--cross-repo', id], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.finding.id, id);
    assert.ok(Array.isArray(parsed.signals.siblingFixes));
    assert.ok(Array.isArray(parsed.signals.siblingTriage));
  } finally { await p.cleanup(); }
});

test('S7: labs.md --cross-repo with no finding-id prints usage', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const scanResult = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(scanResult.status <= 3, `scan must exit <=3; got ${scanResult.status}: ${scanResult.stderr}`);

    const r = runMode(script, ['--cross-repo'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.match(parsed.message, /Usage/);
  } finally { await p.cleanup(); }
});

test('S7: labs.md --synthesize-rule invokes the real synthesize-detector.mjs script and its own gate refuses without the LLM env vars', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const r = runMode(script, ['--synthesize-rule', '--cwe', 'CWE-79', '--lang', 'java', '--files', 'x.java'], p.dir);
    assert.equal(r.status, 2, `expected the real script's own gate exit code 2, got ${r.status}`);
    assert.match(r.stderr, /AGENTIC_SECURITY_LLM_VALIDATE/);
  } finally { await p.cleanup(); }
});

test('S7: labs.md --llm surfaces real OWASP-LLM-tagged findings and an AI-BOM', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(LLM_FIXTURE);
  try {
    fs.writeFileSync(path.join(p.dir, 'pyproject.toml'), '[tool.poetry]\nname = "labs-llm-fixture"\n');
    const r = runMode(script, ['--llm'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /# AI-BOM/);
    const markerIdx = r.stdout.indexOf('"owaspLlmFindingCount"');
    assert.ok(markerIdx >= 0, `expected an owaspLlmFindingCount object in output: ${r.stdout}`);
    const jsonStart = r.stdout.lastIndexOf('{', markerIdx);
    const parsed = JSON.parse(r.stdout.slice(jsonStart));
    assert.ok(parsed.owaspLlmFindingCount > 0, 'the llm-owasp fixture must produce real OWASP-LLM-tagged findings');
    for (const f of parsed.owaspLlmFindings) assert.match(f.owaspLlm, /^LLM\d+$/);
  } finally { await p.cleanup(); }
});

test('S7: labs.md --model-rescan honestly discloses it is unwired rather than fabricating a delta', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject(FIXTURE);
  try {
    const r = runMode(script, ['--model-rescan'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.wired, false);
  } finally { await p.cleanup(); }
});
