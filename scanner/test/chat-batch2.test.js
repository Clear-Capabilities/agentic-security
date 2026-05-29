// Tests for batch-2 Claude Code chat enhancements:
//   #2 intent-context.js
//   #7 git-history.js
//   #12 findings-memory.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { suppressByIntent, _internals as _iint } from '../src/posture/intent-context.js';
import { annotateGitHistory, generateAuthorPing, _internals as _igh } from '../src/posture/git-history.js';
import { queryFindingsMemory } from '../src/posture/findings-memory.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'cb2-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"cb2-test"}');
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── intent-context ─────────────────────────────────────────────────────────

test('intent: examples/ path triggers suppression', async () => {
  const p = await mkProject();
  try {
    const findings = [{ file: 'examples/sqli-demo.js', line: 5, family: 'sqli', severity: 'high', confidence: 0.9 }];
    const r = suppressByIntent(p.dir, findings);
    assert.equal(r.applied, 1);
    assert.equal(findings[0].intentSuppressed, true);
    assert.equal(findings[0].intentReason, 'intent-path-pattern');
    assert.ok(findings[0].confidence < 0.9);
  } finally { await p.cleanup(); }
});

test('intent: current-intent.md excluded-paths suppress findings', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, '.agentic-security', 'current-intent.md'),
      '# Intent\n- tutorial: SQLi demo\n- excluded-paths: ["src/demo/**"]\n',
    );
    const findings = [
      { file: 'src/demo/a.js', line: 1, family: 'sqli', confidence: 0.9 },
      { file: 'src/prod/b.js', line: 1, family: 'sqli', confidence: 0.9 },
    ];
    const r = suppressByIntent(p.dir, findings);
    assert.equal(r.applied, 1);
    assert.equal(findings[0].intentSuppressed, true);
    assert.equal(findings[1].intentSuppressed, undefined);
  } finally { await p.cleanup(); }
});

test('intent: file header @intentionally-vulnerable suppresses', async () => {
  const p = await mkProject();
  try {
    const fp = path.join(p.dir, 'src', 'training.js');
    await fsp.mkdir(path.dirname(fp), { recursive: true });
    await fsp.writeFile(fp, '/**\n * @intentionally-vulnerable for security training\n */\n');
    const findings = [{ file: fp, line: 1, family: 'sqli', confidence: 0.9 }];
    const r = suppressByIntent(p.dir, findings);
    assert.equal(r.applied, 1);
    assert.equal(findings[0].intentReason, 'intent-file-header');
  } finally { await p.cleanup(); }
});

test('intent: NO_INTENT_CTX disables', async () => {
  const p = await mkProject();
  try {
    process.env.AGENTIC_SECURITY_NO_INTENT_CTX = '1';
    try {
      const findings = [{ file: 'examples/x.js', line: 1, family: 'sqli', confidence: 0.9 }];
      const r = suppressByIntent(p.dir, findings);
      assert.equal(r.applied, 0);
    } finally { delete process.env.AGENTIC_SECURITY_NO_INTENT_CTX; }
  } finally { await p.cleanup(); }
});

test('intent: _globMatch supports ** + *', () => {
  assert.equal(_iint._globMatch('src/**', 'src/a/b/c.js'), true);
  assert.equal(_iint._globMatch('src/*.js', 'src/a.js'), true);
  assert.equal(_iint._globMatch('src/*.js', 'src/a/b.js'), false);
  assert.equal(_iint._globMatch('examples/**', 'examples/sqli.js'), true);
});

// ── git-history ────────────────────────────────────────────────────────────

test('git-history: skips when not in a git repo', async () => {
  const p = await mkProject();
  try {
    const findings = [{ file: 'a.js', line: 1, family: 'sqli' }];
    const r = annotateGitHistory(p.dir, findings);
    assert.equal(r.annotated, 0);
  } finally { await p.cleanup(); }
});

test('git-history: annotates findings on real git history', async () => {
  const p = await mkProject();
  try {
    const env = { GIT_AUTHOR_NAME: 'Test User', GIT_AUTHOR_EMAIL: 't@example.com',
                  GIT_COMMITTER_NAME: 'Test User', GIT_COMMITTER_EMAIL: 't@example.com' };
    cp.execSync('git init -q', { cwd: p.dir, env: { ...process.env, ...env } });
    cp.execSync('git config user.email t@example.com && git config user.name "Test User"', { cwd: p.dir });
    await fsp.writeFile(path.join(p.dir, 'a.js'), 'const x = 1;\nconst y = "vulnerable";\n');
    cp.execSync('git add a.js && git commit -q -m "initial — Co-Authored-By: Claude Opus 4.7"',
                { cwd: p.dir, env: { ...process.env, ...env } });
    const findings = [{ file: 'a.js', line: 2, family: 'sqli' }];
    const r = annotateGitHistory(p.dir, findings);
    assert.equal(r.annotated, 1);
    assert.equal(findings[0].introducedBy, 'Test User');
    assert.ok(findings[0].introducedIn);
    assert.equal(findings[0].aiAuthored, true, 'Claude trailer detected');
  } finally { await p.cleanup(); }
});

test('git-history: NO_GIT_HISTORY env disables', async () => {
  const p = await mkProject();
  try {
    process.env.AGENTIC_SECURITY_NO_GIT_HISTORY = '1';
    try {
      const findings = [{ file: 'a.js', line: 1 }];
      const r = annotateGitHistory(p.dir, findings);
      assert.equal(r.annotated, 0);
    } finally { delete process.env.AGENTIC_SECURITY_NO_GIT_HISTORY; }
  } finally { await p.cleanup(); }
});

test('git-history: generateAuthorPing renders Slack-ready text', () => {
  const ping = generateAuthorPing({
    file: 'src/auth.js', line: 14,
    severity: 'critical',
    vuln: 'SQL injection',
    introducedBy: 'Test User',
    introducedIn: 'abc123',
    introducedInMessage: 'add user lookup',
    originatingPrompt: 'add a route that looks up users by email',
  });
  assert.ok(ping);
  assert.match(ping, /@Test\.User/);
  assert.match(ping, /CRITICAL/);
  assert.match(ping, /abc123/);
  assert.match(ping, /add a route/);
});

test('git-history: _extractPrompt picks up Prompt: marker', () => {
  const p = _igh._extractPrompt('add user lookup\n\nPrompt: add a route\n\nCo-Authored-By: Claude');
  assert.equal(p, 'add a route');
});

// ── findings-memory ───────────────────────────────────────────────────────

test('findings-memory: matches current findings', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, '.agentic-security', 'last-scan.json'),
      JSON.stringify({ findings: [
        { id: 'F1', vuln: 'SQL injection in user login', family: 'sqli', severity: 'critical', file: 'src/login.js', line: 10 },
        { id: 'F2', vuln: 'XSS in profile page', family: 'xss', severity: 'high', file: 'src/profile.js', line: 5 },
      ] }),
    );
    const r = queryFindingsMemory(p.dir, 'login sql');
    assert.ok(r.results.length >= 1);
    assert.equal(r.results[0].finding_id, 'F1');
    assert.equal(r.results[0].source, 'finding');
  } finally { await p.cleanup(); }
});

test('findings-memory: matches triage memory + AGENTS.md', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, '.agentic-security', 'triage-memory.jsonl'),
      JSON.stringify({ at: '2026-05-29T00:00:00Z', decision: 'wont-fix', reason: 'Internal admin tool', family: 'sqli', bucket: 'sqli::src/admin' }) + '\n',
    );
    await fsp.writeFile(
      path.join(p.dir, '.agentic-security', 'AGENTS.md'),
      '# History\n\n## SQL injection on internal pages\n\nWe accept SQLi on internal-only admin pages because access is gated by Okta.\n',
    );
    const r = queryFindingsMemory(p.dir, 'admin internal');
    assert.ok(r.results.length >= 2);
    const sources = new Set(r.results.map(x => x.source));
    assert.ok(sources.has('triage'));
    assert.ok(sources.has('agents-md'));
  } finally { await p.cleanup(); }
});

test('findings-memory: empty query returns empty', async () => {
  const p = await mkProject();
  try {
    const r = queryFindingsMemory(p.dir, '');
    assert.equal(r.count, 0);
    assert.equal(r.results.length, 0);
  } finally { await p.cleanup(); }
});

test('findings-memory: caps at top 10', async () => {
  const p = await mkProject();
  try {
    const findings = [];
    for (let i = 0; i < 20; i++) findings.push({ id: `F${i}`, vuln: 'SQL injection variant', family: 'sqli' });
    await fsp.writeFile(path.join(p.dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings }));
    const r = queryFindingsMemory(p.dir, 'sql injection');
    assert.equal(r.results.length, 10);
    assert.ok(r.count >= 20);
  } finally { await p.cleanup(); }
});
