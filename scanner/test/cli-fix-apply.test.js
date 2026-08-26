// CLI `fix --apply` tests (assurance-hardening PRD FR-301/FR-302/FR-303/FR-304).
//
// `agentic-security fix --apply` had NO test coverage at all before this
// file — a real gap for a command that writes to disk. It also had the
// weakest safety posture of any apply path in the codebase: no path
// confinement, integrity failures only warned (never refused), and no fresh
// verification before writing (A-08, worse than the PRD's own evidence
// table described). All three are fixed via the new shared
// src/fix/apply-fix-service.js; these tests prove it end-to-end through the
// real CLI, not just unit-testing the service in isolation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { signLastScan } from '../src/posture/integrity.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: SCANNER, encoding: 'utf8', timeout: 30_000, ...opts });
}

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cli-fix-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

function writeSignedScan(root, findings) {
  const stateDir = path.join(root, '.agentic-security');
  const body = JSON.stringify({ findings });
  fs.writeFileSync(path.join(stateDir, 'last-scan.json'), body);
  fs.writeFileSync(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
}

// ── Security refusals (no real scan needed — hand-crafted last-scan.json) ──

test('fix --apply refuses a finding whose file field escapes the project root (path traversal)', () => {
  const root = mkProject();
  try {
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: '../../../../etc/passwd', line: 1, vuln: 'x', fix: { replacement: 'pwned' } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0, `expected non-zero exit, got ${r.status}: ${r.stdout}`);
    assert.match(r.stderr, /path-escape refused|escapes/i);
    assert.ok(!fs.existsSync('/etc/passwd.tmp'), 'sanity: did not actually write outside the sandbox');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply refuses a finding whose file field is a symlink escaping the project root', () => {
  const root = mkProject();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cli-fix-outside-'));
  const outsideFile = path.join(outside, 'secret.txt');
  fs.writeFileSync(outsideFile, 'ORIGINAL');
  const linkPath = path.join(root, 'link.txt');
  try {
    fs.symlinkSync(outsideFile, linkPath);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'link.txt', line: 1, vuln: 'x', fix: { replacement: 'pwned' } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.equal(fs.readFileSync(outsideFile, 'utf8'), 'ORIGINAL', 'the file outside the root must be untouched');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('fix --apply refuses a reserved-write path (e.g. package.json)', () => {
  const root = mkProject();
  try {
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'package.json', line: 1, vuln: 'x', fix: { replacement: '{"pwned":true}' } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /reserved path refused/i);
    assert.equal(fs.readFileSync(path.join(root, 'package.json'), 'utf8'), '{"name":"fixture"}\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// FR-303's acceptance criteria name three specific reserved-path classes
// beyond a basename match (package.json above): the VCS directory, this
// scanner's own state directory, and the dependency directory. Each gets
// its own direct test on the CLI path — the underlying confinePath/
// isReservedWritePath logic is shared with MCP (already covered
// exhaustively in mcp.test.js), but FR-303 asks for direct evidence on
// BOTH entry points, not an inference from shared code.
test('fix --apply refuses to write under .git/ (VCS directory)', () => {
  const root = mkProject();
  try {
    fs.mkdirSync(path.join(root, '.git'), { recursive: true });
    fs.writeFileSync(path.join(root, '.git', 'config'), '[core]\n');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: '.git/config', line: 1, vuln: 'x', fix: { replacement: 'pwned' } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /reserved path refused/i);
    assert.equal(fs.readFileSync(path.join(root, '.git', 'config'), 'utf8'), '[core]\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply refuses to write under .agentic-security/ (this scanner\'s own state directory)', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, '.agentic-security', 'rules.yml'), 'disable: []\n');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: '.agentic-security/rules.yml', line: 1, vuln: 'x', fix: { replacement: 'disable: [everything]' } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /reserved path refused/i);
    assert.equal(fs.readFileSync(path.join(root, '.agentic-security', 'rules.yml'), 'utf8'), 'disable: []\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply refuses to write under node_modules/ (dependency directory)', () => {
  const root = mkProject();
  try {
    fs.mkdirSync(path.join(root, 'node_modules', 'express'), { recursive: true });
    fs.writeFileSync(path.join(root, 'node_modules', 'express', 'index.js'), 'legit module');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'node_modules/express/index.js', line: 1, vuln: 'x', fix: { replacement: 'malicious()' } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /reserved path refused/i);
    assert.equal(fs.readFileSync(path.join(root, 'node_modules', 'express', 'index.js'), 'utf8'), 'legit module');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply refuses when last-scan.json is tampered (bad signature) — no longer just a warning', () => {
  const root = mkProject();
  try {
    const stateDir = path.join(root, '.agentic-security');
    const body = JSON.stringify({ findings: [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'a.js', line: 1, vuln: 'x', fix: { replacement: 'SAFE' } }] });
    fs.writeFileSync(path.join(stateDir, 'last-scan.json'), body);
    fs.writeFileSync(path.join(stateDir, 'last-scan.json.sig'), 'not-a-real-signature');
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0, 'a tampered scan must REFUSE the write, not warn-and-continue');
    assert.match(r.stderr, /integrity check|Refusing to apply/i);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL', 'the file must be untouched when integrity fails');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply refuses when last-scan.json has no .sig at all (unsigned)', () => {
  const root = mkProject();
  try {
    const stateDir = path.join(root, '.agentic-security');
    const body = JSON.stringify({ findings: [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'a.js', line: 1, vuln: 'x', fix: { replacement: 'SAFE' } }] });
    fs.writeFileSync(path.join(stateDir, 'last-scan.json'), body);
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply refuses a finding with no stableId — cannot verify a candidate fix against it', () => {
  const root = mkProject();
  try {
    writeSignedScan(root, [{ id: 'F1', severity: 'high', file: 'a.js', line: 1, vuln: 'x', fix: { replacement: 'SAFE' } }]); // no stableId
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /stableId/i);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ── Real end-to-end: scan a genuinely vulnerable fixture, apply a genuine fix ──

test('fix --apply: end-to-end against a real scan — a genuine fix verifies and is written; a fake one is rejected', () => {
  const root = mkProject();
  try {
    // A real, detector-triggering weak-hash finding (same shape as the
    // existing MCP apply_fix (#3) test fixture, CWE-328).
    fs.writeFileSync(path.join(root, 'app.js'), "const c=require('crypto');const h=c.createHash('md5');\n");
    const scanRun = run(['scan', root, '--format', 'json', '--no-network'], {});
    // scan writes last-scan.json as a side effect regardless of exit code
    // (exit code reflects finding severity, not scan failure).
    const lastScanPath = path.join(root, '.agentic-security', 'last-scan.json');
    assert.ok(fs.existsSync(lastScanPath), `expected last-scan.json to exist after scan, stdout: ${scanRun.stdout}\nstderr: ${scanRun.stderr}`);
    const last = JSON.parse(fs.readFileSync(lastScanPath, 'utf8'));
    const finding = (last.findings || []).find(f => /md5|hash/i.test(f.vuln || '') || f.cwe === 'CWE-328');
    assert.ok(finding, `expected a weak-hash finding in the real scan, got: ${JSON.stringify((last.findings || []).map(f => f.vuln))}`);
    assert.ok(finding.stableId, 'a real scan finding must carry a stableId (FR-101, annotateStableIds runs unconditionally)');

    // A FAKE "fix" that does not actually remove the md5 usage must be REJECTED.
    const before = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
    // Hand-craft a fix object onto the real finding for the CLI's replacement path.
    const fakeLast = { ...last, findings: last.findings.map(f => f === finding ? { ...f, fix: { replacement: before + '// no actual fix\n' } } : f) };
    const fakeBody = JSON.stringify(fakeLast);
    fs.writeFileSync(lastScanPath, fakeBody);
    fs.writeFileSync(lastScanPath + '.sig', signLastScan(fakeBody));
    const fakeApply = run(['fix', '--finding', finding.id, '--apply', '--root', root]);
    assert.notEqual(fakeApply.status, 0, 'a fix that does not close the finding must be rejected by the fresh verification gate');
    assert.equal(fs.readFileSync(path.join(root, 'app.js'), 'utf8'), before, 'disk must be untouched when verification rejects the fix');

    // A GENUINE fix (removes the weak hash entirely) must verify and apply.
    const genuineLast = { ...last, findings: last.findings.map(f => f === finding ? { ...f, fix: { replacement: 'export function ok() { return 1; }\n' } } : f) };
    const genuineBody = JSON.stringify(genuineLast);
    fs.writeFileSync(lastScanPath, genuineBody);
    fs.writeFileSync(lastScanPath + '.sig', signLastScan(genuineBody));
    const realApply = run(['fix', '--finding', finding.id, '--apply', '--root', root]);
    assert.equal(realApply.status, 0, `expected a genuine fix to apply cleanly: ${realApply.stderr}`);
    assert.equal(fs.readFileSync(path.join(root, 'app.js'), 'utf8'), 'export function ok() { return 1; }\n');
    assert.ok(/applied fix/i.test(realApply.stdout));
    assert.ok(/backup:/i.test(realApply.stdout));
    // FR-305: this fixture (mkProject's bare package.json) has no test
    // script and no linter config, so verification is genuinely degraded —
    // the CLI must say so plainly, not print an unqualified "verified: yes"
    // that would misrepresent a skipped test leg as a full pass.
    assert.match(realApply.stdout, /NOT fully verified/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// D-0024: before this, the CLI had no flag at all to supply approval
// evidence — a high-impact change was unconditionally refused via --apply
// with no way to ever approve it. --approved-by/--approval-reason close
// that gap; these prove it through the real CLI subprocess, not a unit call.
const AUTH_REMOVED_BEFORE = 'function h(req,res){ if(!requireAuth(req)) return res.status(401).end(); doThing(); }\n';
const AUTH_REMOVED_AFTER = 'function h(req,res){ doThing(); }\n';

test('fix --apply (D-0024): a high-impact fix (auth removed) is refused with no approval flags — and the CLI names the missing flags', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'auth.js', line: 1, vuln: 'demo', fix: { replacement: AUTH_REMOVED_AFTER } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root]);
    assert.notEqual(r.status, 0, `expected non-zero exit, got ${r.status}: ${r.stdout}`);
    assert.match(r.stderr, /auth/);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_BEFORE, 'disk must be untouched when refused');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply (D-0024): the same high-impact fix succeeds once --approved-by and --approval-reason are supplied', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'auth.js', line: 1, vuln: 'demo', fix: { replacement: AUTH_REMOVED_AFTER } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root, '--approved-by', 'jane@example.com', '--approval-reason', 'auth removal is intentional']);
    assert.equal(r.status, 0, `expected a genuine, approved fix to apply cleanly: ${r.stderr}`);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_AFTER);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply (FR-1003): with separationOfDuties enabled, --author matching --approved-by is refused via the real CLI', () => {
  const root = mkProject();
  try {
    fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(root, '.agentic-security', 'authorized-approvers.json'), JSON.stringify({
      approvers: [{ identity: 'jane@example.com' }], separationOfDuties: { enabled: true },
    }));
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'auth.js', line: 1, vuln: 'demo', fix: { replacement: AUTH_REMOVED_AFTER } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root, '--approved-by', 'jane@example.com', '--approval-reason', 'self-reviewed', '--author', 'jane@example.com']);
    assert.notEqual(r.status, 0, `expected refusal — author and approver are the same identity, got status ${r.status}: ${r.stdout}`);
    assert.match(r.stderr, /separation-of-duties/);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_BEFORE, 'disk must be untouched when refused');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --apply (FR-1003): with separationOfDuties enabled, a different --author succeeds via the real CLI', () => {
  const root = mkProject();
  try {
    fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(root, '.agentic-security', 'authorized-approvers.json'), JSON.stringify({
      approvers: [{ identity: 'jane@example.com' }, { identity: 'bob@example.com' }], separationOfDuties: { enabled: true },
    }));
    fs.writeFileSync(path.join(root, 'auth.js'), AUTH_REMOVED_BEFORE);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'auth.js', line: 1, vuln: 'demo', fix: { replacement: AUTH_REMOVED_AFTER } }]);
    const r = run(['fix', '--finding', 'F1', '--apply', '--root', root, '--approved-by', 'bob@example.com', '--approval-reason', 'independent review', '--author', 'jane@example.com']);
    assert.equal(r.status, 0, `expected success — approver differs from author: ${r.stderr}`);
    assert.equal(fs.readFileSync(path.join(root, 'auth.js'), 'utf8'), AUTH_REMOVED_AFTER);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fix --preview still works and does not write (read-only path unaffected by the write-side hardening)', () => {
  const root = mkProject();
  try {
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), severity: 'high', file: 'a.js', line: 1, vuln: 'x', fix: { replacement: 'SAFE' } }]);
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const r = run(['fix', '--finding', 'F1', '--preview', '--root', root]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL', 'preview must never write');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
