// FR-602 (assurance-hardening PRD): support provider, model, role, region,
// repository, path, data class, and maximum-context constraints. Tests
// cover allow, deny, and local-only decisions.
//
// FR-601 built ONE genuine, testable deny path (provider). This extends
// evaluateEgress with the remaining 7 named dimensions, each evaluated
// ONLY when the caller supplies the corresponding context value AND the
// config restricts that dimension — a caller with no opinion on region,
// say, must never be blocked by a rule it has no way to satisfy.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { evaluateEgress } from '../src/egress/policy.js';

function mkProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-constraints-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function writePolicy(dir, yaml) {
  fs.writeFileSync(path.join(dir, '.agentic-security', 'egress-policy.yml'), yaml);
}

const EP = 'https://api.anthropic.com/v1/messages';

// ── model ─────────────────────────────────────────────────────────────

test('deniedModels blocks a matching model, allows others', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedModels:\n  - claude-legacy\n');
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, model: 'claude-legacy' });
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /model 'claude-legacy' is in deniedModels/);
    const allowed = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, model: 'claude-current' });
    assert.equal(allowed.allowed, true);
  } finally { p.cleanup(); }
});

test('allowedModels permits only listed models', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'allowedModels:\n  - claude-current\n');
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, model: 'claude-current' }).allowed, true);
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, model: 'other-model' });
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /model 'other-model' is not in allowedModels/);
  } finally { p.cleanup(); }
});

test('a model-dimension policy does NOT block a call that supplies no model at all', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedModels:\n  - claude-legacy\n');
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP });
    assert.equal(d.allowed, true, 'a caller with no opinion on model must not be blocked by a model rule');
  } finally { p.cleanup(); }
});

// ── role ──────────────────────────────────────────────────────────────

test('deniedRoles / allowedRoles gate on the caller-supplied role', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedRoles:\n  - fix\n');
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, role: 'fix' }).allowed, false);
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, role: 'validate' }).allowed, true);
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP }).allowed, true, 'no role supplied — not evaluated');
  } finally { p.cleanup(); }
});

// ── region ────────────────────────────────────────────────────────────

test('deniedRegions / allowedRegions gate on the caller-supplied region', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'allowedRegions:\n  - us-east-1\n');
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, region: 'us-east-1' }).allowed, true);
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, region: 'eu-west-1' });
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /region 'eu-west-1' is not in allowedRegions/);
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP }).allowed, true, 'no region known — not evaluated');
  } finally { p.cleanup(); }
});

// ── repository ────────────────────────────────────────────────────────

test('deniedRepositories / allowedRepositories gate on the caller-supplied repository id', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedRepositories:\n  - internal/secret-repo\n');
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, repository: 'internal/secret-repo' }).allowed, false);
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, repository: 'internal/public-repo' }).allowed, true);
  } finally { p.cleanup(); }
});

// ── path (glob) ───────────────────────────────────────────────────────

test('deniedPaths refuses a glob-matching file path', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedPaths:\n  - "secrets/**"\n  - "**/*.pem"\n');
    const denied1 = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, path: 'secrets/prod.env' });
    assert.equal(denied1.allowed, false);
    assert.match(denied1.reason, /path 'secrets\/prod\.env' matches a deniedPaths pattern/);
    const denied2 = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, path: 'certs/server.pem' });
    assert.equal(denied2.allowed, false);
    const allowed = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, path: 'src/app.js' });
    assert.equal(allowed.allowed, true);
  } finally { p.cleanup(); }
});

test('allowedPaths permits only glob-matching file paths', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'allowedPaths:\n  - "src/**"\n');
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, path: 'src/app.js' }).allowed, true);
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, path: 'vendor/lib.js' });
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /path 'vendor\/lib\.js' does not match any allowedPaths pattern/);
  } finally { p.cleanup(); }
});

test('a path-dimension policy does NOT block a call that supplies no path at all', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedPaths:\n  - "secrets/**"\n');
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP }).allowed, true);
  } finally { p.cleanup(); }
});

// ── dataClass ─────────────────────────────────────────────────────────

test('deniedDataClasses refuses a call carrying a matching regulated-data class', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'deniedDataClasses:\n  - CREDENTIALS\n');
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, dataClass: 'CREDENTIALS' });
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /dataClass 'CREDENTIALS' is in deniedDataClasses/);
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, dataClass: 'PII' }).allowed, true);
  } finally { p.cleanup(); }
});

// ── maxContextTokens ──────────────────────────────────────────────────

test('maxContextTokens denies a call whose caller-estimated size exceeds the cap', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'maxContextTokens: 1000\n');
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, contextTokens: 5000 });
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /estimated context \(5000 tokens\) exceeds maxContextTokens \(1000\)/);
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP, contextTokens: 500 }).allowed, true);
  } finally { p.cleanup(); }
});

test('maxContextTokens is a no-op when the caller supplies no estimate', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'maxContextTokens: 1\n'); // absurdly low cap
    assert.equal(evaluateEgress({ scanRoot: p.dir, purpose: 't', endpoint: EP }).allowed, true);
  } finally { p.cleanup(); }
});

// ── local-only interacts correctly with the new dimensions ─────────────

test('local-only mode still denies a remote endpoint even when every other dimension would allow it', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'mode: local-only\nallowedModels:\n  - claude-current\n');
    const d = evaluateEgress({
      scanRoot: p.dir, purpose: 't', endpoint: EP,
      model: 'claude-current', role: 'validate', region: 'us-east-1',
    });
    assert.equal(d.allowed, false);
    assert.match(d.reason, /local-only/);
  } finally { p.cleanup(); }
});

test('local-only mode allows a loopback endpoint that also satisfies every other configured dimension', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, 'mode: local-only\nallowedModels:\n  - local-model\n');
    const d = evaluateEgress({
      scanRoot: p.dir, purpose: 't', endpoint: 'http://127.0.0.1:11434/v1/chat',
      model: 'local-model',
    });
    assert.equal(d.allowed, true);
  } finally { p.cleanup(); }
});

// ── combined: multiple dimensions together, all supplied ───────────────

test('multiple constraint dimensions supplied together must ALL pass for an allow', () => {
  const p = mkProject();
  try {
    writePolicy(p.dir, [
      'allowedModels:',
      '  - claude-current',
      'allowedRoles:',
      '  - validate',
      'deniedPaths:',
      '  - "secrets/**"',
    ].join('\n') + '\n');
    const allAllow = evaluateEgress({
      scanRoot: p.dir, purpose: 't', endpoint: EP,
      model: 'claude-current', role: 'validate', path: 'src/app.js',
    });
    assert.equal(allAllow.allowed, true);
    const oneDenies = evaluateEgress({
      scanRoot: p.dir, purpose: 't', endpoint: EP,
      model: 'claude-current', role: 'validate', path: 'secrets/prod.env',
    });
    assert.equal(oneDenies.allowed, false, 'a single failing dimension must deny the whole call');
  } finally { p.cleanup(); }
});
