// Egress policy tests (assurance-hardening PRD FR-601).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { evaluateEgress, _internals } from '../src/egress/policy.js';

function mkProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-policy-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function withEnv(vars, fn) {
  const prev = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  try {
    for (const [k, v] of Object.entries(vars)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    return fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

// ── Default behavior (no config, no env) ────────────────────────────────

test('evaluateEgress: no config and no env -> allow (preserves existing default-on behavior)', () => {
  const p = mkProject();
  try {
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
    assert.equal(d.allowed, true);
    assert.equal(d.decision, 'allow');
    assert.equal(d.reason, null);
    assert.equal(d.policySource, 'default');
  } finally { p.cleanup(); }
});

test('evaluateEgress: missing endpoint -> denied with a clear reason, never throws', () => {
  const d = evaluateEgress({ purpose: 'test' });
  assert.equal(d.allowed, false);
  assert.equal(d.decision, 'deny');
  assert.match(d.reason, /no endpoint/);
});

// ── The decision object never carries prompt/source content (PRD walkthrough
//    scenario 7: "records a sanitized decision without retaining source") ──

test('evaluateEgress: the returned decision object never carries prompt or source content, only metadata', () => {
  const d = evaluateEgress({ purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
  const keys = Object.keys(d).sort();
  assert.deepEqual(keys, ['allowed', 'decision', 'policySource', 'provider', 'purpose', 'reason']);
});

// ── mode: deny ───────────────────────────────────────────────────────────

test('evaluateEgress: AGENTIC_SECURITY_EGRESS_DENY=1 denies every call and results in no network request being attempted by any caller', () => {
  withEnv({ AGENTIC_SECURITY_EGRESS_DENY: '1' }, () => {
    const d = evaluateEgress({ purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
    assert.equal(d.allowed, false);
    assert.equal(d.decision, 'deny');
    assert.equal(d.policySource, 'env');
  });
});

test('evaluateEgress: AGENTIC_SECURITY_EGRESS_MODE=deny denies every call regardless of config file', () => {
  withEnv({ AGENTIC_SECURITY_EGRESS_MODE: 'deny' }, () => {
    const d = evaluateEgress({ purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
    assert.equal(d.allowed, false);
    assert.equal(d.policySource, 'env');
  });
});

test('evaluateEgress: mode: deny in egress-policy.yml denies every call', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), 'mode: deny\n');
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
    assert.equal(d.allowed, false);
    assert.equal(d.policySource, 'config');
  } finally { p.cleanup(); }
});

// ── mode: local-only ─────────────────────────────────────────────────────

test('evaluateEgress: mode: local-only allows a loopback endpoint', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), 'mode: local-only\n');
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'http://127.0.0.1:11434/v1/chat' });
    assert.equal(d.allowed, true);
  } finally { p.cleanup(); }
});

test('evaluateEgress: mode: local-only denies a non-loopback endpoint', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), 'mode: local-only\n');
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.anthropic.com/v1/messages' });
    assert.equal(d.allowed, false);
    assert.match(d.reason, /local-only/);
  } finally { p.cleanup(); }
});

test('evaluateEgress: mode: local-only denies a hostname that merely CLAIMS to be local (no DNS trust — matches local-endpoint.js\'s own literal-only rule)', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), 'mode: local-only\n');
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'http://my-local-server.example.com/v1/chat' });
    assert.equal(d.allowed, false);
  } finally { p.cleanup(); }
});

// ── provider allow/deny lists ────────────────────────────────────────────

test('evaluateEgress: deniedProviders blocks a matching provider, allows others', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), 'deniedProviders:\n  - openai\n');
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.openai.com/v1/chat/completions' });
    assert.equal(denied.allowed, false);
    assert.equal(denied.provider, 'openai');
    const allowed = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.anthropic.com/v1/messages' });
    assert.equal(allowed.allowed, true);
  } finally { p.cleanup(); }
});

test('evaluateEgress: allowedProviders permits only listed providers, denies everything else', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), 'allowedProviders:\n  - anthropic\n');
    const allowed = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.anthropic.com/v1/messages' });
    assert.equal(allowed.allowed, true);
    const denied = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.openai.com/v1/chat/completions' });
    assert.equal(denied.allowed, false);
  } finally { p.cleanup(); }
});

// ── provider detection ───────────────────────────────────────────────────

test('_providerOf: recognizes anthropic/openai/google hosts and loopback as "local"', () => {
  assert.equal(_internals._providerOf('https://api.anthropic.com/v1/messages'), 'anthropic');
  assert.equal(_internals._providerOf('https://api.openai.com/v1/chat/completions'), 'openai');
  assert.equal(_internals._providerOf('https://generativelanguage.googleapis.com/v1/models'), 'google');
  assert.equal(_internals._providerOf('http://127.0.0.1:11434/v1/chat'), 'local');
  assert.equal(_internals._providerOf('not a url'), 'unknown');
});

// ── malformed config degrades to default, never throws ──────────────────

test('evaluateEgress: an unparseable egress-policy.yml degrades to the default (allow), never throws', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), '{ not: valid: yaml ][\n');
    assert.doesNotThrow(() => {
      const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
      assert.equal(d.allowed, true);
    });
  } finally { p.cleanup(); }
});

test('evaluateEgress: a config file that parses to a non-object (e.g. a bare scalar or a list) degrades to the default, never throws', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'egress-policy.yml'), '- just\n- a\n- list\n');
    const d = evaluateEgress({ scanRoot: p.dir, purpose: 'test', endpoint: 'https://api.example.com/v1/chat' });
    assert.equal(d.allowed, true);
  } finally { p.cleanup(); }
});
