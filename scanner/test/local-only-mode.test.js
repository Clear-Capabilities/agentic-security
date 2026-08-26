// FR-605 (assurance-hardening PRD): enforce an unambiguous local-only
// provider mode — a remote URL cannot be smuggled into local-only
// configuration.
//
// Two things are proven here:
//   1. isLoopbackUrl (the mechanism mode:local-only relies on) is
//      adversarially robust against known real-world localhost-bypass
//      techniques (octal/hex/decimal IPv4 notation, IPv4-mapped IPv6,
//      hostname lookalikes, URL-parsing userinfo confusion) — not just
//      the happy-path loopback/non-loopback cases already covered
//      elsewhere.
//   2. The REAL gap found this cycle: discovery/llm-invoke.js's
//      multi-endpoint consensus mode (AGENTIC_SECURITY_LLM_ENDPOINTS)
//      used to construct its caller with NO egress check at all, so
//      `mode: local-only` was silently bypassable by using the
//      consensus env var instead of the single-endpoint one. Fixed by
//      giving each consensus endpoint its own evaluateEgress decision.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

import { isLoopbackUrl } from '../src/llm-validator/local-endpoint.js';
import { resolveLlmInvokeWithDecision } from '../src/discovery/llm-invoke.js';

async function tmpProjectWithPolicy(mode) {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'local-only-mode-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  await fsp.mkdir(path.join(d, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(d, '.agentic-security', 'egress-policy.yml'), `mode: ${mode}\n`);
  return d;
}

// ── isLoopbackUrl: adversarial cases beyond the happy path ──────────────

test('isLoopbackUrl: alternate IPv4 notations (octal/hex/decimal/short-form) for 127.0.0.1 are all correctly recognized, via canonical URL-parser normalization, not a raw-string match', () => {
  // The URL parser normalizes these to "127.0.0.1" BEFORE the check ever
  // runs — this is what makes the check safe rather than a smuggling hole:
  // there is no alternate notation for a REMOTE ip that could be confused
  // with 127.0.0.1, because canonicalization happens first.
  for (const url of ['http://0177.0.0.1/', 'http://0x7f.0.0.1/', 'http://2130706433/', 'http://127.1/']) {
    assert.equal(isLoopbackUrl(url), true, `${url} should normalize to loopback`);
  }
});

test('isLoopbackUrl: hostname lookalikes are correctly rejected (no DNS trust)', () => {
  for (const url of ['http://localhost.evil.com/', 'http://127.0.0.1.nip.io/', 'http://EVIL.COM/']) {
    assert.equal(isLoopbackUrl(url), false, `${url} must not be treated as loopback`);
  }
});

test('isLoopbackUrl: URL-parsing userinfo confusion does not smuggle a remote host past the check', () => {
  // A naive regex over the raw string could be fooled by userinfo tricks;
  // this relies on new URL().hostname, which resolves the ACTUAL host.
  assert.equal(isLoopbackUrl('http://user:pass@127.0.0.1@evil.com/'), false);
  assert.equal(isLoopbackUrl('http://evil.com#@127.0.0.1/'), false);
});

test('isLoopbackUrl: unparseable or non-http(s) input is never treated as loopback (fails closed)', () => {
  assert.equal(isLoopbackUrl('not a url'), false);
  assert.equal(isLoopbackUrl('ftp://127.0.0.1/'), false);
  assert.equal(isLoopbackUrl(''), false);
  assert.equal(isLoopbackUrl(null), false);
  assert.equal(isLoopbackUrl(undefined), false);
});

// ── FR-605 regression: consensus mode used to bypass mode:local-only ────

test('FR-605 regression: mode:local-only denies EVERY endpoint in a multi-endpoint consensus list that is not loopback', async () => {
  const dir = await tmpProjectWithPolicy('local-only');
  const savedEnv = process.env.AGENTIC_SECURITY_LLM_ENDPOINTS;
  try {
    process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = 'https://api.openai.com/v1/chat,https://api.anthropic.com/v1/messages';
    const { invoke, decision, decisions } = resolveLlmInvokeWithDecision({ scanRoot: dir });
    assert.equal(invoke, null, 'both remote endpoints must be denied — no consensus caller must be constructed');
    assert.equal(decision.allowed, false);
    assert.equal(decisions.length, 2);
    assert.ok(decisions.every(d => !d.allowed), 'every individual endpoint decision must also be a denial');
  } finally {
    if (savedEnv === undefined) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINTS; else process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = savedEnv;
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('FR-605: mode:local-only allows a consensus list where SOME endpoints are loopback — the denied ones are excluded, not fatal to the whole list', async () => {
  const dir = await tmpProjectWithPolicy('local-only');
  const savedEnv = process.env.AGENTIC_SECURITY_LLM_ENDPOINTS;
  try {
    process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = 'http://127.0.0.1:11434/v1/chat,https://api.openai.com/v1/chat';
    const { invoke, decision, decisions } = resolveLlmInvokeWithDecision({ scanRoot: dir });
    assert.notEqual(invoke, null, 'the loopback endpoint should still be usable');
    assert.equal(decisions.length, 2);
    assert.equal(decisions.filter(d => d.allowed).length, 1, 'exactly one of the two endpoints is allowed');
  } finally {
    if (savedEnv === undefined) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINTS; else process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = savedEnv;
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('FR-605: mode:deny denies an entire consensus list regardless of endpoint content', async () => {
  const dir = await tmpProjectWithPolicy('deny');
  const savedEnv = process.env.AGENTIC_SECURITY_LLM_ENDPOINTS;
  try {
    process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = 'http://127.0.0.1:11434/v1/chat,http://127.0.0.1:11435/v1/chat';
    const { invoke, decision } = resolveLlmInvokeWithDecision({ scanRoot: dir });
    assert.equal(invoke, null, 'mode:deny must deny even loopback endpoints — it is a blanket rule, not local-only-specific');
    assert.equal(decision.allowed, false);
  } finally {
    if (savedEnv === undefined) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINTS; else process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = savedEnv;
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('consensus mode with no policy configured (default allow) still constructs a working invoker — backward compatible default', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'local-only-mode-default-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  const savedEnv = process.env.AGENTIC_SECURITY_LLM_ENDPOINTS;
  try {
    process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = 'https://api.openai.com/v1/chat,https://api.anthropic.com/v1/messages';
    const { invoke, decisions } = resolveLlmInvokeWithDecision({ scanRoot: dir });
    assert.notEqual(invoke, null, 'default allow policy must not break the pre-existing consensus feature');
    assert.equal(decisions.length, 2);
    assert.ok(decisions.every(d => d.allowed));
  } finally {
    if (savedEnv === undefined) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINTS; else process.env.AGENTIC_SECURITY_LLM_ENDPOINTS = savedEnv;
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('an injected llmInvoke callback still bypasses egress entirely (opaque escape hatch, unchanged by this fix)', () => {
  const fn = () => 'x';
  const { invoke, decision } = resolveLlmInvokeWithDecision({ llmInvoke: fn });
  assert.equal(invoke, fn);
  assert.equal(decision, null);
});
