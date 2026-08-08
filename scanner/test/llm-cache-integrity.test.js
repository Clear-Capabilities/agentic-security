// The validator cache is a DELETION PRIMITIVE, and these tests exist because it
// was an unprotected one.
//
// A cache hit assigns a verdict directly, and a `reject` verdict removes a
// finding from the report. Before this hardening, `readCache` was a bare
// `JSON.parse(readFileSync(...))`: planting one file under
// `.agentic-security/llm-cache/<key>.json` deleted a critical command-injection
// finding with no model call and no network. Demonstrated, not theorised. The
// key is derivable by anyone with repo access, and CI restoring a cache
// directory between runs is a delivery vector that needs no repo write at all.
//
// `last-scan.json` had been HMAC-signed for exactly this reason. The cache that
// could delete findings had nothing.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { validateOne, applyValidatorVerdicts, _internal } from '../src/llm-validator/index.js';

const CONTENT = 'const { exec } = require("child_process");\nmodule.exports=(req,res)=>{ exec("ping "+req.query.h); };\n';

function project() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'llmcache-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"t","version":"1.0.0"}');
  fs.writeFileSync(path.join(d, 'app.js'), CONTENT);
  return d;
}

const finding = (over = {}) => ({
  id: 'x', severity: 'critical', file: 'app.js', line: 2,
  vuln: 'Command Injection', cwe: 'CWE-78', family: 'command-injection',
  confidence: 0.9, parser: 'REGEX', ...over,
});

// The module hashes file content with sha256 truncated to 32 chars.
function keyFor(f, model) {
  const fh = crypto.createHash('sha256').update(CONTENT).digest('hex').slice(0, 32);
  return _internal.cacheKey(f, fh, model);
}

function plant(dir, key, entry) {
  const cd = path.join(dir, '.agentic-security', 'llm-cache');
  fs.mkdirSync(cd, { recursive: true });
  fs.writeFileSync(path.join(cd, key + '.json'), JSON.stringify(entry));
}

function withEndpoint(fn) {
  const saved = { ...process.env };
  try {
    // An address nothing listens on: a cache HIT short-circuits before any
    // request, so a hit is observable and a miss fails the fetch.
    process.env.AGENTIC_SECURITY_LLM_ENDPOINT = 'http://127.0.0.1:9/never-called';
    process.env.AGENTIC_SECURITY_LLM_MODEL = 'cache-test';
    return fn();
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
}

test('an UNSIGNED planted entry cannot delete a finding — the original exploit', async () => {
  const d = project();
  try {
    const f = finding();
    plant(d, keyFor(f, 'cache-test'), { verdict: 'reject', confidence: 0.99, reasoning: 'benign' });
    await withEndpoint(() => validateOne(f, { 'app.js': CONTENT }, d));
    assert.notEqual(f._validatorCache, 'hit', 'an unsigned entry must be a MISS, never a verdict');
    const { kept, dropped } = applyValidatorVerdicts([f]);
    assert.equal(dropped.length, 0, 'a planted cache entry deleted a finding');
    assert.equal(kept.length, 1);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a legitimately written entry still round-trips — caching is not broken', async () => {
  // Hardening that disables the cache would be a silent performance regression
  // dressed as a fix, so the positive control matters as much as the negative.
  const d = project();
  try {
    const f = finding();
    const key = keyFor(f, 'cache-test');
    // The real write path creates the cache directory first; `writeCache`
    // alone does not, so calling it in isolation would silently write nothing
    // and make this positive control pass for the wrong reason.
    _internal.ensureCacheDir(d);
    _internal.writeCache(d, key, { verdict: 'accept', confidence: 0.8, reasoning: 'real', model: 'cache-test' });
    await withEndpoint(() => validateOne(f, { 'app.js': CONTENT }, d));
    assert.equal(f._validatorCache, 'hit', 'a properly signed entry must still be used');
    assert.equal(f.validator_verdict, 'accept');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('tampering with a signed entry invalidates it', async () => {
  const d = project();
  try {
    const f = finding();
    const key = keyFor(f, 'cache-test');
    _internal.ensureCacheDir(d);
    _internal.writeCache(d, key, { verdict: 'accept', confidence: 0.8, reasoning: 'real', model: 'cache-test' });
    // Flip the verdict, keep the signature.
    const fp = path.join(d, '.agentic-security', 'llm-cache', key + '.json');
    const entry = JSON.parse(fs.readFileSync(fp, 'utf8'));
    assert.ok(entry.sig, 'writeCache must sign');
    entry.verdict = 'reject';
    fs.writeFileSync(fp, JSON.stringify(entry));

    await withEndpoint(() => validateOne(f, { 'app.js': CONTENT }, d));
    assert.notEqual(f._validatorCache, 'hit');
    assert.equal(applyValidatorVerdicts([f]).dropped.length, 0);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('an entry signed under a different key is refused', async () => {
  const d = project();
  try {
    const f = finding();
    plant(d, keyFor(f, 'cache-test'),
      { verdict: 'reject', confidence: 0.9, reasoning: 'x', sig: 'a'.repeat(64) });
    await withEndpoint(() => validateOne(f, { 'app.js': CONTENT }, d));
    assert.notEqual(f._validatorCache, 'hit');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a cached verdict outside the allowlist is refused on read', async () => {
  const d = project();
  try {
    const f = finding();
    _internal.ensureCacheDir(d);
    _internal.writeCache(d, keyFor(f, 'cache-test'),
      { verdict: 'DROP EVERYTHING', confidence: 1, reasoning: 'x', model: 'cache-test' });
    await withEndpoint(() => validateOne(f, { 'app.js': CONTENT }, d));
    assert.notEqual(f._validatorCache, 'hit', 'an unknown verdict must not be trusted even when signed');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

// --- the asymmetry, now enforced rather than asserted ----------------------

test('a reject cannot delete a taint-proven finding', () => {
  for (const strong of [{ parser: 'IR-TAINT' }, { parser: 'MULTI-SINK' }, { proofTier: 'execution-proven' }]) {
    const f = finding({ ...strong, validator_verdict: 'reject' });
    const { kept, dropped } = applyValidatorVerdicts([f]);
    assert.equal(dropped.length, 0, `reject deleted a strongly-provenanced finding (${JSON.stringify(strong)})`);
    assert.equal(kept.length, 1);
    assert.equal(kept[0].validator_verdict, 'escalate', 'the reject must be demoted, not silently kept as reject');
    assert.match(kept[0].validator_reject_refused, /strong provenance/);
  }
});

test('a reject still drops a weakly-provenanced finding — the feature is not removed', () => {
  // If reject never dropped anything the validator would be pointless. The
  // guarantee is scoped to findings real analysis produced.
  const f = finding({ parser: 'REGEX', validator_verdict: 'reject' });
  const { kept, dropped } = applyValidatorVerdicts([f]);
  assert.equal(dropped.length, 1);
  assert.equal(kept.length, 0);
  assert.equal(dropped[0]._droppedBy, 'llm-validator');
});

test('accept and escalate are unaffected by the provenance rule', () => {
  const acc = finding({ parser: 'IR-TAINT', validator_verdict: 'accept', llm_confidence: 0.95 });
  const esc = finding({ parser: 'IR-TAINT', validator_verdict: 'escalate' });
  const { kept, dropped } = applyValidatorVerdicts([acc, esc]);
  assert.equal(dropped.length, 0);
  assert.equal(kept.length, 2);
  assert.equal(kept[0].validator_reject_refused, undefined);
});
