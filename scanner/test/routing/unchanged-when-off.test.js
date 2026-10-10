// X-601 to X-604 rollout: with the `model-routing` feature off, the existing routing, trust, cache-economics, catalog and advisor
// behaviour is byte-identical to what it was BEFORE this work. The pins in test/fixtures/routing/pre-change-pins.json were generated from
// the code as it stood before any routing edit was made (the generator ran first, before model-routing.js was touched); this test recomputes every value from
// the current code and compares.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { routeModelForFinding, routeModelWithTrust, routeModelWithPolicy, summarizeRouting, trustKeyFor } from '../../src/posture/model-routing.js';
import { createTrustLedger } from '../../src/posture/model-trust.js';
import { analyzeTranscript, formatCacheReport } from '../../src/posture/cache-economics.js';
import { SOURCED_AT, modelEntry } from '../../src/posture/provider-catalog.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PINS = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'routing', 'pre-change-pins.json'), 'utf8'));
const require = createRequire(import.meta.url);
const advisor = require(path.join(HERE, '..', '..', '..', 'hooks', 'model-cost-advisor.js'));

const findings = [
  { severity: 'critical', cwe: 'CWE-89' }, { severity: 'high', cwe: 'CWE-327' }, { severity: 'high', cwe: 'CWE-79' },
  { severity: 'medium', cwe: 'CWE-22' }, { severity: 'low', cwe: 'CWE-209' }, { severity: 'medium', multiFile: true },
  { severity: 'high' }, {},
];
const ledger = () => { const l = createTrustLedger(); const k = trustKeyFor({ severity: 'high', cwe: 'CWE-79' }); for (let i = 0; i < 400; i++) l.record(k, false); return l; };
const OFF = resolveAssuranceConfig({ env: {}, platform: 'linux' });
const SRC = path.join(HERE, '..', '..', 'src');
const clone = (v) => JSON.parse(JSON.stringify(v));

describe('[X-604.AC01] feature off: the existing routing, trust, cache economics, catalog and advisor outputs are unchanged', () => {
  test('capability routing and measured-trust routing match the pre-change pins', () => {
    assert.deepEqual(clone(findings.map(routeModelForFinding)), PINS.routeModelForFinding);
    assert.deepEqual(clone(findings.map((f) => routeModelWithTrust(f))), PINS.routeModelWithTrust_noLedger);
    assert.deepEqual(clone(findings.map((f) => routeModelWithTrust(f, ledger()))), PINS.routeModelWithTrust_ledger);
    assert.deepEqual(clone(summarizeRouting(findings)), PINS.summarizeRouting);
  });

  test('the policy entry point with the feature off returns the same value as the trust router, for every pinned finding', () => {
    for (const [i, f] of findings.entries()) {
      assert.deepEqual(clone(routeModelWithPolicy(f, { config: OFF, ledger: ledger() })), PINS.routeModelWithTrust_ledger[i]);
      assert.deepEqual(clone(routeModelWithPolicy(f, {})), PINS.routeModelWithTrust_noLedger[i]);
    }
  });

  test('cache economics, the provider catalog and the cost advisor match the pre-change pins', () => {
    const fixture = path.join(HERE, '..', 'fixtures', 'cache-economics', 'session.jsonl');
    assert.equal(formatCacheReport(analyzeTranscript({ transcriptPath: fixture })), PINS.cacheReport);
    assert.equal(SOURCED_AT, PINS.sourcedAt);
    for (const p of PINS.providerEntries) {
      const e = modelEntry(p.p, p.id);
      assert.deepEqual({ p: p.p, id: e.id, in: e.in, out: e.out, cached: e.cached }, p);
    }
    const prompts = ['explain this function', 'refactor the auth module across src/a.js and src/b.js, design the migration', 'fix the typo in README.md'];
    assert.deepEqual(prompts.map((p) => advisor.classifyTier(p)), PINS.advisorTiers);
    assert.deepEqual(['claude-opus-4-8', 'claude-haiku-4-5'].map((m) => advisor.estimateCost(m, 'medium', 'medium')), PINS.advisorCosts);
  });

  test('nothing outside the routing directory depends on it except the policy entry point in model-routing.js', () => {
    const offenders = [];
    const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (p.endsWith('.js')) { const t = fs.readFileSync(p, 'utf8'); if (/posture\/routing\/|from '\.\/routing\//.test(t) || (p.includes(`${path.sep}posture${path.sep}`) && /from '\.\.?\/routing\//.test(t))) offenders.push(path.relative(SRC, p)); } } };
    walk(SRC);
    const importers = offenders.filter((f) => !f.startsWith(path.join('posture', 'routing')));
    assert.deepEqual(importers, [path.join('posture', 'model-routing.js')]);
    const hooksText = fs.readFileSync(path.join(HERE, '..', '..', '..', 'hooks', 'model-cost-advisor.js'), 'utf8');
    assert.ok(!/routing\//.test(hooksText), 'the interactive advisor hook does not import the routing modules');
    const engine = fs.readFileSync(path.join(SRC, 'engine.js'), 'utf8');
    assert.ok(!/routing\//.test(engine), 'the scan engine does not import the routing modules');
  });

  test('the model-routing feature is off by default and a kill switch beats an explicit enable', () => {
    assert.equal(OFF.features['model-routing'].enabled, false);
    const killed = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: '1', AGENTIC_SECURITY_NO_ASSURANCE: '1' }, platform: 'linux' });
    assert.equal(killed.features['model-routing'].enabled, false);
  });
});
