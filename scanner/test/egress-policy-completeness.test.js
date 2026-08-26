// Egress policy completeness guard (assurance-hardening PRD FR-601).
//
// Same spirit as artifact-registry-completeness.test.js: a policy nobody is
// forced to keep current is a snapshot, not a control. A direct audit this
// cycle found LLM network calls scattered across 6 files with zero shared
// infrastructure between 4 of them (discovery/llm-invoke.js and
// llm-validator/index.js were the only real chokepoints; adversary-agent.js,
// llm-redteam.js, flow-narration.js, and sca/llm-function-extract.js each had
// their own inline `fetch`). That scatter is exactly the shape a NEW call
// site added later can slip through unnoticed — this guard scans every
// `fetch(` call site under src/ and fails if a file makes what looks like a
// real network call without also importing `evaluateEgress`.
//
// EXCLUDED_FILES lists every fetch( site verified NOT to be LLM egress (SCA
// registries, PoC/regression-test harnesses that call the SCANNED app rather
// than a model, ticket/webhook integrations, Sigstore's Rekor transparency
// log, etc.) plus files where `fetch(` appears only inside a comment as a
// pattern example, not a real call. Each entry states which. Adding a file
// here is a real, reviewable decision — not a way to silence this guard.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const SRC = path.join(SCANNER, 'src');

const EXCLUDED_FILES = new Map([
  ['src/egress/policy.js', 'the policy module itself — evaluateEgress is defined here, not a caller of itself'],
  ['src/engine.js', 'OSV/KEV/npm/PyPI/registry fetches, not LLM egress'],
  ['src/posture/epss.js', 'FIRST.org EPSS score fetches, not LLM egress'],
  ['src/posture/federated-learning.js', 'calibration/telemetry sink, not an LLM provider'],
  ['src/posture/realtime-cve-monitor.js', 'CVE feed polling, not LLM egress'],
  ['src/posture/regression-test-gen.js', 'generated PoC harness fetches the SCANNED application under test, not a model provider'],
  ['src/posture/poc-generator.js', 'generated PoC harness fetches the SCANNED application under test, not a model provider'],
  ['src/posture/secret-live-check.js', 'checks whether a leaked credential is live against ITS OWN provider API (AWS/Stripe/GitHub/etc.) — a different, already-scoped security check, not LLM egress'],
  ['src/posture/schema-aware-bridge.js', "`fetch(` appears only inside a comment describing a JS client call pattern to name-match against a server route — no real network call in this file"],
  ['src/privacy/ir-adapter.js', "`fetch(` appears only inside comments describing example source code this module adapts IR for — no real network call in this file"],
  ['src/dataflow/async-sequencing.js', "`fetch(` appears only inside comments describing a taint pattern this module recognizes — no real network call in this file"],
  ['src/dataflow/string-domain.js', "`fetch(` appears only inside a comment describing a string-domain example — no real network call in this file"],
  ['src/sca/sigstore-verify.js', 'fetches the public Rekor transparency log for SBOM/provenance verification, not LLM egress'],
  ['src/mcp/audit.js', 'telemetry sink, not LLM egress'],
  ['src/integrations/tickets.js', 'Linear/Jira ticket-creation integrations, not LLM egress'],
  ['src/integrations/index.js', 'webhook/ServiceNow/PagerDuty/Teams notification integrations, not LLM egress'],
]);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

test('every real fetch() call site under src/ either imports evaluateEgress or is on the reviewed exclude list', () => {
  const missing = [];
  for (const file of walk(SRC)) {
    const rel = path.relative(SCANNER, file).replace(/\\/g, '/');
    if (EXCLUDED_FILES.has(rel)) continue;
    const raw = fs.readFileSync(file, 'utf8');
    const codeOnly = stripComments(raw);
    if (!codeOnly.includes('fetch(')) continue;
    if (!raw.includes('evaluateEgress')) missing.push(rel);
  }
  assert.deepEqual(missing, [],
    `file(s) with a real fetch() call but no evaluateEgress import, and not on the reviewed exclude list:\n${missing.join('\n')}\n` +
    `Either wire the call through egress/policy.js's evaluateEgress before it fires, or — if it is genuinely not an LLM call — ` +
    `add it to EXCLUDED_FILES in this test with a one-line reason, the same way every current entry documents one.`);
});

test('every EXCLUDED_FILES entry still exists and still contains a fetch( call (a stale exclusion hides nothing real)', () => {
  const stale = [];
  for (const [rel] of EXCLUDED_FILES) {
    if (rel === 'src/egress/policy.js') continue; // exempt for a different reason, not a fetch-absence claim
    const full = path.join(SCANNER, rel);
    if (!fs.existsSync(full)) { stale.push(`${rel}: file no longer exists`); continue; }
    const src = fs.readFileSync(full, 'utf8');
    if (!src.includes('fetch(')) stale.push(`${rel}: no longer contains fetch( — remove this stale exclusion`);
  }
  assert.deepEqual(stale, [], `stale EXCLUDED_FILES entries:\n${stale.join('\n')}`);
});

test('the guard itself found more than zero gated LLM-egress files (sanity — proves the scan is not silently matching nothing)', () => {
  let gated = 0;
  for (const file of walk(SRC)) {
    const rel = path.relative(SCANNER, file).replace(/\\/g, '/');
    if (EXCLUDED_FILES.has(rel)) continue;
    const raw = fs.readFileSync(file, 'utf8');
    if (stripComments(raw).includes('fetch(') && raw.includes('evaluateEgress')) gated++;
  }
  assert.ok(gated >= 6, `expected at least 6 files with a gated fetch() call, found ${gated} — the scan may have stopped matching`);
});
