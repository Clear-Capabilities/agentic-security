#!/usr/bin/env node
// A bounded local original/patch replay (DOC-001.AC02): verify one synthetic repair with the three-part patch-negative check.
//
//   node scripts/patch-replay-example.mjs [--still-vulnerable]
//
// The original revision is the repository's own pinned fixture
// (scanner/test/fixtures/oracles/injection-execution/positive/target.mjs) and the patch is the pinned negative fixture. All four
// runs (original-positive, patched-negative, functional baseline, functional regression) go through the trust boundary: no
// network, workspace-only writes, the oracle's own time and output budgets, a process tree torn down before the verdict is read.
// The `verification-oracles` and `patch-negative-verification` features are OFF by default for every scan and CLI path; this
// script turns them on in this one process and nothing else.
//
// `--still-vulnerable` replaces the patch with the original plus a comment, a cosmetic edit. A re-scan could go quiet on such
// an edit; the patched-negative run must still confirm the exploit, so the result is NOT a verified fix. That is the second
// direction of the example.
//
// Exit: 0 the outcome was the expected one (verified fix, or, with --still-vulnerable, correctly refused) / 1 it was not /
// 3 this host cannot run the trust boundary (stated, never reported as a pass).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'scanner');
const mod = (rel) => import(pathToFileURL(path.join(SCANNER, 'src', rel)).href);
const { verifyPatchNegative } = await mod('posture/verification/patch-negative.js');
const { resolveAssuranceConfig } = await mod('posture/assurance/config.js');

const stillVulnerable = process.argv.includes('--still-vulnerable');
const dir = path.join(SCANNER, 'test', 'fixtures', 'oracles', 'injection-execution');
const read = (rel) => fs.readFileSync(path.join(dir, rel), 'utf8');
const vulnerable = read('positive/target.mjs');
const patched = stillVulnerable ? `${vulnerable}\n// reviewed\n` : read('negative/target.mjs');

const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true, 'patch-negative-verification': true } } });
const result = await verifyPatchNegative({
  hypothesisId: 'doc-example-patch', commit: 'a1'.repeat(20),
  original: { files: { 'target.mjs': vulnerable }, entry: 'target.mjs', oracleId: 'injection-execution', inputs: JSON.parse(read('scenario.json')) },
  patch: { files: { 'target.mjs': patched } },
  functional: { inputs: { export: 'handler', cases: [{ id: 'echo-hello', args: ['hello'], expected: 'hello\n' }] } },
}, { config });

if (result.steps.some((s) => s.code === 'prerequisite-unmet')) {
  console.log('not executed: a prerequisite of the trust boundary is unmet on this host');
  console.log('nothing was verified; this is not a pass');
  process.exit(3);
}
console.log(`patch ${String(result.patchDigest).slice(0, 19)} against ${'a1'.repeat(6)}`);
for (const s of result.steps) console.log(`${s.step}: ${s.status}${s.outcome ? ` (oracle outcome ${s.outcome}, expected ${s.expected})` : ''}${s.code ? ` [${s.code}]` : ''}`);
console.log(result.verifiedFix ? 'result: verified-fix (declared scenario and cases only)' : `result: NOT verified-fix (${result.failureCode ?? result.status})`);
const expectedVerified = !stillVulnerable;
process.exit(result.verifiedFix === expectedVerified ? 0 : 1);
