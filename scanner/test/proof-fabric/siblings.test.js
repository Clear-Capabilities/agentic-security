// Sibling-exposure search (PRD 1 requirement 6): finds the same shape elsewhere, says where each came from, and never lets a
// bound that was hit read as "no siblings".
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { findSiblings } from '../../src/posture/proof-fabric/siblings.js';
import { verifyFixWithProof } from '../../src/posture/proof-fabric/fix-proof.js';

function repo(files) { const d = mkTestTmp('sib-'); for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), c); } return d; }
const VULN = "const out = child_process.execSync('ping -c 1 ' + host);\n";

test('the same shape written elsewhere is found even when the engine flagged nothing there, with renamed identifiers', () => {
  const d = repo({
    'a.js': VULN, 'b.js': "function other() {\n  const result = child_process.execSync('traceroute ' + target);\n}\n", 'c.js': "const x = child_process.execFileSync('ls', [dir]);\n",
    'notes.md': "child_process.execSync('ping ' + host)", 'node_modules/dep/index.js': VULN, 'deep/er/d.ts': "const r = child_process.execSync(\"nslookup \" + name);\n",
  });
  const r = findSiblings({ root: d, finding: { id: 'F1', file: 'a.js', line: 1 } });
  const where = r.siblings.map((s) => `${s.file}:${s.line}`).sort();
  assert.deepEqual(where, ['b.js:2', path.join('deep', 'er', 'd.ts') + ':1']);
  assert.ok(r.siblings.every((s) => s.source === 'structural' && s.text));
  assert.equal(r.truncated.length, 0);
  assert.ok(r.pattern.includes('child_process\\.execSync'));
});

test('the engine\'s own other findings of the same kind are included and labelled, without duplicating a structural hit', () => {
  const d = repo({ 'a.js': VULN, 'b.js': "x = child_process.execSync('ping ' + h);\n" });
  const r = findSiblings({ root: d, finding: { id: 'F1', stableId: 'S1', file: 'a.js', line: 1, cwe: 'CWE-78' }, scanFindings: [
    { id: 'F1', stableId: 'S1', file: 'a.js', line: 1, cwe: 'CWE-78' }, { id: 'F2', file: 'b.js', line: 1, cwe: 'CWE-78' }, { id: 'F3', file: 'z.js', line: 9, cwe: 'CWE-78' }, { id: 'F4', file: 'q.js', line: 2, cwe: 'CWE-79' },
  ] });
  const by = Object.fromEntries(r.siblings.map((s) => [`${s.file}:${s.line}`, s.source]));
  assert.deepEqual(by, { 'b.js:1': 'scan', 'z.js:9': 'scan' }, 'the flagged spot and the unrelated class are not siblings; b.js is reported once');
});

test('bounds are enforced and disclosed: a search that stopped early says so', () => {
  const files = { 'a.js': VULN }; for (let i = 0; i < 30; i++) files[`f${i}.js`] = "const x = child_process.execSync('ping ' + h);\n";
  const d = repo(files);
  const capped = findSiblings({ root: d, finding: { id: 'F', file: 'a.js', line: 1 }, limits: { maxFiles: 5, maxFileBytes: 1e6, maxMatches: 100, budgetMs: 8000 } });
  assert.ok(capped.truncated.some((t) => /file limit/.test(t)));
  const many = findSiblings({ root: d, finding: { id: 'F', file: 'a.js', line: 1 }, limits: { maxFiles: 5000, maxFileBytes: 1e6, maxMatches: 3, budgetMs: 8000 } });
  assert.equal(many.siblings.length, 3); assert.ok(many.truncated.some((t) => /match limit/.test(t)));
  let t = 0; const timed = findSiblings({ root: d, finding: { id: 'F', file: 'a.js', line: 1 }, now: () => (t += 5000) });
  assert.ok(timed.truncated.some((x) => /time budget/.test(x)));
});

test('a vanished file, a short line and symlinks degrade quietly to what is knowable', () => {
  const d = repo({ 'a.js': 'x();\n' });
  assert.deepEqual(findSiblings({ root: d, finding: { id: 'F', file: 'gone.js', line: 1 } }).siblings, []);
  assert.equal(findSiblings({ root: d, finding: { id: 'F', file: 'a.js', line: 1 } }).pattern, null, 'a one-token line has no shape worth searching for');
  const out = mkTestTmp('sib-out-'); fs.writeFileSync(path.join(out, 'x.js'), VULN);
  fs.writeFileSync(path.join(d, 'v.js'), VULN); fs.symlinkSync(out, path.join(d, 'linked'));
  assert.deepEqual(findSiblings({ root: d, finding: { id: 'F', file: 'v.js', line: 1 } }).siblings, [], 'a linked directory outside the repository is not followed');
});

test('an incomplete sibling search makes a verified fix DEGRADED, never FULL', async () => {
  const stub = async () => ({ status: 'completed', oracle: { fired: false }, observation: {}, degraded: [], durationMs: 1, environment: { mode: 'container', assurance: 'high' } });
  const confirmedFirst = async (r, o) => (o?.overlay ? stub() : { ...(await stub()), oracle: { fired: true } });
  const repro = { schema: 'agentic-security/reproducer', version: 1, findingId: 'F1', lang: 'javascript', files: { 'a.mjs': 'x' }, run: ['{{NODE}}', 'a.mjs'], oracle: { type: 'command_execution', params: { canary: 'command' } } };
  const okStatic = { ok: true, verifiedFull: true, degradedLegs: [], rescan: { ok: true } };
  const full = await verifyFixWithProof({ finding: { id: 'F1', stableId: 'F1' }, reproducer: repro, files: { 'a.js': 'p' }, scanRoot: '.', staticVerification: okStatic, siblings: [], deps: { attemptFn: confirmedFirst } });
  assert.equal(full.completeness, 'FULL');
  const partial = await verifyFixWithProof({ finding: { id: 'F1', stableId: 'F1' }, reproducer: repro, files: { 'a.js': 'p' }, scanRoot: '.', staticVerification: okStatic, siblings: [], siblingSearchTruncated: ['time budget'], deps: { attemptFn: confirmedFirst } });
  assert.equal(partial.completeness, 'DEGRADED'); assert.ok(partial.degradedLegs.includes('sibling-search-incomplete'));
  const found = await verifyFixWithProof({ finding: { id: 'F1', stableId: 'F1' }, reproducer: repro, files: { 'a.js': 'p' }, scanRoot: '.', staticVerification: okStatic, siblings: [{ file: 'b.js', line: 2 }], deps: { attemptFn: confirmedFirst } });
  assert.ok(found.degradedLegs.includes('sibling-exposures:1'));
});
