// E6-04: the cross-scan analysis cache returns exactly what a cold scan returns after any change to an entrypoint, a dependency, the configuration or a
// sanitizer; a stale, planted or damaged cache is discarded, never trusted; secret-bearing results are not kept.
//
// Set EE_E604_SWEEP=1 to also run the broad metamorphic sweep over every fixture directory (slow).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { canonicalizeScan } from '../../src/pipeline/canonical-output.js';
import { computeGlobalKey } from '../../src/posture/scan-checkpoint.js';
import { confidentialOf } from '../../src/posture/artifact-registry.js';
import { secretCanaryHit } from '../../src/posture/runtime-trace-ingest.js';

setStateWritesEnabled(true);
const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const CACHE_FILE = (root) => path.join(root, '.agentic-security', 'analysis-cache.jsonl');
const project = () => { const b = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e6-04-')); fs.writeFileSync(path.join(b, 'package.json'), '{}'); return b; };
const done = (...dirs) => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); };

async function scan(root, files, { cache, env = {} } = {}) {
  const saved = {}; for (const k of Object.keys(env)) { saved[k] = process.env[k]; process.env[k] = env[k]; }
  if (cache) process.env.AGENTIC_SECURITY_ANALYSIS_CACHE = '1'; else delete process.env.AGENTIC_SECURITY_ANALYSIS_CACHE;
  try {
    const s = await runFullScan({ fileContents: files, scanRoot: root, deep: false });
    return { digest: canonicalizeScan(s).digest, canonical: canonicalizeScan(s).canonical, meta: s._scanMeta.checkpoint, scan: s };
  } finally { delete process.env.AGENTIC_SECURITY_ANALYSIS_CACHE; for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}
const sig = (r) => [...(r.canonical.findings || []), ...(r.canonical.logicVulns || [])].map((f) => `${f.file}:${f.line}:${f.vuln}`).sort();

/**
 * warm = scan `before` with the cache, then scan `after` with it.
 * cold = scan `before` WITHOUT the cache, then scan `after` without it: the same history on disk (a scan also records an SBOM history that the next scan
 * compares against, which is unrelated to the cache), so the only difference between the arms is whether the cache was used.
 */
async function incrementalVsCold(before, after, { beforeEnv = {}, afterEnv = {}, prep = null, prepAfter = null } = {}) {
  const warmRoot = project(); const coldRoot = project();
  try {
    if (prep) prep(warmRoot); if (prep) prep(coldRoot);
    await scan(warmRoot, before, { cache: true, env: beforeEnv });
    await scan(coldRoot, before, { cache: false, env: beforeEnv });
    if (prepAfter) { prepAfter(warmRoot); prepAfter(coldRoot); }
    const warm = await scan(warmRoot, after, { cache: true, env: afterEnv });
    const cold = await scan(coldRoot, after, { cache: false, env: afterEnv });
    return { warm, cold };
  } finally { done(warmRoot, coldRoot); }
}

const EXEC = "const { exec } = require('child_process');\nconst express = require('express');\nconst app = express();\napp.get('/run', (req, res) => { exec('ls ' + req.query.dir, () => res.end()); });\n";
const OTHER = "const express = require('express');\nconst app = express();\napp.get('/hi', (req, res) => res.send('hi'));\n";

test('a second scan of the same tree is served from the cache and gives the same findings as a cold scan', async () => {
  const root = project(); const cold = project();
  try {
    const files = { 'a.js': EXEC, 'b.js': OTHER, 'c.js': EXEC.replace('/run', '/run2') };
    const c = await scan(cold, files, { cache: false });
    const r1 = await scan(root, files, { cache: true });
    assert.equal(r1.meta.resumed, 0, 'nothing to reuse yet'); assert.equal(r1.meta.kind, 'analysis-cache');
    const r2 = await scan(root, files, { cache: true });
    assert.equal(r2.meta.resumed, 3, 'all three files came from the cache');
    assert.equal(r1.digest, c.digest); assert.equal(r2.digest, c.digest);
    assert.ok(c.canonical.findings.length > 0, 'the comparison is not over an empty result');
    assert.ok(fs.existsSync(CACHE_FILE(root)), 'the cache is kept after a completed scan');
    const lines = fs.readFileSync(CACHE_FILE(root), 'utf8').trim().split('\n');
    assert.equal(lines.length, 4, 'header and one line per file: compacted, not growing');
    assert.match(JSON.parse(lines[0]).hm, /^[0-9a-f]{64}$/, 'the header carries a signature'); assert.match(JSON.parse(lines[1]).c, /^[0-9a-f]{64}$/);
    const r3 = await scan(root, files, { cache: true });
    assert.equal(fs.readFileSync(CACHE_FILE(root), 'utf8').trim().split('\n').length, 4, 'a third scan does not grow the file'); assert.equal(r3.digest, c.digest);
  } finally { done(root, cold); }
});

test('ENTRYPOINT EDIT: only the edited file is re-analysed, and a finding it newly contains appears', async () => {
  const before = { 'a.js': OTHER, 'b.js': OTHER.replace('/hi', '/yo'), 'c.js': EXEC };
  const after = { ...before, 'a.js': EXEC.replace('/run', '/changed') };
  const { warm, cold } = await incrementalVsCold(before, after);
  assert.equal(warm.meta.resumed, 2, 'b.js and c.js reused'); assert.deepEqual(warm.meta.invalidatedFiles, [{ file: 'a.js', reason: 'content changed since it was checkpointed' }]);
  assert.equal(warm.digest, cold.digest); assert.ok(sig(warm).some((s) => s.startsWith('a.js')), 'the new finding is present, not hidden by a stale entry');
});

test('the reverse: a vulnerability FIXED in a file disappears from the warm result too (no stale finding)', async () => {
  const before = { 'a.js': EXEC, 'b.js': OTHER };
  const after = { ...before, 'a.js': OTHER.replace('/hi', '/fixed') };
  const { warm, cold } = await incrementalVsCold(before, after);
  assert.equal(warm.digest, cold.digest); assert.ok(!sig(warm).some((s) => s.startsWith('a.js:') && /Command/i.test(s)), sig(warm).join('\n'));
});

test('DEPENDENCY EDIT: a change in one file that alters what another file\'s analysis sees invalidates it (cross-file project context)', async () => {
  const reviews = "const express = require('express');\nconst Review = require('./models/review');\nconst app = express();\napp.post('/products/:id/review', async (req, res) => {\n  const r = await Review.create({ productId: req.params.id, rating: req.body.rating });\n  res.json(r);\n});\nmodule.exports = app;\n";
  const withModel = { 'reviews.js': reviews, 'models/order.js': 'class Order { constructor(id) { this.id = id; } }\nmodule.exports = Order;\n' };
  const withoutModel = { 'reviews.js': reviews, 'models/order.js': 'class Thing { constructor(id) { this.id = id; } }\nmodule.exports = Thing;\n' };
  const a = await incrementalVsCold(withoutModel, withModel);
  assert.equal(a.warm.digest, a.cold.digest, 'adding an e-commerce model elsewhere changes reviews.js, which did not change');
  const b = await incrementalVsCold(withModel, withoutModel);
  assert.equal(b.warm.digest, b.cold.digest, 'and removing it changes it back');
  const hit = (r) => sig(r).filter((s) => s.startsWith('reviews.js') && /Purchase/i.test(s)).length;
  assert.notEqual(hit(a.cold), hit(b.cold), 'the dependency really does change reviews.js\'s findings, so the test is not vacuous');
  assert.equal(a.warm.meta.resumed, 0, 'a changed project context discards the cache rather than reusing a file that could now be wrong');
});

test('FILE ADDED and FILE REMOVED: the warm result equals the cold result', async () => {
  const base = { 'a.js': EXEC, 'b.js': OTHER };
  const added = await incrementalVsCold(base, { ...base, 'c.js': EXEC.replace('/run', '/new') });
  assert.equal(added.warm.digest, added.cold.digest); assert.equal(added.warm.meta.resumed, 2);
  const removed = await incrementalVsCold({ ...base, 'c.js': EXEC.replace('/run', '/gone') }, base);
  assert.equal(removed.warm.digest, removed.cold.digest);
  assert.equal(JSON.stringify(removed.warm.canonical).includes('c.js'), false, 'nothing of the removed file survives');
});

test('CONFIGURATION: changing a scanner switch discards the cache and the result equals a cold scan under the new switch', async () => {
  const files = { 'a.js': "const k = require('openai');\nconst c = new k.OpenAI();\nasync function f(q){ return c.chat.completions.create({ model: 'x', messages: [{ role: 'user', content: q }] }); }\n" + EXEC };
  const { warm, cold } = await incrementalVsCold(files, files, { afterEnv: { AGENTIC_SECURITY_NO_LLM_APP: '1', AGENTIC_SECURITY_NO_INTEGRATION: '1' } });
  assert.equal(warm.meta.resumed, 0); assert.match(warm.meta.discardReason, /AGENTIC_SECURITY_\* environment switch changed/);
  assert.equal(warm.digest, cold.digest);
  const k = (e) => computeGlobalKey({ engineVersion: '1', rulesetVersion: '1', bundleSha: 'x', env: e });
  assert.equal(k({}), k({ AGENTIC_SECURITY_ANALYSIS_CACHE: '1', AGENTIC_SECURITY_NO_STRING_MEMO: '1' }), 'the switches that only choose whether a cache is used are not part of the key');
  assert.notEqual(k({}), k({ AGENTIC_SECURITY_NO_MOBILE: '1' })); assert.notEqual(k({}), computeGlobalKey({ engineVersion: '2', rulesetVersion: '1', bundleSha: 'x', env: {} }));
  assert.notEqual(k({}), computeGlobalKey({ engineVersion: '1', rulesetVersion: '1', bundleSha: 'x', env: {}, extra: 'ctx' }), 'cross-file context is part of the key');
});

test('CUSTOM RULES: adding or removing an operator rule changes an UNCHANGED file\'s result, and the warm scan follows in both directions', async () => {
  const app = "const express = require('express');\nconst app = express();\napp.get('/u', (req, res) => {\n  const v = req.query.q;\n  legacyRun(v);\n  res.end();\n});\n";
  const files = { 'app.js': app, 'other.js': OTHER };
  const write = (root, text) => { fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true }); fs.writeFileSync(path.join(root, '.agentic-security', 'rules.yml'), text); };
  const SINK = "sinks:\n  - pattern: 'legacyRun\\('\n    type: Command Injection\n    cwe: CWE-78\n    severity: high\n";
  const SANITIZER = "sanitizers:\n  - pattern: 'legacyRun\\('\n    type: Custom Sanitizer\n";
  const coldRoot = project(); const withRoot = project();
  try {
    write(withRoot, SINK);
    const coldWithout = await scan(coldRoot, files, { cache: false }); const coldWith = await scan(withRoot, files, { cache: false });
    assert.notEqual(sig(coldWithout).join('|'), sig(coldWith).join('|'), 'the rule changes app.js\'s findings, so the comparison below is not vacuous');
    // populate without the rule, then add it
    const w1 = project(); try {
      await scan(w1, files, { cache: true }); write(w1, SINK);
      const warm = await scan(w1, files, { cache: true });
      assert.equal(warm.digest, coldWith.digest, 'rule added: the warm result equals cold-with-rule'); assert.equal(warm.meta.resumed, 0, 'the rules file is part of the context, so the cache was not reused');
    } finally { done(w1); }
    // populate with the rule, then remove it (a stale entry would keep reporting a finding the rule no longer produces)
    const w2 = project(); try {
      write(w2, SINK); await scan(w2, files, { cache: true }); fs.rmSync(path.join(w2, '.agentic-security', 'rules.yml'));
      const warm = await scan(w2, files, { cache: true });
      assert.equal(warm.digest, coldWithout.digest, 'rule removed: the warm result equals cold-without-rule');
    } finally { done(w2); }
    // swapping one rule for another of a different kind
    const w3 = project(); const c3 = project(); try {
      write(w3, SINK); await scan(w3, files, { cache: true }); write(w3, SANITIZER); write(c3, SANITIZER);
      const warm = await scan(w3, files, { cache: true }); const cold = await scan(c3, files, { cache: false });
      assert.equal(warm.digest, cold.digest, 'rule replaced');
    } finally { done(w3, c3); }
  } finally { done(coldRoot, withRoot); }
});

test('PLANTED CACHE: a cache file made without this installation\'s key is discarded whole, so findings cannot be hidden by shipping one', async () => {
  const files = { 'a.js': EXEC, 'b.js': OTHER };
  const root = project(); const cold = project();
  try {
    const c = await scan(cold, files, { cache: false });
    await scan(root, files, { cache: true });
    const fp = CACHE_FILE(root);
    const lines = fs.readFileSync(fp, 'utf8').trim().split('\n');
    // forge: same header and records, but with the findings of a.js emptied and the checksum recomputed the way an attacker without the key can (plain SHA-256)
    const { createHash } = await import('node:crypto');
    const forged = [lines[0]];
    for (const l of lines.slice(1)) {
      const rec = JSON.parse(l); const payload = JSON.parse(rec.d); payload.findings = []; payload.sinks = []; payload.sources = []; payload.pfrFindings = 0;
      rec.d = JSON.stringify(payload); rec.c = createHash('sha256').update(rec.d, 'utf8').digest('hex'); forged.push(JSON.stringify(rec));
    }
    fs.writeFileSync(fp, forged.join('\n') + '\n');
    const r = await scan(root, files, { cache: true });
    assert.equal(r.meta.resumed, 0, 'forged records were not replayed'); assert.equal(r.digest, c.digest, 'the findings are all still there');
    // a header with a made-up signature is refused too
    const h = JSON.parse(lines[0]); h.hm = 'f'.repeat(64);
    fs.writeFileSync(fp, [JSON.stringify(h), ...lines.slice(1)].join('\n') + '\n');
    const r2 = await scan(root, files, { cache: true });
    assert.equal(r2.meta.resumed, 0); assert.match(r2.meta.discardReason, /not written by this installation/); assert.equal(r2.digest, c.digest);
    // and one with no signature at all
    delete h.hm; fs.writeFileSync(fp, [JSON.stringify(h), ...lines.slice(1)].join('\n') + '\n');
    assert.equal((await scan(root, files, { cache: true })).meta.resumed, 0);
  } finally { done(root, cold); }
});

test('DAMAGED CACHE: a torn tail, garbage and a wrong format are survived; the result is the cold result', async () => {
  const files = { 'a.js': EXEC, 'b.js': OTHER };
  const root = project(); const cold = project();
  try {
    const c = await scan(cold, files, { cache: false });
    await scan(root, files, { cache: true });
    const fp = CACHE_FILE(root); const good = fs.readFileSync(fp, 'utf8');
    fs.writeFileSync(fp, good + '{"f":"a.js","h":"x","c":"y","d":"{trunc');
    const torn = await scan(root, files, { cache: true });
    assert.equal(torn.digest, c.digest); assert.equal(torn.meta.resumed, 2, 'the verified records before the torn tail were kept');
    fs.writeFileSync(fp, 'not json at all\n\u0000\u0001');
    assert.equal((await scan(root, files, { cache: true })).digest, c.digest);
    fs.writeFileSync(fp, '');
    assert.equal((await scan(root, files, { cache: true })).digest, c.digest);
    fs.writeFileSync(fp, JSON.stringify({ v: 'agentic-security-scan-checkpoint/1', gk: 'x' }) + '\n');
    const r = await scan(root, files, { cache: true }); assert.equal(r.digest, c.digest); assert.match(r.meta.discardReason, /format changed|corrupt|empty/);
  } finally { done(root, cold); }
});

test('NOT CACHED: a file whose analysis has side effects (MCP configuration) or whose result holds a secret is analysed afresh every time', async () => {
  const SECRET = 'sk_' + 'live_4eC39HqLyjWDarjtT1zdp7dc';
  const files = { 'a.js': EXEC, '.mcp.json': JSON.stringify({ mcpServers: { x: { command: 'npx', args: ['-y', 'some-mcp-server'] } } }), 'config.js': `const stripeKey = '${SECRET}';\nmodule.exports = { stripeKey };\n` };
  const root = project();
  try {
    const r1 = await scan(root, files, { cache: true });
    const text = fs.readFileSync(CACHE_FILE(root), 'utf8');
    assert.ok(!text.includes(SECRET), 'the secret is not in the cache');
    assert.ok(!text.includes('.mcp.json'), 'the MCP configuration is not cached (its analysis compares against a recorded baseline)');
    assert.ok(text.includes('"a.js"') || text.includes('a.js'), 'an ordinary file is');
    assert.ok(r1.meta.secretSkips >= 1, 'the secret-bearing result was skipped, and counted');
    const r2 = await scan(root, files, { cache: true });
    assert.equal(r2.meta.resumed, 1, 'only the ordinary file was reused'); assert.equal(r2.digest, r1.digest);
    assert.equal(secretCanaryHit(`password = "hunter2hunter2"`), 'secret-assignment'); assert.equal(secretCanaryHit('const a = 1;'), null);
    assert.equal(confidentialOf('analysis-cache.jsonl'), true, 'registered as confidential state');
  } finally { done(root); }
});

test('OFF BY DEFAULT: without the switch no cache file is written and nothing is read', async () => {
  const root = project();
  try {
    const r = await scan(root, { 'a.js': EXEC }, { cache: false });
    assert.equal(r.meta.enabled, false); assert.equal(fs.existsSync(CACHE_FILE(root)), false);
  } finally { done(root); }
});

test('the resume checkpoint now restores sharing between a finding and its source and sink entries (a defect the cache comparison exposed)', async () => {
  const root = project(); const cold = project();
  try {
    const files = { 'a.js': EXEC };
    const c = await scan(cold, files, { cache: false });
    await scan(root, files, { cache: true });
    const w = await scan(root, files, { cache: true });
    assert.equal(w.meta.resumed, 1); assert.equal(w.digest, c.digest, 'flowStatus and riskStatus, set on shared source and sink objects after analysis, reach the replayed findings');
  } finally { done(root, cold); }
});

// ---- the broad sweep ---------------------------------------------------------------------------------------------------------

const SWEEP = process.env.EE_E604_SWEEP === '1';
function loadDir(d) {
  const files = {};
  (function walk(p, rel) {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      if (['.agentic-security', 'node_modules', '.git'].includes(e.name)) continue;
      const r = path.join(rel, e.name);
      if (e.isDirectory()) walk(path.join(p, e.name), r);
      else if (/\.(js|mjs|ts|tsx|jsx|py|java|rb|php|go|cs|kt|rs|json|ya?ml|properties|tf|Dockerfile)$/i.test(e.name) && fs.statSync(path.join(p, e.name)).size < 150_000) files[r] = fs.readFileSync(path.join(p, e.name), 'utf8');
    }
  })(path.join(FIX, d), '');
  return files;
}
function mutate(files, kind, n) {
  const names = Object.keys(files).sort(); const out = { ...files };
  if (!names.length) return out;
  const pick = names[n % names.length];
  if (kind === 'edit') out[pick] = files[pick] + (/\.(py|rb)$/.test(pick) ? '\nimport os\nos.system(input())\n' : /\.(js|mjs|ts|jsx|tsx)$/.test(pick) ? "\nrequire('child_process').exec(process.argv[2]);\n" : '\n');
  else if (kind === 'constant') out[pick] = files[pick].replace(/(=\s*['"])([^'"\n]{1,40})(['"])/, '$1changed-by-sweep$3');
  else if (kind === 'remove') delete out[pick];
  else if (kind === 'add') out['added_by_sweep.js'] = EXEC;
  return out;
}
test('SWEEP: over every fixture directory, edit / constant / add / remove mutations give a warm result equal to the cold result', { skip: !SWEEP, timeout: 3_600_000 }, async () => {
  const dirs = fs.readdirSync(FIX, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  let compared = 0; const failures = []; let reuse = 0;
  for (const [i, d] of dirs.entries()) {
    const files = loadDir(d); const n = Object.keys(files).length;
    if (n === 0 || n > 120) continue;
    for (const kind of ['edit', 'constant', 'add', 'remove']) {
      const after = mutate(files, kind, i);
      if (JSON.stringify(after) === JSON.stringify(files)) continue;
      const { warm, cold } = await incrementalVsCold(files, after);
      compared++; reuse += warm.meta.resumed;
      if (warm.digest !== cold.digest) failures.push(`${d} ${kind}: warm ${warm.canonical.findings.length} findings vs cold ${cold.canonical.findings.length}`);
    }
  }
  console.log(`sweep: ${compared} comparisons over ${dirs.length} directories, ${reuse} file results reused, ${failures.length} mismatches`);
  const out = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'docs', 'engineering-excellence', 'data', 'analysis-cache-sweep.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify({ schema: 'agentic-security/analysis-cache-sweep@1', fixtureDirectories: dirs.length, comparisons: compared, mutationKinds: ['edit', 'constant', 'add', 'remove'], fileResultsReused: reuse, mismatches: failures, note: 'each comparison scans a fixture tree to fill the cache, mutates it, and compares a warm scan with a cold scan that has the same on-disk history; directories with more than 120 files are skipped' }, null, 2) + '\n');
  assert.ok(compared > 100, `compared ${compared}`);
  assert.deepEqual(failures, []);
});
