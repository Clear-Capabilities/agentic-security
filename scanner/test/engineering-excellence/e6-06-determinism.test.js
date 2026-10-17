// E6-06: repeated same-input runs give identical canonical findings while run timestamps stay separate; race stress finds no order-sensitive analysis.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { canonicalizeScan, nondeterminismSources } from '../../src/pipeline/canonical-output.js';
import * as os from 'node:os';
import { loadWafRules } from '../../src/posture/waf-ingest.js';

setStateWritesEnabled(false);
const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
function load(...dirs) {
  const files = {};
  for (const d of dirs) (function walk(p, rel) {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      if (e.name === '.agentic-security' || e.name === 'node_modules') continue;
      const r = path.join(rel, e.name);
      if (e.isDirectory()) walk(path.join(p, e.name), r);
      else if (/\.(js|py|java|json|ts|php|rb|go|yml|yaml)$/.test(e.name) && fs.statSync(path.join(p, e.name)).size < 200_000) files[`${d}/${r}`] = fs.readFileSync(path.join(p, e.name), 'utf8');
    }
  })(path.join(FIX, d), '');
  return files;
}
const permute = (files, how) => { const n = Object.keys(files); const o = how === 'rev' ? [...n].reverse() : how === 'rot' ? [...n.slice(7), ...n.slice(0, 7)] : how === 'shuf' ? seeded(n) : n; return Object.fromEntries(o.map((k) => [k, files[k]])); };
function seeded(a) { const r = [...a]; let x = 12345; for (let i = r.length - 1; i > 0; i--) { x = (x * 1103515245 + 12345) & 0x7fffffff; const j = x % (i + 1); [r[i], r[j]] = [r[j], r[i]]; } return r; }
const scan = (fileContents) => runFullScan({ fileContents, scanRoot: null, deep: true });

for (const [name, dirs] of [['vulnerable-js', ['vulnerable-js']], ['python and java mix', ['python-vulnerable', 'xxe-java', 'java-taint-flow']], ['taint chain', ['deep-taint', 'js-code-injection']]]) {
  test(`same input, five different file orders, run concurrently: one canonical digest (${name})`, async () => {
    const files = load(...dirs);
    assert.ok(Object.keys(files).length >= 2, 'the fixture loaded');
    const runs = await Promise.all(['fwd', 'rev', 'rot', 'shuf', 'fwd'].map((h) => scan(permute(files, h))));
    const cs = runs.map((r) => canonicalizeScan(r));
    assert.ok(cs[0].canonical.findings.length > 0, 'the fixture produces findings, so equality is not vacuous');
    for (const c of cs.slice(1)) assert.equal(c.digest, cs[0].digest);
    assert.deepEqual(cs.map((c) => c.canonical), cs.map(() => cs[0].canonical));
  });
}

test('sequential repeats with a delay between: the canonical part is identical and the run part is kept separately', async () => {
  const files = load('vulnerable-js');
  const a = canonicalizeScan(await scan(files)); await new Promise((r) => setTimeout(r, 40)); const b = canonicalizeScan(await scan(files));
  assert.equal(a.digest, b.digest);
  assert.ok(a.run.telemetry && b.run.telemetry, 'telemetry is in the run part');
  assert.ok(!JSON.stringify(a.canonical).includes('"telemetry"') && !JSON.stringify(a.canonical).includes('fileTimings'));
  assert.notDeepEqual(a.run.telemetry, b.run.telemetry, 'run timings differ between runs, and that does not matter');
});

test('what is and is not in the digest: run metadata never changes it, a finding change always does', async () => {
  const base = await scan(load('vulnerable-js'));
  const d0 = canonicalizeScan(base).digest;
  const noisy = { ...base, telemetry: { totalMs: 99999, stages: [] }, _scanMeta: { ...base._scanMeta, startedAt: '2001-01-01T00:00:00Z', durationMs: 7, scanId: 'zzz', fileTimings: [{ file: 'a', ms: 1 }] } };
  assert.equal(canonicalizeScan(noisy).digest, d0);
  const stamped = { ...base, findings: base.findings.map((f) => ({ ...f, detectedAt: Date.now(), elapsedMs: Math.random() })) };
  assert.equal(canonicalizeScan(stamped).digest, d0, 'a per-finding timestamp is volatile');
  const moved = { ...base, findings: base.findings.map((f, i) => (i === 0 ? { ...f, line: f.line + 1 } : f)) };
  assert.notEqual(canonicalizeScan(moved).digest, d0);
  const dropped = { ...base, findings: base.findings.slice(1) };
  assert.notEqual(canonicalizeScan(dropped).digest, d0);
  const shuffledOutput = { ...base, findings: [...base.findings].reverse() };
  assert.equal(canonicalizeScan(shuffledOutput).digest, d0, 'output order of the same findings does not matter');
});

test('numbers are rounded to a fixed precision and keys are ordered, so float noise and key order cannot move the digest', () => {
  const mk = (c, order) => ({ findings: [order ? { b: 1, a: { y: 1, x: 2 }, confidence: c, file: 'f', line: 1, id: 'i' } : { id: 'i', file: 'f', line: 1, confidence: c, a: { x: 2, y: 1 }, b: 1 }] });
  assert.equal(canonicalizeScan(mk(0.1 + 0.2, false)).digest, canonicalizeScan(mk(0.3, true)).digest);
  assert.notEqual(canonicalizeScan(mk(0.3, false)).digest, canonicalizeScan(mk(0.31, false)).digest);
  assert.equal(canonicalizeScan({ findings: [{ file: 'f', line: 1, id: 'i', n: 1.0000000001 }] }).canonical.findings[0].n, 1);
});

test('ordering is total: findings that tie on file, line and vuln are still placed the same way whichever came first', () => {
  const a = { file: 'f', line: 1, vuln: 'v', id: 'same', z: 1 }; const b = { file: 'f', line: 1, vuln: 'v', id: 'same', z: 2 };
  assert.equal(canonicalizeScan({ findings: [a, b] }).digest, canonicalizeScan({ findings: [b, a] }).digest);
});

test('NEGATIVE CONTROL: the stress method does detect an order-sensitive analysis', async () => {
  const orderSensitive = async (fileContents) => ({ findings: [{ id: 'first', file: Object.keys(fileContents)[0], line: 1, vuln: 'v' }] });
  const files = load('vulnerable-js');
  const d = await Promise.all(['fwd', 'rev'].map(async (h) => canonicalizeScan(await orderSensitive(permute(files, h))).digest));
  assert.notEqual(d[0], d[1], 'an analysis that depends on file order produces different digests, which the tests above would fail on');
});

test('nondeterminism is disclosed: a configured model and live feeds are named, and offline/deterministic runs name nothing', () => {
  assert.deepEqual(nondeterminismSources({ AGENTIC_SECURITY_DETERMINISTIC: '1' }), []);
  assert.deepEqual(nondeterminismSources({ AGENTIC_SECURITY_OFFLINE: '1' }), []);
  const live = nondeterminismSources({}); assert.equal(live[0].source, 'network-feeds');
  const llm = nondeterminismSources({ AGENTIC_SECURITY_DETERMINISTIC: '1', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://x', AGENTIC_SECURITY_LLM_MODEL: 'm1' });
  assert.deepEqual(llm.map((x) => x.source), ['llm-validator']); assert.equal(llm[0].model, 'm1');
  assert.deepEqual(nondeterminismSources({ AGENTIC_SECURITY_DETERMINISTIC: '1', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://x', AGENTIC_SECURITY_LLM_VALIDATE: '0' }), []);
  const c = canonicalizeScan({ findings: [] }, { env: { AGENTIC_SECURITY_DETERMINISTIC: '1' }, scannerVersion: '9.9.9' });
  assert.equal(c.provenance.scannerVersion, '9.9.9'); assert.match(c.provenance.rulePackHash, /^[0-9a-f]{16}$/); assert.deepEqual(c.provenance.nondeterminism, []);
});

test('the one randomness that reached output is gone: WAF rules with no id get a content-derived id, the same every time', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e6-06-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}'); fs.mkdirSync(path.join(root, '.agentic-security'));
  const put = (rules) => fs.writeFileSync(path.join(root, '.agentic-security', 'waf-rules.json'), JSON.stringify(rules));
  try {
    put([{ action: 'block', expression: 'http.request.uri.query contains "union select"', description: 'sql injection' }]);
    const a = loadWafRules(root); const b = loadWafRules(root);
    assert.equal(a.length, 1); assert.equal(a[0].id, b[0].id); assert.match(a[0].id, /^cf-[0-9a-f]{8}$/);
    put([{ action: 'block', expression: 'http.request.uri.query contains "xp_cmdshell"', description: 'command injection' }]);
    assert.notEqual(loadWafRules(root)[0].id, a[0].id, 'different content, different id');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
  const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'posture', 'waf-ingest.js'), 'utf8');
  assert.ok(!/Math\.random/.test(src));
});
