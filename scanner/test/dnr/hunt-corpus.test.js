// GA-10 §2 (0.195.31): the hunt against the labelled log corpus (`test/fixtures/dnr/corpus/manifest.json`). Every scenario names
// the attack the detection is built from and the verdict the hunt must return with the caveat it must state: malicious and
// near-miss samples per class, malformed records, a zone-less timestamp, a retention gap (informational by default, blocking when
// the operator declares a gap limit) and a payload past the parser's parameter limit. The timezone cases are parsed in child
// processes under two TZ values, so the same line never lands on different instants on different machines.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildDetectionIR } from '../../src/posture/dnr/detection-ir.js';
import { huntLogs } from '../../src/posture/dnr/hunt.js';
import { parseLine, timeIsAmbiguous } from '../../src/posture/dnr/log-reader.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'dnr', 'corpus');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const FINDING = { id: 'F1', stableId: 'F1', cwe: 'CWE-78', file: 'app.js', line: 9 };
const irFor = (attack) => {
  const r = buildDetectionIR({ finding: FINDING, proof: { state: 'EXPLOIT_CONFIRMED', recordDigest: 'abc123', oracle: 'command_execution', reproducer: { attack: { sink: 'exec()', ...attack } } } });
  assert.equal(r.ok, true, r.reason);
  return r.ir;
};

test('the corpus manifest is well formed and every scenario directory exists', () => {
  assert.equal(manifest.schema, 'agentic-security/dnr-hunt-corpus');
  assert.ok(manifest.scenarios.length >= 10);
  for (const s of manifest.scenarios) {
    assert.ok(fs.existsSync(path.join(ROOT, s.dir)), s.dir);
    assert.ok(['OBSERVED', 'NOT_OBSERVED', 'INCONCLUSIVE', 'TELEMETRY_UNAVAILABLE'].includes(s.expect.verdict), s.id);
  }
});

for (const s of manifest.scenarios) {
  test(`corpus: ${s.id} is ${s.expect.verdict}${s.expect.caveat ? ` with "${s.expect.caveat}"` : ''}`, async () => {
    const r = await huntLogs({ ir: irFor(s.attack), logsPath: path.join(ROOT, s.dir), limits: s.limits });
    assert.equal(r.verdict, s.expect.verdict, `${s.id}: ${JSON.stringify(r.caveats)}`);
    assert.equal(r.notExploitedClaim, false);
    if (s.expect.matches !== undefined) assert.equal(r.matches.count, s.expect.matches, s.id);
    if (s.expect.caveat) assert.ok(r.caveats.some((c) => c.includes(s.expect.caveat)), `${s.id}: ${JSON.stringify(r.caveats)}`);
    if (s.expect.gaps !== undefined) { assert.equal(r.coverage.gaps.count, s.expect.gaps); assert.equal(r.coverage.gaps.listed.length, s.expect.gaps); }
    if (s.expect.verdict === 'NOT_OBSERVED') assert.ok(r.caveats.every((c) => c.startsWith('informational: ') || c.startsWith('no request to the endpoint')), 'a negative carries only informational caveats');
  });
}

test('timezone: five spellings of one instant parse to the same ISO time, and a zone-less timestamp is ambiguous under any TZ', () => {
  const lines = fs.readFileSync(path.join(ROOT, 'timezone', 'app.jsonl'), 'utf8').trim().split('\n');
  const times = lines.slice(0, 5).map((l) => parseLine(l).time);
  assert.ok(times.every((t) => t === '2026-03-14T02:13:44.000Z'), JSON.stringify(times));
  const zoneless = parseLine(lines[5]);
  assert.equal(zoneless.time, null);
  assert.equal(zoneless.timeAmbiguous, true);
  assert.equal(timeIsAmbiguous('2026-03-14 02:13:44'), true);
  assert.equal(timeIsAmbiguous('2026-03-14T02:13:44Z'), false);
  assert.equal(timeIsAmbiguous('2026-03-14'), false, 'a bare date has no time to be ambiguous about');
  for (const tz of ['UTC', 'Asia/Kolkata', 'America/Los_Angeles']) {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', `import { parseLine } from ${JSON.stringify(path.resolve('src/posture/dnr/log-reader.js'))}; const l = ${JSON.stringify(lines)}; console.log(JSON.stringify(l.map((x) => { const e = parseLine(x); return [e.time, e.timeAmbiguous]; })));`], { encoding: 'utf8', env: { ...process.env, TZ: tz }, cwd: path.resolve('.') });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.ok(out.slice(0, 5).every(([t]) => t === '2026-03-14T02:13:44.000Z'), `${tz}: ${r.stdout}`);
    assert.deepEqual(out[5], [null, true], `${tz}: the zone-less line is undated and ambiguous, never local time`);
  }
});

test('a query past the parser limit is reported on the event, and a request to another path is not "a request to the endpoint"', async () => {
  const line = fs.readFileSync(path.join(ROOT, 'query-limits', 'app.jsonl'), 'utf8').trim().split('\n').pop();
  const ev = parseLine(line);
  assert.deepEqual(ev.truncated, ['query-params']);
  assert.equal(Object.keys(ev.query).length, 200, 'the parser kept its first two hundred parameters');
  const other = await huntLogs({ ir: irFor({ method: 'GET', path: '/api/nothing-here', parameter: 'name', location: 'query', payloadClass: 'path-traversal' }), logsPath: path.join(ROOT, 'near-miss') });
  assert.equal(other.verdict, 'NOT_OBSERVED');
  assert.equal(other.coverage.endpointEvents, 0);
  assert.ok(other.caveats.some((c) => c.startsWith('no request to the endpoint')), JSON.stringify(other.caveats));
  const same = await huntLogs({ ir: irFor({ method: 'GET', path: '/api/files', parameter: 'name', location: 'query', payloadClass: 'path-traversal' }), logsPath: path.join(ROOT, 'near-miss') });
  assert.equal(same.coverage.endpointEvents, 1, 'one GET to /api/files');
});
