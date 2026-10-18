// Log reading, matching and historical hunting (PRD 7 requirement 4, privacy, and the "NOT_OBSERVED is not NOT_EXPLOITED" rule).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { parseLine, parseQuery, readLogs } from '../../src/posture/dnr/log-reader.js';
import { evaluateEvent, pathMatches, requiredFields } from '../../src/posture/dnr/matchers.js';
import { buildDetectionIR } from '../../src/posture/dnr/detection-ir.js';
import { huntLogs, HUNT_VERDICTS } from '../../src/posture/dnr/hunt.js';
import { redactValue } from '../../src/posture/dnr/redact.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/dnr/logs');
const ir = (a = {}, cwe = 'CWE-78') => buildDetectionIR({ finding: { id: 'F1', cwe }, proof: { state: 'EXPLOIT_CONFIRMED', reproducer: { attack: { method: 'POST', path: '/api/export', parameter: 'filename', location: 'body', payloadClass: 'command-injection', ...a } } } }).ir;
const write = (dir, name, text) => { fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true }); fs.writeFileSync(path.join(dir, name), text); };

test('parseLine: common/combined logs, JSON lines and Envoy shapes; anything else is a failure, never a guess', () => {
  const clf = parseLine('203.0.113.9 - bob [10/Oct/2023:13:55:36 -0700] "GET /a/b?x=1&y=%3Bid HTTP/1.1" 200 2326 "-" "curl"');
  assert.equal(clf.method, 'GET'); assert.equal(clf.path, '/a/b'); assert.deepEqual(clf.query, { x: ['1'], y: [';id'] });
  assert.equal(clf.time, '2023-10-10T20:55:36.000Z', 'the logged offset is applied');
  assert.equal(clf.authPresent, null, 'a combined log cannot say whether a credential was sent');
  assert.equal(clf.bodyParams, null);
  const js = parseLine('{"@timestamp":"2024-03-14T02:13:44Z","http":{"request":{"method":"post"},"response":{"status_code":200}},"url":{"path":"/api/export"},"body":"{\\"filename\\":\\"a\\"}"}');
  assert.equal(js.method, 'POST'); assert.equal(js.path, '/api/export'); assert.equal(js.status, 200); assert.deepEqual(js.bodyParams, { filename: ['a'] });
  const envoy = parseLine('{"start_time":"2024-03-14T02:13:44.000Z","method":"GET",":path":"/x?q=1","response_code":403}');
  assert.equal(envoy.path, '/x'); assert.equal(envoy.status, 403); assert.deepEqual(envoy.query, { q: ['1'] });
  assert.equal(parseLine('not a log line at all'), null);
  assert.equal(parseLine('{"unrelated":true}'), null);
  assert.equal(parseLine('{broken json'), null);
  assert.equal(parseLine('   '), undefined);
  assert.equal(parseLine('[1,2,3]'), null);
});

test('parseLine: epoch times, auth header presence and hostile content', () => {
  assert.equal(parseLine('{"method":"GET","path":"/a","ts":1710382424}').time, '2024-03-14T02:13:44.000Z');
  assert.equal(parseLine('{"method":"GET","path":"/a","headers":{"Authorization":"Bearer x"}}').authPresent, true);
  assert.equal(parseLine('{"method":"GET","path":"/a","headers":{"Accept":"*/*"}}').authPresent, false);
  assert.equal(parseLine('{"method":"GET","path":"/a"}').authPresent, null);
  assert.deepEqual(parseQuery('a=%ZZ&b=%E0%A4%A&=x&c'), { a: ['%ZZ'], b: ['%E0%A4%A'], '': ['x'], c: [''] }, 'bad escapes are kept literally, never thrown');
  const many = parseQuery(Array.from({ length: 5000 }, (_, i) => `k${i}=v`).join('&'));
  assert.ok(Object.keys(many).length <= 200, 'parameter count is capped');
  assert.equal(parseLine(`{"method":"GET","path":"/a","__proto__":{"polluted":1}}`).method, 'GET');
  assert.equal({}.polluted, undefined);
});

test('matchers: path templates, undecidable vs no-match, and the auth-bypass behavior class', () => {
  assert.equal(pathMatches('/api/users/:id', '/api/users/42'), true);
  assert.equal(pathMatches('/api/users/{id}/x', '/api/users/42/x/'), true);
  assert.equal(pathMatches('/api/users/:id', '/api/users/'), false);
  assert.equal(pathMatches('/api/users/:id', '/api/users/42/extra'), false);
  const d = ir();
  assert.deepEqual(requiredFields(d).sort(), ['body', 'method', 'path']);
  const logged = { method: 'POST', path: '/api/export', query: {}, bodyParams: { filename: ['x; cat /etc/passwd'] }, status: 200, authPresent: null };
  assert.equal(evaluateEvent(d, logged).match, true);
  assert.equal(evaluateEvent(d, { ...logged, bodyParams: { filename: ['report.pdf'] } }).match, false);
  const blind = evaluateEvent(d, { ...logged, bodyParams: null });
  assert.equal(blind.match, false); assert.equal(blind.undecidable, true); assert.deepEqual(blind.missing, ['body']);
  assert.equal(evaluateEvent(d, { ...logged, method: undefined }).undecidable, true);
  const ab = buildDetectionIR({ finding: { id: 'A', cwe: 'CWE-306' }, proof: { state: 'EXPLOIT_CONFIRMED', reproducer: { attack: { method: 'GET', path: '/admin/users', payloadClass: 'auth-bypass' } } } }).ir;
  assert.equal(evaluateEvent(ab, { method: 'GET', path: '/admin/users', status: 200, authPresent: false }).match, true);
  assert.equal(evaluateEvent(ab, { method: 'GET', path: '/admin/users', status: 200, authPresent: true }).match, false);
  assert.equal(evaluateEvent(ab, { method: 'GET', path: '/admin/users', status: 401, authPresent: false }).match, false);
  assert.equal(evaluateEvent(ab, { method: 'GET', path: '/admin/users', status: 200, authPresent: null }).undecidable, true, 'unknown auth is not "no auth"');
});

test('readLogs: caps, symlinks, compressed files and unreadable paths are reported, never crash', async () => {
  const dir = mkTestTmp('dnr-logs-');
  write(dir, 'a.log', `${'x'.repeat(40000)}\n{"method":"GET","path":"/ok"}\ngarbage\n`);
  fs.writeFileSync(path.join(dir, 'b.log.gz'), Buffer.from([0x1f, 0x8b, 8, 0]));
  fs.symlinkSync(path.join(dir, 'a.log'), path.join(dir, 'link.log'));
  const evs = [];
  const st = await readLogs(dir, { onEvent: (e) => evs.push(e) });
  assert.equal(evs.length, 1); assert.equal(st.parsed, 1);
  assert.equal(st.oversizeLines, 1); assert.ok(st.failed >= 2);
  const reasons = st.filesSkipped.map((f) => f.reason).sort();
  assert.deepEqual(reasons, ['compressed-unsupported', 'symlink']);
  const missing = await readLogs(path.join(dir, 'nope'));
  assert.equal(missing.unreadable, true);
  const viaLink = await readLogs(path.join(dir, 'link.log'));
  assert.equal(viaLink.unreadable, true, 'a symlink given directly is refused too');
});

test('readLogs: file, line and time budgets are enforced and disclosed', async () => {
  const dir = mkTestTmp('dnr-budget-');
  write(dir, 'a.log', Array.from({ length: 50 }, (_, i) => `{"method":"GET","path":"/p${i}"}`).join('\n'));
  write(dir, 'b.log', '{"method":"GET","path":"/b"}\n');
  const lineCap = await readLogs(dir, { limits: { maxLines: 10 } });
  assert.equal(lineCap.parsed, 10); assert.ok(lineCap.truncated.includes('line-limit'));
  const sizeCap = await readLogs(dir, { limits: { maxFileBytes: 100 } });
  assert.ok(sizeCap.truncated.includes('file-too-large'));
  const clock = await readLogs(dir, { limits: { budgetMs: -1 } });
  assert.equal(clock.budgetExhausted, true);
  const ac = new AbortController(); ac.abort();
  assert.equal((await readLogs(dir, { signal: ac.signal })).aborted, true);
  const countCap = await readLogs(dir, { limits: { maxFiles: 1 } });
  assert.ok(countCap.filesSkipped.some((f) => f.reason === 'file-count-limit'));
});

test('hunt: the exploit in structured app logs is OBSERVED, lookalikes are not, and the evidence is redacted', async () => {
  const r = await huntLogs({ ir: ir(), logsPath: path.join(FIX, 'app.jsonl') });
  assert.equal(r.verdict, 'OBSERVED');
  assert.equal(r.matches.count, 2, 'two exploit requests; the three lookalikes (other endpoint, other method, other field) do not count');
  assert.equal(r.matches.firstSeen, '2024-03-14T02:13:44.000Z');
  assert.equal(r.notExploitedClaim, false);
  assert.equal(r.egress, 'none');
  const text = JSON.stringify(r);
  assert.doesNotMatch(text, /abcd1234efgh5678secretvalue/, 'a token inside the matched value is not persisted');
  assert.match(text, /\[REDACTED/);
  assert.ok(r.matches.samples.every((s) => /^[0-9a-f]{16}$/.test(s.valueFingerprint)));
  assert.match(r.statement, /lead to investigate/);
});

test('hunt: a clean log is NOT_OBSERVED, and the result refuses to call that "not exploited"', async () => {
  const r = await huntLogs({ ir: ir(), logsPath: path.join(FIX, 'clean') });
  assert.equal(r.verdict, 'NOT_OBSERVED');
  assert.equal(r.notExploitedClaim, false);
  assert.match(r.statement, /does not establish that the vulnerability was not exploited/);
  assert.equal(r.matches.count, 0);
});

test('hunt: logs that cannot show the parameter are INCONCLUSIVE, not clean', async () => {
  const r = await huntLogs({ ir: ir(), logsPath: path.join(FIX, 'incomplete') });
  assert.equal(r.verdict, 'INCONCLUSIVE');
  assert.ok(r.caveats.some((c) => /lacked a field.*body/.test(c)), r.caveats.join('|'));
  assert.deepEqual(r.coverage.requiredFields.sort(), ['body', 'method', 'path']);
  assert.equal(r.coverage.fieldAvailability.body, 0);
});

test('hunt: INCONCLUSIVE for each reason a negative answer would be unsafe', async () => {
  const dir = mkTestTmp('dnr-incon-');
  const good = Array.from({ length: 20 }, (_, i) => `{"time":"2024-03-1${i % 9}T00:00:00Z","method":"POST","path":"/api/export","body":{"filename":"f${i}.pdf"}}`);
  write(dir, 'parse/a.jsonl', `${good.join('\n')}\n${Array.from({ length: 5 }, () => 'junk line').join('\n')}\n`);
  assert.ok((await huntLogs({ ir: ir(), logsPath: path.join(dir, 'parse') })).caveats.some((c) => /could not be parsed/.test(c)));
  assert.equal((await huntLogs({ ir: ir(), logsPath: path.join(dir, 'parse') })).verdict, 'INCONCLUSIVE');
  write(dir, 'notime/a.jsonl', '{"method":"POST","path":"/api/export","body":{"filename":"a.pdf"}}\n');
  const nt = await huntLogs({ ir: ir(), logsPath: path.join(dir, 'notime') });
  assert.equal(nt.verdict, 'INCONCLUSIVE'); assert.ok(nt.caveats.some((c) => /no event carries a timestamp/.test(c)));
  write(dir, 'cut/a.jsonl', `${good.join('\n')}\n`);
  const cut = await huntLogs({ ir: ir(), logsPath: path.join(dir, 'cut'), limits: { maxLines: 5 } });
  assert.equal(cut.verdict, 'INCONCLUSIVE'); assert.ok(cut.caveats.some((c) => /cut short/.test(c)));
  const bad = await huntLogs({ ir: ir(), logsPath: path.join(dir, 'cut'), since: 'not-a-date' });
  assert.equal(bad.verdict, 'INCONCLUSIVE'); assert.equal(bad.matches.count, 0);
  const skipped = mkTestTmp('dnr-skip-');
  write(skipped, 'a.jsonl', `${good.join('\n')}\n`);
  fs.writeFileSync(path.join(skipped, 'older.log.gz'), 'x');
  assert.equal((await huntLogs({ ir: ir(), logsPath: skipped })).verdict, 'INCONCLUSIVE', 'a compressed file we could not read means part of the history is missing');
});

test('hunt: no readable request records is TELEMETRY_UNAVAILABLE', async () => {
  const dir = mkTestTmp('dnr-none-');
  write(dir, 'empty.log', '');
  write(dir, 'other.log', 'this is not an access log\njust text\n');
  for (const p of [path.join(dir, 'missing'), path.join(dir, 'empty.log'), path.join(dir, 'other.log'), dir]) {
    const r = await huntLogs({ ir: ir(), logsPath: p });
    assert.equal(r.verdict, 'TELEMETRY_UNAVAILABLE', p);
    assert.equal(r.notExploitedClaim, false);
    assert.ok(r.caveats.length);
  }
});

test('hunt: a requested window excludes events outside it and is disclosed', async () => {
  const r = await huntLogs({ ir: ir(), logsPath: path.join(FIX, 'app.jsonl'), since: '2024-03-15T00:00:00Z' });
  assert.notEqual(r.verdict, 'OBSERVED', 'the exploit requests are on the 14th, before the window');
  assert.ok(r.coverage.outOfWindow > 0);
  const inWin = await huntLogs({ ir: ir(), logsPath: path.join(FIX, 'app.jsonl'), since: '2024-03-14T00:00:00Z', until: '2024-03-14T23:59:59Z' });
  assert.equal(inWin.verdict, 'OBSERVED'); assert.equal(inWin.matches.count, 2);
});

test('hunt: verdicts are a closed set and an auth-bypass hunt over a log that hides credentials is not clean', async () => {
  assert.deepEqual([...HUNT_VERDICTS], ['OBSERVED', 'NOT_OBSERVED', 'INCONCLUSIVE', 'TELEMETRY_UNAVAILABLE']);
  const ab = buildDetectionIR({ finding: { id: 'A', cwe: 'CWE-306' }, proof: { state: 'EXPLOIT_CONFIRMED', reproducer: { attack: { method: 'POST', path: '/api/export', payloadClass: 'auth-bypass' } } } }).ir;
  const r = await huntLogs({ ir: ab, logsPath: path.join(FIX, 'incomplete') });
  assert.equal(r.verdict, 'INCONCLUSIVE');
  assert.ok(r.caveats.some((c) => /auth/.test(c)));
});

test('redaction: credentials, personal data and long tokens never survive', () => {
  const cases = ['password=hunter2', 'ada@example.com', '4111 1111 1111 1111', '123-45-6789', 'Bearer abcdefghijklmnop', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'A'.repeat(60)];
  for (const c of cases) assert.doesNotMatch(redactValue(`x ${c} y`), new RegExp(c.slice(0, 12).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), c);
  assert.equal(redactValue('ab '.repeat(200), 50).length, 51);
  assert.equal(redactValue('; cat /etc/passwd'), '; cat /etc/passwd', 'the payload SHAPE is kept; that is the evidence');
});

test('privacy: the loop has no network or model dependency, so production logs cannot leave the machine', () => {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../src/posture/dnr');
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.js'))) {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.doesNotMatch(src, /from 'node:(?:http|https|net|tls|dgram|dns|http2)'|\bfetch\(|XMLHttpRequest|llm-validator|egress\/|WebSocket/, `${f} must stay local`);
  }
});
