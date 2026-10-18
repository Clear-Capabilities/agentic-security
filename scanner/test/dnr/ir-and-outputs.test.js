// Detection IR, payload classes, renderers and validation (PRD 7 requirements 1, 2, 3, 6). Pure functions; no execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDetectionIR, validateDetectionIR, parseRouteText } from '../../src/posture/dnr/detection-ir.js';
import { PAYLOAD_CLASSES, PAYLOAD_CLASS_NAMES, classForCwe, matchesClass } from '../../src/posture/dnr/payload-classes.js';
import { validateAttackFacts } from '../../src/posture/dnr/attack-facts.js';
import { renderAll, renderDetection, FORMATS, classRegex } from '../../src/posture/dnr/outputs.js';
import { validateDetection } from '../../src/posture/dnr/validate.js';
import { validateReproducer } from '../../src/posture/proof-fabric/reproducer.js';

const FINDING = { id: 'F1', stableId: 'F1', cwe: 'CWE-78', file: 'app.js', line: 9 };
const attack = (over = {}) => ({ method: 'POST', path: '/api/export', parameter: 'filename', location: 'body', payloadClass: 'command-injection', sink: 'exec()', ...over });
const proof = (state = 'EXPLOIT_CONFIRMED', a = attack()) => ({ state, recordDigest: 'abc123', oracle: 'command_execution', reproducer: { attack: a } });

test('IR: built only from evidence, grounded, and content-addressed', () => {
  const r = buildDetectionIR({ finding: FINDING, proof: proof() });
  assert.equal(r.ok, true);
  assert.equal(r.ir.grounding, 'exploit-confirmed');
  assert.deepEqual(r.ir.endpoint, { method: 'POST', path: '/api/export' });
  assert.deepEqual(r.ir.parameter, { name: 'filename', location: 'body' });
  assert.equal(r.ir.facts.endpoint.source, 'reproducer');
  assert.equal(r.ir.facts.payloadClass.source, 'reproducer');
  assert.deepEqual(validateDetectionIR(r.ir), []);
  const again = buildDetectionIR({ finding: FINDING, proof: proof() });
  assert.equal(again.ir.digest, r.ir.digest, 'same evidence, same digest');
  assert.match(r.ir.id, /^det-[0-9a-f]{12}$/);
});

test('IR: no proof means no detection unless explicitly allowed, and an allowed one says so', () => {
  const refused = buildDetectionIR({ finding: FINDING, proof: null });
  assert.equal(refused.ok, false);
  assert.match(refused.reason, /prove it first/);
  const weak = buildDetectionIR({ finding: FINDING, proof: null, allowUnproven: true });
  assert.equal(weak.ok, true);
  assert.equal(weak.ir.grounding, 'static-only');
  assert.ok(weak.ir.confidence < 0.5);
  assert.ok(weak.ir.limitations.some((l) => /not executed/.test(l)));
  const strong = buildDetectionIR({ finding: FINDING, proof: proof() });
  assert.ok(strong.ir.confidence > weak.ir.confidence);
});

test('IR: a candidate-state proof is not exploit-confirmed grounding', () => {
  assert.equal(buildDetectionIR({ finding: FINDING, proof: proof('CANDIDATE') }).ok, false);
  assert.equal(buildDetectionIR({ finding: FINDING, proof: proof('REPRODUCED') }).ir.grounding, 'reproduced');
});

test('IR: nothing is invented — a missing endpoint stays null and is stated; no payload class means no detection', () => {
  const noEndpoint = buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', { payloadClass: 'command-injection' }) });
  assert.equal(noEndpoint.ok, true);
  assert.equal(noEndpoint.ir.endpoint, null);
  assert.ok(noEndpoint.ir.limitations.some((l) => /no endpoint/.test(l)));
  assert.equal(renderDetection(noEndpoint.ir, 'sigma').applicable, false);
  assert.equal(renderDetection(noEndpoint.ir, 'waf').applicable, false);
  const unknownCwe = buildDetectionIR({ finding: { ...FINDING, cwe: 'CWE-1' }, proof: proof('EXPLOIT_CONFIRMED', { method: 'GET', path: '/x' }) });
  assert.equal(unknownCwe.ok, false);
  assert.match(unknownCwe.reason, /no payload class/);
});

test('IR: the finding can supply the route, and says that is where it came from', () => {
  const r = buildDetectionIR({ finding: { ...FINDING, route: 'DELETE /api/items/:id' }, proof: proof('EXPLOIT_CONFIRMED', { payloadClass: 'sql-injection' }) });
  assert.deepEqual(r.ir.endpoint, { method: 'DELETE', path: '/api/items/:id' });
  assert.equal(r.ir.facts.endpoint.source, 'finding');
  assert.equal(parseRouteText('nonsense'), null);
  assert.equal(parseRouteText('POST /a b'), null);
});

test('IR: closed-world — there is no field that can hold an attacker address, domain, hash or user agent', () => {
  const { ir } = buildDetectionIR({ finding: FINDING, proof: proof() });
  for (const bad of ['attackerIp', 'sourceIp', 'domain', 'fileHash', 'malwareHash', 'userAgent', 'ioc']) {
    assert.ok(validateDetectionIR({ ...ir, [bad]: 'x' }).some((e) => e.includes(`unknown IR field: ${bad}`)), bad);
  }
  assert.ok(validateAttackFacts({ ip: '203.0.113.7' }).length);
  assert.ok(validateAttackFacts({ userAgent: 'x' }).length);
  // and nothing generated mentions one
  const everything = JSON.stringify([ir, renderAll(ir)]);
  assert.doesNotMatch(everything, /(?<![\d.])(?!127\.|169\.254\.|10\.|192\.168\.|172\.)\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/, 'no address literal other than the reserved ranges the payload classes describe');
  assert.doesNotMatch(everything, /user-agent|malware|\bioc\b/i);
});

test('IR: a tampered IR fails its own digest', () => {
  const { ir } = buildDetectionIR({ finding: FINDING, proof: proof() });
  assert.ok(validateDetectionIR({ ...ir, confidence: 0.99 }).some((e) => /digest/.test(e)));
});

test('attack facts: hostile values are refused at the reproducer boundary', () => {
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: 'a', lang: 'javascript', files: { 'a.js': 'x' }, run: ['{{NODE}}', 'a.js'], oracle: { type: 'command_execution' } };
  assert.deepEqual(validateReproducer({ ...base, attack: attack() }), []);
  for (const bad of [{ path: '/a"b' }, { path: '/a/../b' }, { path: '/a?x=1' }, { path: 'api' }, { method: 'post' }, { method: 'TRACE' }, { parameter: 'a b', location: 'query' }, { parameter: 'x', location: 'nowhere' }, { payloadClass: 'bogus' }, { sink: 'exec();rm -rf /' }, { parameter: 'only-one', location: undefined }]) {
    const errs = validateReproducer({ ...base, attack: attack(bad) });
    assert.ok(errs.length, `expected a refusal for ${JSON.stringify(bad)}`);
  }
});

test('payload classes: every CWE maps once, exemplars behave, and decoding is tolerant', () => {
  assert.equal(classForCwe('CWE-89'), 'sql-injection');
  assert.equal(classForCwe('cwe-78'), 'command-injection');
  assert.equal(classForCwe('22'), 'path-traversal');
  assert.equal(classForCwe('CWE-99999'), null);
  assert.equal(classForCwe(undefined), null);
  const seen = new Map();
  for (const [n, d] of Object.entries(PAYLOAD_CLASSES)) for (const c of d.cwe) { assert.ok(!seen.has(c), `${c} is claimed by ${seen.get(c)} and ${n}`); seen.set(c, n); }
  for (const n of PAYLOAD_CLASS_NAMES) {
    if (PAYLOAD_CLASSES[n].matcher === 'behavior') continue;
    for (const p of PAYLOAD_CLASSES[n].exemplars.positive) assert.equal(matchesClass(n, p), true, `${n} positive: ${p.slice(0, 30)}`);
    for (const b of PAYLOAD_CLASSES[n].exemplars.benign) assert.equal(matchesClass(n, b), false, `${n} benign: ${b.slice(0, 30)}`);
  }
  assert.equal(matchesClass('path-traversal', '%2e%2e%2f%2e%2e%2fetc%2fpasswd'), true);
  assert.equal(matchesClass('sql-injection', "1%27%20OR%20%271%27%3D%271"), true);
  assert.equal(matchesClass('command-injection', '%E0%A4%A'), false, 'malformed escapes must not throw');
});

test('payload classes: adversarial input cannot stall the matchers (each pattern is linear, not quadratic)', () => {
  // Found by timing: a run of newlines made the command pattern quadratic, and a run of dots made the traversal pattern quadratic.
  const nasty = [' '.repeat(70000), ';'.repeat(70000), '%'.repeat(70000), `'${' or '.repeat(9000)}`, 'a'.repeat(70000), '.'.repeat(70000), `${'../'.repeat(23000)}x`,
    '\n'.repeat(70000), '\r\n'.repeat(35000), '\t'.repeat(70000), '; '.repeat(35000), ';'.repeat(35000) + ' '.repeat(35000), '%20'.repeat(23000), '+'.repeat(70000), '/'.repeat(70000),
    ';' + '\t'.repeat(70000), '..'.repeat(35000), "' or ".repeat(14000), '%2e'.repeat(23000), 'sleep ('.repeat(10000), 'union '.repeat(11000), '['.repeat(70000), 'O:1:"'.repeat(14000)];
  let worst = 0; let where = '';
  for (const n of PAYLOAD_CLASS_NAMES) for (const v of nasty) {
    const t0 = process.hrtime.bigint(); matchesClass(n, v);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (ms > worst) { worst = ms; where = `${n} on ${JSON.stringify(v.slice(0, 12))}x${v.length}`; }
  }
  assert.ok(worst < 400, `slowest match took ${worst.toFixed(0)}ms (${where})`);
});

test('outputs: every format renders for a full IR, and an inapplicable one says why', () => {
  const { ir } = buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', attack({ location: 'query' })) });
  const all = renderAll(ir);
  assert.deepEqual(Object.keys(all).sort(), [...FORMATS].sort());
  for (const f of FORMATS) {
    if (f === 'yara') { assert.equal(all.yara.applicable, false); assert.match(all.yara.reason, /request-shaped/); continue; }
    // the P1 SIEM adapters translate exactly or say why not (see the adapter tests below)
    if (['elastic', 'yaral', 'datadog'].includes(f)) { assert.equal(all[f].applicable === true || typeof all[f].reason === 'string', true, f); continue; }
    assert.equal(all[f].applicable, true, f);
    assert.match(all[f].content, /api\\?\/export/, f);
  }
  const des = buildDetectionIR({ finding: { ...FINDING, cwe: 'CWE-502' }, proof: proof('EXPLOIT_CONFIRMED', attack({ payloadClass: 'deserialization' })) });
  assert.equal(renderDetection(des.ir, 'yara').applicable, true);
  assert.match(renderDetection(des.ir, 'yara').content, /AC ED 00 05/);
  assert.equal(renderDetection(ir, 'nonsense').applicable, false);
});

test('outputs: sigma is valid structure, the WAF suggestion cannot block, and values are escaped for each target', () => {
  const { ir } = buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', attack({ path: '/api/users/:id/export' })) });
  const sigma = renderDetection(ir, 'sigma').content;
  assert.match(sigma, /^title: "/m);
  assert.match(sigma, /condition: selection_request and selection_payload/);
  assert.match(sigma, /cs-uri-stem\|re: "\^\/api\/users\/\[\^\/\]\+\/export\$"/, 'a templated path becomes an anchored regex');
  const waf = renderDetection(ir, 'waf');
  assert.equal(waf.enforcement, 'detect-only');
  assert.match(waf.content, /SUGGESTION ONLY/);
  assert.doesNotMatch(waf.content, /\b(?:deny|drop|block|redirect)\b/i, 'a generated WAF rule must never enforce');
  assert.match(waf.content, /id:9\d{6}/);
  const http = JSON.parse(renderDetection(ir, 'http').content);
  assert.equal(http.mode, 'detect');
  assert.equal(http.request.pathTemplate, '/api/users/:id/export');
  assert.doesNotThrow(() => new RegExp(http.payload.regex, 'i'));
});

test('outputs: body/header locations are not pretended into logs that cannot see them', () => {
  const body = buildDetectionIR({ finding: FINDING, proof: proof() }).ir;
  assert.equal(renderDetection(body, 'kql').applicable, false);
  assert.equal(renderDetection(body, 'cloudwatch').applicable, false);
  const query = buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', attack({ location: 'query' })) }).ir;
  assert.equal(renderDetection(query, 'kql').applicable, true);
  assert.match(renderDetection(query, 'spl').content, /uri_query=/);
});

test('outputs: the auth-bypass class describes behavior, not a payload', () => {
  const { ir } = buildDetectionIR({ finding: { ...FINDING, cwe: 'CWE-306' }, proof: proof('EXPLOIT_CONFIRMED', { method: 'GET', path: '/admin/users', payloadClass: 'auth-bypass' }) });
  assert.equal(classRegex('auth-bypass'), null);
  assert.match(renderDetection(ir, 'sigma').content, /sc-status\|startswith: "2"/);
  assert.match(renderDetection(ir, 'sigma').content, /not filter_credential/);
  assert.match(renderDetection(ir, 'waf').content, /&REQUEST_HEADERS:Authorization "@eq 0"/);
});

test('validation: every class at every parameter location fires on the exploit and stays silent on every lookalike', () => {
  for (const cls of PAYLOAD_CLASS_NAMES) {
    for (const loc of ['query', 'body', 'header', 'path']) {
      if (cls === 'auth-bypass' && loc !== 'query') continue;
      const a = { method: 'POST', path: loc === 'path' ? '/api/files/:name' : '/api/export', payloadClass: cls, ...(cls === 'auth-bypass' ? {} : { parameter: 'name', location: loc }) };
      const { ir } = buildDetectionIR({ finding: { id: 'F', cwe: 'CWE-1' }, proof: proof('EXPLOIT_CONFIRMED', a) });
      const v = validateDetection(ir);
      assert.equal(v.status, 'VALIDATED', `${cls}/${loc}: ${(v.failures || []).join('; ')}`);
      assert.ok(v.counts.positives >= 1 && v.counts.negatives >= 4);
    }
  }
});

test('validation: a rule that fires on everything is caught by the negatives; no endpoint is NOT_VALIDATED, never VALIDATED', () => {
  const { ir } = buildDetectionIR({ finding: FINDING, proof: proof() });
  const saved = PAYLOAD_CLASSES['command-injection'].indicators.slice();
  PAYLOAD_CLASSES['command-injection'].indicators.splice(0, PAYLOAD_CLASSES['command-injection'].indicators.length, /./);
  try {
    const v = validateDetection(ir);
    assert.equal(v.status, 'FAILED');
    assert.ok(v.failures.some((f) => /benign/.test(f)));
  } finally { PAYLOAD_CLASSES['command-injection'].indicators.splice(0, 1, ...saved); }
  const noEp = buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', { payloadClass: 'command-injection' }) }).ir;
  assert.equal(validateDetection(noEp).status, 'NOT_VALIDATED');
});

import { luceneRegex } from '../../src/posture/dnr/outputs.js';

const irFor = (over) => buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', attack(over)) }).ir;

test('luceneRegex: translates the shorthand classes, groups and reserved characters, and refuses what Lucene cannot say', () => {
  assert.equal(luceneRegex('a\\d+b'), 'a[0-9]+b');
  assert.equal(luceneRegex('(?:x|y)\\s*z'), '(x|y)[ \\t\\n\\r]*z');
  assert.equal(luceneRegex('[\\d.]'), '[0-9.]');
  assert.equal(luceneRegex('a&b~c<d>e@f"g#h'), 'a\\&b\\~c\\<d\\>e\\@f\\"g\\#h');
  assert.equal(luceneRegex('a.*?b'), 'a.*b', 'lazy becomes greedy, which is exact for a yes/no match');
  for (const bad of ['^a', 'a$', '\\bword', '(?=x)y', '(?<n>a)', '(a)\\1', '[abc', '\\p{L}']) assert.equal(luceneRegex(bad), null, bad);
});

test('elastic: a structurally exact query, or a stated reason; the proof\'s own class decides which', () => {
  const auth = irFor({ payloadClass: 'auth-bypass', location: 'header', path: '/api/users/:id/export' });
  const e = renderDetection(auth, 'elastic');
  assert.equal(e.applicable, true);
  const q = JSON.parse(e.content).query.bool;
  assert.deepEqual(q.filter[0], { term: { 'http.request.method': 'POST' } });
  assert.deepEqual(q.filter[1], { regexp: { 'url.path': { value: '/api/users/[^/]+/export' } } });
  assert.deepEqual(q.filter[2], { range: { 'http.response.status_code': { gte: 200, lte: 299 } } });
  assert.deepEqual(q.must_not, [{ exists: { field: 'http.request.headers.authorization' } }]);
  const sql = renderDetection(irFor({ location: 'query' }), 'elastic');
  assert.equal(sql.applicable, false); assert.match(sql.reason, /Lucene cannot express exactly/);
  const body = renderDetection(irFor({ payloadClass: 'buffer-overflow', location: 'body' }), 'elastic');
  assert.equal(body.applicable, true); assert.match(JSON.parse(body.content).query.bool.filter[2].regexp['http.request.body.content'].value, /^\.\*\(\.\{512,\}\)\.\*$/);
  assert.equal(JSON.parse(body.content).query.bool.filter[2].regexp['http.request.body.content'].case_insensitive, true);
  assert.equal(renderDetection(irFor({ payloadClass: 'buffer-overflow', location: 'header' }), 'elastic').applicable, false);
});

test('yaral and datadog: only what the target can say exactly', () => {
  const big = irFor({ payloadClass: 'buffer-overflow', location: 'query' });
  const y = renderDetection(big, 'yaral');
  assert.equal(y.applicable, true); assert.match(y.content, /^rule as_[0-9a-f]{12} \{/); assert.match(y.content, /re\.regex\(\$e\.target\.url, `\(\?i\)\.\{512,\}`\)/);
  assert.equal(renderDetection(irFor({ location: 'query' }), 'yaral').applicable, false, 'anchored indicators would mean something else against a whole URL');
  assert.match(renderDetection(irFor({ location: 'query' }), 'yaral').reason, /anchored/);
  assert.equal(renderDetection(irFor({ payloadClass: 'auth-bypass', location: 'header' }), 'yaral').applicable, false);
  assert.equal(renderDetection(irFor({ payloadClass: 'buffer-overflow', location: 'body' }), 'yaral').applicable, false);
  const auth = irFor({ payloadClass: 'auth-bypass', location: 'header', path: '/api/users/:id/export' });
  const d = JSON.parse(renderDetection(auth, 'datadog').content);
  assert.equal(d.isEnabled, false, 'generated rules are never enabled');
  assert.equal(d.queries[0].query, '@http.method:POST @http.url_details.path:/api/users/*/export @http.status_code:[200 TO 299] -@http.request.headers.authorization:*');
  assert.match(renderDetection(irFor({ location: 'query' }), 'datadog').reason, /no regular expressions/);
});

test('a path that could break out of a rule never reaches a renderer: the IR builder refuses it', () => {
  const r = buildDetectionIR({ finding: FINDING, proof: proof('EXPLOIT_CONFIRMED', attack({ payloadClass: 'auth-bypass', location: 'header', path: '/api/a b' })) });
  assert.equal(r.ir ?? null, null);
});
