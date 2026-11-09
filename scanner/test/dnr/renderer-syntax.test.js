// GA-10 §1 and §4 (0.195.31): every rendered detection parses under the grammar of what it claims to be, for every payload class
// at every parameter location; each checker rejects a known-bad sample (so a passing check means something); the renderers decline
// what their target cannot express instead of inventing a field; and the per-format assurance statement matches the contract page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDetectionIR } from '../../src/posture/dnr/detection-ir.js';
import { PAYLOAD_CLASS_NAMES } from '../../src/posture/dnr/payload-classes.js';
import { renderAll, renderDetection, FORMATS, FORMAT_ASSURANCE } from '../../src/posture/dnr/outputs.js';
import { checkRendered, checkSigma, checkModsecChain, checkYara, checkYaral, checkSpl, checkKql, checkCloudwatch, checkJsonShape, SYNTAX_TARGETS } from '../../src/posture/dnr/syntax.js';
import { readPage, fieldsUnder } from '../helpers/contract-page.js';

const FINDING = { id: 'F1', stableId: 'F1', cwe: 'CWE-78', file: 'app.js', line: 9 };
const LOCATIONS = ['query', 'body', 'header', 'cookie'];
const irFor = (payloadClass, location, path = '/api/export') => {
  const a = payloadClass === 'auth-bypass' ? { method: 'GET', path, payloadClass } : { method: 'POST', path, parameter: 'filename', location, payloadClass, sink: 'exec()' };
  const r = buildDetectionIR({ finding: FINDING, proof: { state: 'EXPLOIT_CONFIRMED', recordDigest: 'abc123', oracle: 'command_execution', reproducer: { attack: a } } });
  assert.equal(r.ok, true, `${payloadClass}/${location}: ${r.reason}`);
  return r.ir;
};

test('every applicable rendering of every class at every location, on a literal and a templated path, passes its format\'s syntax check', () => {
  let applicable = 0; let declined = 0;
  for (const cls of PAYLOAD_CLASS_NAMES) for (const loc of LOCATIONS) for (const path of ['/api/export', '/api/users/:id/export']) {
    const ir = irFor(cls, loc, path);
    const all = renderAll(ir);
    for (const format of FORMATS) {
      const r = all[format];
      if (!r.applicable) { declined++; assert.ok(typeof r.reason === 'string' && r.reason.length > 20, `${format} ${cls}/${loc}: a declined format states why`); continue; }
      applicable++;
      const c = checkRendered(format, r.content);
      assert.ok(c.ok, `${format} ${cls}/${loc} ${path}: ${c.errors.join('; ')}\n${r.content}`);
      assert.equal(c.target, SYNTAX_TARGETS[format]);
    }
  }
  assert.ok(applicable > 100 && declined > 30, `${applicable} applicable, ${declined} declined`);
});

test('the renderers decline what the target cannot see, instead of inventing a field or widening the rule', () => {
  const body = irFor('command-injection', 'body'); const header = irFor('command-injection', 'header'); const auth = irFor('auth-bypass', 'query');
  for (const ir of [body, header]) { const s = renderDetection(ir, 'sigma'); assert.equal(s.applicable, false); assert.match(s.reason, /records no request (body|header)/); }
  assert.equal(renderDetection(irFor('command-injection', 'cookie'), 'sigma').applicable, true, 'the cookie header is a webserver field');
  const kql = renderDetection(auth, 'kql'); assert.equal(kql.applicable, false); assert.match(kql.reason, /no request headers/);
  const cw = renderDetection(auth, 'cloudwatch'); assert.equal(cw.applicable, false); assert.match(cw.reason, /no request headers/);
  const sigma = renderDetection(irFor('command-injection', 'query'), 'sigma').content;
  assert.doesNotMatch(sigma, /cwe\./, 'no invented tag namespace');
  assert.match(sigma, /^date: "\d{4}-\d{2}-\d{2}"$/m);
  assert.match(sigma, /CWE-78/, 'the weakness is named in the description instead');
  const waf = renderDetection(body, 'waf').content;
  const lines = waf.split('\n').filter((l) => l.trim().startsWith('SecRule'));
  assert.match(lines[0], /"id:9\d{6},phase:2,pass,log,auditlog,msg:'[^']*',severity:'CRITICAL',tag:'cwe-78',chain"$/, 'metadata on the chain starter');
  assert.ok(lines.slice(1).every((l) => !/msg:|severity:|tag:|auditlog|\blog\b/.test(l)), 'no metadata on a chained rule');
});

test('each checker rejects a known-bad sample, so a pass is a decision', () => {
  const bad = (r, re) => { assert.equal(r.ok, false); assert.ok(r.errors.some((e) => re.test(e)), r.errors.join('; ')); };
  bad(checkSigma('title: x\n'), /missing required key/);
  bad(checkSigma('title: "t"\nid: "not-a-uuid"\nstatus: experimental\ndescription: "d"\nlogsource:\n  category: webserver\ndetection:\n  selection_request:\n    request-body|re: "x"\n  condition: selection_request and selection_payload\nlevel: high\n'), /not a field of the webserver log source/);
  bad(checkSigma('title: "t"\nid: "12345678-1234-1234-1234-123456789abc"\nstatus: experimental\ndescription: "d"\nlogsource:\n  category: webserver\ndetection:\n  selection_request:\n    cs-method: "GET"\n  condition: selection_request and selection_payload\nlevel: high\n'), /not a selection/);
  bad(checkSigma('title: "t"\nid: "12345678-1234-1234-1234-123456789abc"\nstatus: experimental\ndescription: "d"\nlogsource:\n  category: webserver\ndetection:\n  selection_request:\n    cs-method|fuzzy: "GET"\n  condition: selection_request\nlevel: high\n'), /unknown modifier/);
  bad(checkModsecChain('SecRule REQUEST_METHOD "@streq POST" "id:9000001,phase:2,pass,chain"\n  SecRule ARGS "@rx x" "log,msg:\'m\'"\n'), /metadata actions belong on the chain starter/);
  bad(checkModsecChain('SecRule REQUEST_METHOD "@streq POST" "id:9000001,phase:2,deny"\n'), /must be pass/);
  bad(checkModsecChain('SecRule REQUEST_METHOD "@streq POST" "id:9000001,phase:2,pass,chain"\n'), /last rule still says chain/);
  bad(checkModsecChain('SecRule REQUEST_METHOD "@streq POST" "id:1,phase:2,pass"\n'), /outside the generated range/);
  bad(checkYara('rule r {\n  meta:\n    description = "a\\u0000b"\n  strings:\n    $a = "x"\n  condition:\n    any of them\n}\n'), /escapes/);
  bad(checkYara('rule r {\n  strings:\n    $a = "x"\n}\n'), /no condition/);
  bad(checkYaral('rule r {\n  meta:\n    author = "a"\n  events:\n    $e.metadata.event_type = "NETWORK_HTTP"\n    re.regex($e.target.url, `a`b`)\n  condition:\n    $e\n}\n'), /outside the subset grammar/);
  bad(checkSpl('method=GET\n| regex uri_query="(unterminated"\n'), /starting with index=|not a regular expression/);
  bad(checkKql('W3CIISLog\n| where csAuthorization == "x"\n'), /not a column of W3CIISLog/);
  bad(checkKql('SomeOtherTable\n| where csMethod == "GET"\n'), /known table/);
  bad(checkCloudwatch('fields @message\n| filter @message like /a/b/\n'), /unescaped/);
  bad(checkJsonShape('http', '{"schema":"agentic-security/http-detection","version":1,"mode":"block","request":{"method":"GET","pathTemplate":"/"}}'), /mode must be detect/);
  bad(checkJsonShape('log-query', '{"schema":"agentic-security/structured-log-query","version":1,"where":[{"field":"a","op":"like","value":"x"}]}'), /unknown op/);
  bad(checkJsonShape('elastic', '{"query":{"bool":{"filter":[{"regexp":{"url.query":{"value":"\\\\d+"}}}]}}}'), /Lucene has no/);
  bad(checkJsonShape('datadog', '{"name":"n","type":"log_detection","isEnabled":true,"message":"m","tags":[],"queries":[{"query":"q"}],"cases":[{"condition":"a > 0"}],"options":{}}'), /disabled until reviewed/);
  assert.equal(checkRendered('nope', 'x').ok, false);
});

test('the assurance statement per format is the one the contract page carries, and claims no official tool and no product', () => {
  const page = readPage('docs/reference/dnr-contract.md');
  assert.deepEqual([...fieldsUnder(page, 'Format assurance')].sort(), [...FORMATS].sort(), 'every format has a row');
  for (const f of FORMATS) {
    const a = FORMAT_ASSURANCE[f];
    assert.equal(a.generated, true); assert.equal(a.product, false);
    assert.ok(['subset-grammar', 'vendored-schema'].includes(a.syntax), f);
    assert.equal(a.syntax, SYNTAX_TARGETS[f].check, `${f}: the assurance level is the checker's own kind`);
    const row = page.split('\n').find((l) => l.startsWith(`| \`${f}\` |`));
    assert.ok(row, `${f} row`);
    assert.ok(row.includes(a.syntax) && row.includes(a.samples ? 'yes' : 'no'), `${f}: page row matches ${JSON.stringify(a)}: ${row}`);
  }
  assert.deepEqual(Object.entries(FORMAT_ASSURANCE).filter(([, a]) => a.samples).map(([f]) => f), ['http', 'log-query'], 'only the two formats with an interpreter are sample-tested');
});
