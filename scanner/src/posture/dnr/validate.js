// Detection validation (PRD 7, requirement 6): before a detection is allowed to be "enabled", prove it behaves.
//   positive exploit event  -> the detection fires
//   negative lookalike      -> the detection does not fire
// Events are synthesized from the IR's own proven facts (endpoint, parameter, class) and the class's exemplar payloads, then
// pushed through the SAME evaluator the hunt uses, so a rule that validates is the rule that searches the logs. The negatives
// are the point: a rule that fires on everything passes every positive test.
import { PAYLOAD_CLASSES } from './payload-classes.js';
import { evaluateEvent } from './matchers.js';
import { classRegex } from './outputs.js';

const PROBE = 'probe';

function eventFor(ir, { method, path, values, extraParam = null, status = 200, authPresent = null }) {
  const p = ir.parameter;
  const bag = {};
  const ev = { time: '2024-01-01T00:00:00.000Z', method, path, query: {}, bodyParams: {}, headers: {}, status, authPresent };
  const put = (loc, name, vals) => {
    if (loc === 'query') ev.query[name] = vals;
    else if (loc === 'body') ev.bodyParams[name] = vals;
    else if (loc === 'header' || loc === 'cookie') ev.headers[name.toLowerCase()] = vals[0];
  };
  void bag;
  if (values) {
    if (p?.location === 'path') {
      const t = ir.endpoint.path.split('/').map((seg) => (seg === `:${p.name}` || seg === `{${p.name}}` ? encodeURIComponent(values[0]) : (/^(?::\w+|\{\w+\})$/.test(seg) ? 'x' : seg)));
      if (path === ir.endpoint.path.replace(/(:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})/g, '42')) ev.path = t.join('/');
    } else if (p) put(p.location, extraParam ?? p.name, values);
    else put('query', extraParam ?? PROBE, values);
  }
  // a channel the IR does not use is "present and empty", not "not logged": the event models a log that records everything
  return ev;
}

export function validateDetection(ir) {
  const def = PAYLOAD_CLASSES[ir.payloadClass];
  const cases = [];
  const render = { regexCompiles: true };
  try { const rx = classRegex(ir.payloadClass); if (rx) new RegExp(rx, 'i'); } catch { render.regexCompiles = false; }
  if (!ir.endpoint) return { schema: 'agentic-security/detection-validation', version: 1, detectionId: ir.id, status: 'NOT_VALIDATED', reason: 'no endpoint is known, so there is no request to synthesize', cases, render, counts: { positives: 0, negatives: 0, passed: 0, failed: 0 } };
  const concretePath = ir.endpoint.path.replace(/(:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})/g, '42');
  const { method } = ir.endpoint;
  const add = (kind, name, ev) => { const r = evaluateEvent(ir, ev); cases.push({ kind, name, expected: kind === 'positive', fired: r.match, undecidable: r.undecidable, ok: kind === 'positive' ? r.match : !r.match }); };

  if (ir.payloadClass === 'auth-bypass') {
    add('positive', 'success with no credential', eventFor(ir, { method, path: concretePath, status: 200, authPresent: false }));
    add('negative', 'success with a credential', eventFor(ir, { method, path: concretePath, status: 200, authPresent: true }));
    add('negative', 'refusal without a credential (401)', eventFor(ir, { method, path: concretePath, status: 401, authPresent: false }));
    add('negative', 'refusal without a credential (403)', eventFor(ir, { method, path: concretePath, status: 403, authPresent: false }));
    add('negative', 'same request on another path', eventFor(ir, { method, path: '/other/unrelated', status: 200, authPresent: false }));
  } else {
    for (const [i, v] of def.exemplars.positive.entries()) add('positive', `exploit payload #${i + 1}`, eventFor(ir, { method, path: concretePath, values: [v] }));
    for (const [i, v] of def.exemplars.benign.entries()) add('negative', `benign value #${i + 1} on the same endpoint`, eventFor(ir, { method, path: concretePath, values: [v] }));
    const exploit = [def.exemplars.positive[0]];
    const otherMethod = method === 'GET' ? 'POST' : 'GET';
    add('negative', `exploit payload with another method (${otherMethod})`, eventFor(ir, { method: otherMethod, path: concretePath, values: exploit }));
    add('negative', 'exploit payload on another path', eventFor(ir, { method, path: '/other/unrelated', values: exploit }));
    add('negative', 'same endpoint, no parameter at all', eventFor(ir, { method, path: concretePath }));
    if (ir.parameter && ir.parameter.location !== 'path') add('negative', 'exploit payload in an unrelated parameter', eventFor(ir, { method, path: concretePath, values: exploit, extraParam: 'unrelated_field' }));
  }
  const positives = cases.filter((c) => c.kind === 'positive'); const negatives = cases.filter((c) => c.kind === 'negative');
  const failed = cases.filter((c) => !c.ok);
  const status = failed.length === 0 && positives.length && negatives.length && render.regexCompiles ? 'VALIDATED' : 'FAILED';
  return { schema: 'agentic-security/detection-validation', version: 1, detectionId: ir.id, status, cases, render, counts: { positives: positives.length, negatives: negatives.length, passed: cases.length - failed.length, failed: failed.length }, failures: failed.map((c) => c.name) };
}
