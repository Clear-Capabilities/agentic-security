// FR-LOGIC-6 flow narration tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateNarration, _internals } from '../src/posture/flow-narration.js';

test('annotateNarration sets f.narration for high+ findings (template fallback)', async () => {
  const findings = [
    { family: 'sql-injection', severity: 'critical', file: 'app.js', line: 10 },
    { family: 'ssrf',          severity: 'high',     file: 'app.js', line: 20 },
  ];
  await annotateNarration(findings);
  assert.ok(typeof findings[0].narration === 'string');
  assert.ok(findings[0].narration.includes('UNION'));
  assert.ok(typeof findings[1].narration === 'string');
});

test('annotateNarration skips low/medium severity', async () => {
  const f = [{ family: 'sql-injection', severity: 'low' }];
  await annotateNarration(f);
  assert.equal(f[0].narration, null);
});

test('annotateNarration falls back to generic template for unknown family', async () => {
  const f = [{ family: 'novel-family', severity: 'critical', file: 'x', line: 1 }];
  await annotateNarration(f);
  assert.ok(typeof f[0].narration === 'string');
  assert.ok(f[0].narration.length > 30);
});

test('annotateNarration does not throw on garbage input', async () => {
  await assert.doesNotReject(async () => annotateNarration(null));
  await assert.doesNotReject(async () => annotateNarration([null, {}, undefined]));
});

test('templates cover the load-bearing CWE families', () => {
  for (const fam of ['sql-injection', 'command-injection', 'xss', 'ssrf', 'path-traversal', 'code-injection', 'csrf', 'open-redirect', 'insecure-deserialization', 'xxe']) {
    assert.ok(typeof _internals.TEMPLATES[fam] === 'function', `missing narration template for ${fam}`);
  }
});

test('no narration emits a broken location when the line is missing', () => {
  // Templates that reference a location must not render ":undefined" / ":?".
  for (const fam of Object.keys(_internals.TEMPLATES)) {
    const text = _internals.TEMPLATES[fam]({ family: fam, file: 'app.js' }); // no line
    assert.doesNotMatch(text, /:undefined|:\?/, `${fam} template emits a broken location`);
  }
  // Generic fallback with no file/line at all stays clean.
  assert.doesNotMatch(_internals._renderTemplate({ family: 'novel', severity: 'high' }), /:undefined|:\?|<endpoint>/);
});
