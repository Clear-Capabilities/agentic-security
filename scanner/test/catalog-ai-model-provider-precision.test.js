// Precision regression guard for Sub-project H's AC-07 closure
// (docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-h-ac07.md).
//
// A task review found the first cut of `js-anthropic-messages-create`/
// `js-openai-responses-create` matched ordinary `db.messages.create()`/
// `prisma.messages.create()` (Sequelize/Prisma's idiomatic row-insert
// shape) — `receiver` alone is checked via `_receiverAllowed`'s `.some()`
// over the WHOLE member chain, so any object with a `.messages`/
// `.responses` property satisfied it. Reproduced live against a real scan:
// a 7-line Express app doing `db.messages.create({...req.body})` produced
// a real "Regulated Data to AI Model Provider (Anthropic messages.create)"
// finding — a false claim about where the user's data actually went, the
// worst-direction error for a privacy/compliance feature. Fixed by adding
// `receiverBase` to both entries. This file pins both directions so the
// fix can never silently regress: the real AI-provider shapes still match,
// and the ordinary-ORM shapes that used to false-positive no longer do.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../src/ir/parser-js.js';
import { matchSinkOrSanitizer } from '../src/dataflow/catalog.js';

function calleeOfFirstStatementCall(src) {
  const ir = parseJsFile('a.js', `function h() { ${src} }`);
  const fn = ir.functions[0];
  const callNode = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call');
  assert.ok(callNode, `no statement-call CFG node found for: ${src}`);
  return callNode.callee;
}

function idsMatching(src) {
  const callee = calleeOfFirstStatementCall(src);
  const hits = matchSinkOrSanitizer(callee, 'a.js', undefined) ?? [];
  return hits.map((h) => h.id);
}

test('AC-07 precision: real AI-provider call shapes still match after the receiverBase fix', () => {
  assert.ok(idsMatching('anthropic.messages.create(x);').includes('js-anthropic-messages-create'));
  assert.ok(idsMatching('client.messages.create(x);').includes('js-anthropic-messages-create'));
  assert.ok(idsMatching('claude.messages.create(x);').includes('js-anthropic-messages-create'));
  assert.ok(idsMatching('openai.responses.create(x);').includes('js-openai-responses-create'));
  assert.ok(idsMatching('oai.responses.create(x);').includes('js-openai-responses-create'));
});

test('AC-07 precision: ordinary ORM/queue calls that merely SHARE a property name no longer false-positive as AI-provider sinks', () => {
  for (const src of [
    'db.messages.create(x);',
    'prisma.messages.create(x);',
    'queue.messages.create(x);',
    'sequelize.models.responses.create(x);',
    'this.responses.create(x);',
  ]) {
    const ids = idsMatching(src);
    assert.ok(
      !ids.includes('js-anthropic-messages-create') && !ids.includes('js-openai-responses-create'),
      `${src} must not match an AI-model-provider entry — matched: ${JSON.stringify(ids)}`,
    );
  }
});
