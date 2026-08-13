// PRD R4a (docs/DETECTION_GAP_REMEDIATION_PRD.md): catalog.js's own header
// documents that `match.callee` supports two shapes — 'name' (bare, matched
// by last segment) and 'name.foo' (matched by full path) — but every lookup
// path (matchSource's call-shaped source path, matchSinkOrSanitizer) reduced
// every callee to its last segment unconditionally. Any entry registered
// under a full dotted key (catalog-expanded.js's `san()` helper builds many:
// 'Encode.forHtml', 'pg.escapeLiteral', 'filepath.Clean', ...) could
// therefore never be retrieved by either lookup function.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CATALOG, matchSinkOrSanitizer, matchSource } from '../src/dataflow/catalog.js';

test('a sanitizer registered under a full dotted callee key is retrievable by matchSinkOrSanitizer', () => {
  const dotted = CATALOG.find((e) => e.kind === 'sanitizer' && typeof e.match?.callee === 'string' && e.match.callee.includes('.'));
  assert.ok(dotted, 'expected at least one catalog entry with a dotted match.callee — if this fails the catalog changed shape, re-derive the fixture');
  const [obj, prop] = dotted.match.callee.split('.');
  const hits = matchSinkOrSanitizer({ kind: 'member', object: { kind: 'ident', name: obj }, prop }, `a.${dotted.language === 'js' ? 'js' : dotted.language}`);
  assert.ok(hits && hits.some((h) => h.id === dotted.id), `expected matchSinkOrSanitizer to retrieve ${dotted.id} (callee "${dotted.match.callee}") via a member call {object:'${obj}', prop:'${prop}'}, got: ${JSON.stringify(hits)}`);
});

test('matchSinkOrSanitizer still resolves an ordinary bare-name callee (no regression)', () => {
  const bare = CATALOG.find((e) => e.kind === 'sanitizer' && typeof e.match?.callee === 'string' && !e.match.callee.includes('.'));
  assert.ok(bare, 'expected at least one bare-callee sanitizer entry');
  const hits = matchSinkOrSanitizer({ kind: 'ident', name: bare.match.callee }, `a.${bare.language === 'js' ? 'js' : bare.language}`);
  assert.ok(hits && hits.some((h) => h.id === bare.id), `expected matchSinkOrSanitizer to still retrieve ${bare.id} via its bare callee`);
});

test('a call-shaped source registered under a full dotted callee key is retrievable by matchSource', () => {
  const dottedSource = CATALOG.find((e) => e.kind === 'source' && e.match?.type === 'call' && typeof e.match?.callee === 'string' && e.match.callee.includes('.'));
  if (!dottedSource) return; // no dotted-callee source in the catalog today — nothing to regress
  const [obj, prop] = dottedSource.match.callee.split('.');
  const expr = { kind: 'call', callee: { kind: 'member', object: { kind: 'ident', name: obj }, prop } };
  const hit = matchSource(expr, `a.${dottedSource.language === 'js' ? 'js' : dottedSource.language}`);
  assert.ok(hit, `expected matchSource to retrieve a dotted-callee source (callee "${dottedSource.match.callee}")`);
});
