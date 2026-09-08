// Completeness guard for SUPPLY_CHAIN_ABSENCE_TYPES (S4, adversarial
// premortem third pass on the --assurance strict fix, 2026-09-07).
//
// engine.js's supply-chain provenance-stamping loop classifies every
// non-vulnerable_dep supply-chain finding type into one of two buckets:
// SUPPLY_CHAIN_ABSENCE_TYPES (unpinned_dep/no_lockfile — genuinely no origin
// commit exists) or the "not yet wired" fallback (cdn_no_integrity/
// dynamic_require — a real source location, just not resolved today). A
// third premortem pass on this same fix flagged that nothing catches a
// FUTURE type added to one of engine.js's SCA detection loops without also
// being added to SUPPLY_CHAIN_ABSENCE_TYPES — it would silently fall into
// the fallback bucket and tell a user a genuinely-permanent limitation is an
// ordinary, fixable coverage gap, the exact wrong-direction error this
// module's own history (the module-artifact-liveness.test.js sibling check,
// same session) exists to catch mechanically rather than by luck.
//
// This does NOT judge which bucket is correct for a NEW type — that is a
// human call, same as COMPLIANCE_FAMILY_GAPS/MODULE_ARTIFACTS elsewhere in
// this codebase. It only refuses to let a new supply-chain finding type
// exist with NO deliberate classification at all.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { _internals } from '../src/engine.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_JS = path.join(HERE, '..', 'src', 'engine.js');

// Location-based types: a genuine file:line a future resolver update could
// walk, deliberately reviewed and excluded from SUPPLY_CHAIN_ABSENCE_TYPES —
// see engine.js's own comment on the provenance-stamping loop for why.
const KNOWN_LOCATION_BASED_TYPES = new Set(['cdn_no_integrity', 'dynamic_require']);
// Handled by its own, separate resolver path (resolveDirectSCAOrigin /
// resolveTransitiveSCAOrigin) — not subject to this absence/location split
// at all, so it is neither a member of SUPPLY_CHAIN_ABSENCE_TYPES nor of
// KNOWN_LOCATION_BASED_TYPES above.
const HANDLED_SEPARATELY = new Set(['vulnerable_dep']);

// Every real supply-chain finding in this file is constructed exactly as
// `results.push({type:'x', ...})` (or `results.push({ type: 'x', ...` for
// vulnerable_dep) — confirmed against the current source, not assumed.
// engine.js's lines are extremely long (many unrelated statements packed
// per physical line), so a same-LINE "also has severity:" heuristic was
// tried first and produced false positives: unrelated taint-chain path-step
// tags (`{type:'sanitizer'|'sink', label:..., line:..., snippet:...}`,
// which never carry a severity field of their own) coincidentally share a
// physical line with a distant, unrelated finding object's `severity:`.
// Anchoring on the `results.push({` call site itself is precise because
// every one of the 5 known types (4 classified here + vulnerable_dep,
// handled separately) is built this exact way, and no unrelated `type:` tag
// in this file is.
function findSupplyChainTypes(src) {
  const types = new Set();
  const re = /results\.push\(\{\s*type:\s*['"]([a-z_]+)['"]/g;
  let m;
  while ((m = re.exec(src))) types.add(m[1]);
  return types;
}

test('every supply-chain finding type engine.js produces is deliberately classified as absence-based or location-based', () => {
  const src = fs.readFileSync(ENGINE_JS, 'utf8');
  const found = findSupplyChainTypes(src);
  const unclassified = [...found].filter((t) =>
    !HANDLED_SEPARATELY.has(t) &&
    !_internals.SUPPLY_CHAIN_ABSENCE_TYPES.has(t) &&
    !KNOWN_LOCATION_BASED_TYPES.has(t));
  assert.deepEqual(unclassified, [],
    `supply-chain finding type(s) found in engine.js with no deliberate absence/location classification: ` +
    `${unclassified.join(', ')} — add each to SUPPLY_CHAIN_ABSENCE_TYPES (engine.js) if it describes an ` +
    `absent declaration with no origin commit, or to KNOWN_LOCATION_BASED_TYPES (this test) if it carries a ` +
    `real file:line a future resolver could walk.`);
});

test('the completeness guard itself finds the known types (sanity — proves the line-scan is not silently matching nothing)', () => {
  const src = fs.readFileSync(ENGINE_JS, 'utf8');
  const found = findSupplyChainTypes(src);
  for (const t of ['unpinned_dep', 'no_lockfile', 'cdn_no_integrity', 'dynamic_require']) {
    assert.ok(found.has(t), `expected to find a '${t}' supply-chain finding type in engine.js, found none — the scan regex may have drifted from the real code shape`);
  }
});

test('SUPPLY_CHAIN_ABSENCE_TYPES and KNOWN_LOCATION_BASED_TYPES never overlap (a type cannot be both permanent and resolvable)', () => {
  const overlap = [..._internals.SUPPLY_CHAIN_ABSENCE_TYPES].filter((t) => KNOWN_LOCATION_BASED_TYPES.has(t));
  assert.deepEqual(overlap, [], `type(s) claimed as both absence-based and location-based: ${overlap.join(', ')}`);
});
