// E0-03: the existing-behaviour contract. These tests fail when a public surface changes by accident.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { REPO, cleanup } from './helpers.js';
import { SNAPSHOT_REL, captureContract, compareContracts, diffShapes, loadSnapshot, mergeShapes, shapeOf, writeSnapshot } from '../../../scripts/engineering-excellence/contract.mjs';

let live;
const capture = async () => (live ||= await captureContract(REPO));

// ---- shapes ------------------------------------------------------------------------------------------------------------------

test('a shape records key names and value types, merges array elements, and marks keys missing on one side as optional', () => {
  assert.deepEqual(shapeOf({ b: 1, a: 'x', c: null, d: [1, 2] }), { object: { a: 'string', b: 'number', c: 'null', d: { array: 'number' } } });
  assert.deepEqual(shapeOf([]), { array: 'empty' });
  const merged = shapeOf([{ id: 1, extra: true }, { id: 2 }]);
  assert.deepEqual(merged, { array: { object: { extra: { optional: 'boolean' }, id: 'number' } } });
  assert.equal(mergeShapes('string', 'null'), 'null|string');
});

test('removing a key or changing a type is breaking; adding a key or widening a type is additive', () => {
  const before = shapeOf({ id: 'a', severity: 'high', line: 1 });
  const removed = diffShapes(before, shapeOf({ id: 'a', severity: 'high' }));
  assert.deepEqual(removed.map((d) => [d.path, d.kind]), [['$.line', 'removed']]);
  const retyped = diffShapes(before, shapeOf({ id: 'a', severity: 5, line: 1 }));
  assert.deepEqual(retyped.map((d) => [d.path, d.kind]), [['$.severity', 'type-changed']]);
  const added = diffShapes(before, shapeOf({ id: 'a', severity: 'high', line: 1, extra: [] }));
  assert.deepEqual(added.map((d) => [d.path, d.kind]), [['$.extra', 'added']]);
  const widened = diffShapes(shapeOf({ x: 'a' }), shapeOf({ x: null }));
  assert.equal(widened[0].kind, 'type-changed', 'string became null: the old type is gone');
  assert.equal(diffShapes({ object: { x: 'string' } }, { object: { x: 'null|string' } })[0].kind, 'added');
});

// ---- the committed contract ---------------------------------------------------------------------------------------------------

test('the committed snapshot exists and covers every public surface the program depends on', () => {
  const snap = loadSnapshot(REPO);
  assert.ok(snap, `${SNAPSHOT_REL} is missing; run node scripts/engineering-excellence/contract.mjs --update`);
  assert.equal(snap.schemaVersion, 1);
  for (const k of ['scanJson', 'findingsRequired', 'scanHealth', 'assuranceModes', 'cliExitCodes', 'mcpTools', 'verifyFix', 'findingProvenance', 'evidenceBundle', 'oscal']) assert.ok(snap.surfaces[k], `surface ${k}`);
});

test('the live behaviour has not broken the committed contract', async () => {
  const snap = loadSnapshot(REPO);
  const { breaking } = compareContracts(snap, await capture());
  assert.deepEqual(breaking, [], `a public contract changed. If the change is intended and versioned, run node scripts/engineering-excellence/contract.mjs --update --accept-breaking "<reason>"\n${JSON.stringify(breaking, null, 1)}`);
});

test('the safety semantics other tools rely on are pinned: strict assurance fails a broken scan, advisory and standard do not', async () => {
  const s = (await capture()).surfaces;
  assert.deepEqual(s.assuranceModes.modes, ['advisory', 'standard', 'strict']);
  assert.equal(s.assuranceModes.default, 'standard');
  const ok = s.assuranceModes.okByModeAndCase;
  assert.equal(ok.strict.clean, true);
  assert.equal(ok.strict.analyzerFailed, false, 'a failed analyzer must fail strict assurance');
  assert.equal(ok.strict.analyzerTimedOut, false, 'a timed-out analyzer must fail strict assurance');
  for (const mode of ['advisory', 'standard']) for (const c of Object.keys(ok[mode])) assert.equal(ok[mode][c], true, `${mode}/${c}`);
  assert.equal(s.scanHealth.statusWhenClean, 'complete');
  assert.notEqual(s.scanHealth.statusWhenAFileTimedOut, 'complete', 'a timed-out file is never a complete scan');
});

test('scan and ci --assurance strict keep distinct exit codes for clean and vulnerable fixtures', async () => {
  const c = (await capture()).surfaces.cliExitCodes;
  assert.equal(c.ciStrictClean, 0);
  assert.equal(c.ciStrictVulnerable, 1);
  assert.notEqual(c.scanClean, c.scanVulnerable);
  assert.ok(c.scanVulnerable > c.scanClean, 'findings raise the scan exit code');
});

test('signed evidence verifies when intact and is rejected when a field is edited', async () => {
  const e = (await capture()).surfaces.evidenceBundle;
  assert.equal(e.verifiesWhenIntact, true);
  assert.equal(e.rejectsWhenTampered, true);
});

test('every MCP tool is captured with its required inputs, and the write tools are still guarded', async () => {
  const tools = (await capture()).surfaces.mcpTools;
  const by = Object.fromEntries(tools.map((t) => [t.name, t]));
  for (const name of ['scan_diff', 'verify_fix', 'apply_fix', 'synthesize_fix', 'apply_sca_upgrade']) assert.ok(by[name], name);
  assert.ok(tools.length >= 23);
  assert.ok('confirm' in by.apply_fix.properties || 'dry_run' in by.apply_fix.properties, 'apply_fix keeps a confirmation or dry-run input');
});

// ---- the comparison and the update policy -------------------------------------------------------------------------------------

test('an accidental change to a public shape is reported as breaking', async () => {
  const snap = structuredClone(loadSnapshot(REPO));
  const now = structuredClone(await capture());
  // simulate three accidents: a finding field is dropped, a vocabulary entry vanishes, a tool is removed
  const findings = now.surfaces.scanJson.shape.object.findings;
  const target = findings?.array?.object ?? findings?.object;
  assert.ok(target, 'the scan JSON shape includes findings');
  const dropped = Object.keys(target)[0];
  delete target[dropped];
  now.surfaces.severityVocabulary = now.surfaces.severityVocabulary.slice(1);
  now.surfaces.mcpTools = now.surfaces.mcpTools.filter((t) => t.name !== 'verify_fix');
  const { breaking } = compareContracts(snap, now);
  const kinds = breaking.map((b) => `${b.surface}:${b.kind}`);
  assert.ok(kinds.includes('scanJson:removed'), kinds.join(','));
  assert.ok(breaking.some((b) => /vocabulary entry/.test(b.detail || '')), 'a removed vocabulary entry is breaking');
  assert.ok(breaking.some((b) => b.path === 'mcpTools.verify_fix' && b.kind === 'removed'));
  assert.ok(breaking.length >= 3);
});

test('an added field is additive, not breaking, and a changed exit code is breaking', async () => {
  const snap = structuredClone(loadSnapshot(REPO));
  const now = structuredClone(await capture());
  now.surfaces.scanHealth.shape.object.brandNewField = 'string';
  now.surfaces.mcpTools.push({ name: 'a_new_tool', required: [], properties: {} });
  let r = compareContracts(snap, now);
  assert.deepEqual(r.breaking, []);
  assert.ok(r.additive.some((a) => a.path.endsWith('brandNewField')));
  assert.ok(r.additive.some((a) => a.path === 'mcpTools.a_new_tool'));
  now.surfaces.cliExitCodes.ciStrictVulnerable = 0;
  r = compareContracts(snap, now);
  assert.ok(r.breaking.some((b) => b.path === 'cliExitCodes.ciStrictVulnerable' && b.kind === 'value-changed'));
});

test('accepting a breaking change records the reason in the snapshot history', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-contract-'));
  try {
    const cap = structuredClone(await capture());
    writeSnapshot(root, cap);
    assert.deepEqual(loadSnapshot(root).history, []);
    writeSnapshot(root, cap, { acceptBreaking: 'removed legacy field in 9.9.9', previous: loadSnapshot(root) });
    const h = loadSnapshot(root).history;
    assert.equal(h.length, 1);
    assert.match(h[0].acceptedBreakingChange, /legacy field/);
    assert.equal(h[0].version, cap.capturedAtVersion);
  } finally { cleanup(root); }
});
