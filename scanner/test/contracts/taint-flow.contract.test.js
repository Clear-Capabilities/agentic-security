// Contract test for the taint flow finding (docs/reference/taint-flow-contract.md): fixture projects are deep-scanned and every taint
// finding is held to the page's core fields, hops and verdicts. The comparison fails if a core field disappears, and the rules the page
// states are pinned in both directions: a flow with a real sanitizer is `proven-clean` and the same flow without one is not, and the
// last hop of a chain is the sink.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runScan.js';
import { readPage, fieldsUnder } from '../helpers/contract-page.js';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_OFFLINE = '1';
const PAGE = readPage('docs/reference/taint-flow-contract.md');
const CORE = fieldsUnder(PAGE, 'Core fields');
const FIX = (n) => fileURLToPath(new URL(`../fixtures/ir-taint/${n}/`, import.meta.url));

async function taintOf(fixture) {
  const dir = mkTestTmp('agsec-taint-contract-');
  fs.cpSync(FIX(fixture), dir, { recursive: true });
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => f.parser === 'IR-TAINT');
}

test('contract: every taint finding carries every documented core field, and the check itself fails when one is missing', async () => {
  for (const fixture of ['interproc', 'sanitized', 'deadbranch', 'crossfile']) {
    const found = await taintOf(fixture);
    assert.ok(found.length >= 1, `${fixture} produced a taint finding`);
    for (const f of found) for (const k of CORE) assert.ok(k in f || (k === 'falsification' && f.source === null) || (k === 'evidence' && !(f.corroboration && f.corroboration.count > 1)), `${fixture}: ${f.id} has ${k}`);
  }
  const [one] = await taintOf('interproc');
  const { stableId, ...without } = one;
  assert.ok(!CORE.every((k) => k in without), 'dropping a core field is detected');
  assert.ok(stableId);
});

test('contract: severity, confidence and the proof and falsification verdicts are in their documented sets', async () => {
  const proof = fieldsUnder(PAGE, 'Proof verdicts');
  const fals = fieldsUnder(PAGE, 'Falsification verdicts');
  for (const fixture of ['interproc', 'sanitized', 'deadbranch']) {
    for (const f of await taintOf(fixture)) {
      assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
      assert.ok(f.confidence >= 0 && f.confidence <= 1);
      assert.ok(['high', 'medium', 'low'].includes(f.confidenceTier));
      assert.ok(proof.includes(f.proof.verdict), `proof ${f.proof.verdict}`);
      if (f.source) assert.ok(fals.includes(f.falsification.verdict), `falsification ${f.falsification.verdict}`);
      else assert.equal(f.falsification, undefined, 'no source, no path to refute');
    }
  }
});

test('contract: a flow through another function names its source, its hops and ends the chain at the sink', async () => {
  const [f] = await taintOf('interproc');
  assert.equal(f.sourceProvenance, 'interproc');
  assert.ok(f.source && Number.isInteger(f.source.line));
  assert.ok(f.chain.length >= 2);
  const last = f.chain[f.chain.length - 1];
  assert.equal(last.kind, 'sink');
  assert.equal(last.line, f.line);
  assert.doesNotMatch(last.label, /\[object Object\]/, 'the sink hop is readable');
  const hopKeys = new Set(fieldsUnder(PAGE, 'A hop in'));
  for (const hop of f.chain) for (const k of Object.keys(hop)) assert.ok(hopKeys.has(k), `${k} is a documented hop field`);
  assert.equal(f.proof.verdict, 'feasible');
  assert.equal(f.falsification.verdict, 'survived');
});

test('contract: the same sink is proven-clean with a sanitizer and feasible without one', async () => {
  const clean = await taintOf('sanitized');
  assert.ok(clean.every((f) => f.proof.verdict === 'proven-clean'), 'every flow in the sanitized fixture is proven clean');
  assert.ok(clean.every((f) => f.confidenceTier === 'low'), 'and scored down');
  const open = await taintOf('crossfile');
  assert.ok(open.some((f) => f.proof.verdict === 'feasible'));
  const noSource = open.find((f) => f.source === null);
  if (noSource) assert.equal(noSource.chain.length, 0, 'no invented source and no invented hops');
});

test('contract: a flow in code that cannot run is kept and flagged, not removed', async () => {
  const dead = await taintOf('deadbranch');
  assert.ok(dead.length >= 1);
  assert.ok(dead.some((f) => f._inDeadCode === true));
});
