#!/usr/bin/env node
// Offline miniature public reproduction (QA-008.AC03): `npm run reproduce:mini` from scanner/, or `node scripts/public-reproduction.mjs`.
//
// What this is. A few-minute, network-free run that anyone with a checkout can repeat. It exercises the real measuring path end to end
// (freeze a protocol, stage workspaces through the leakage audit, run the engine in a child process, score end to end, report with
// intervals, account costs, judge the real-code gates) over the small PUBLIC synthetic suite in scanner/test/fixtures/evaluation-synthetic/,
// and then runs the NEGATIVE CONTROLS that show the measuring path can tell a good result from a bad one:
//
//   null-engine        an engine that reports nothing must score recall 0 and be worse than the real engine
//   flag-everything    an engine that reports every line must score worse precision than the real engine, on the negatives
//   shuffled-labels    the real engine's findings scored against labels moved to the wrong lines must collapse to recall 0
//   planted-leak       a workspace carrying an answer-key file must be quarantined, counted as a miss, and must FAIL the leak gate
//   gates-need-data    the real-code gates must NOT pass on this population, however good the figures
//
// What it is not. It uses no sealed labels (there are none in this repository), measures no real code and says nothing about the engine's
// accuracy: three authored files cannot support a figure, and every number printed here is labelled synthetic. A control that does not
// behave as expected makes the script exit 1, which would mean the measuring path is broken.
//
// `--fault <control>` deliberately BREAKS one control's measuring path (the stand-in engine behaves like the real one, the labels stay
// where they are, the leak is not planted), to show the script can fail: with a fault injected it must exit 1 and name the control.
// The faultable controls are null-engine, flag-everything, shuffled-labels and planted-leak.
//
// Exit: 0 every control behaved, 1 a control did not, 2 usage.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSyntheticSuite, syntheticResolver } from '../scanner/src/posture/evaluation/synthetic.js';
import { runEvaluation } from '../scanner/src/posture/evaluation/runner.js';
import { scoreRun } from '../scanner/src/posture/evaluation/score.js';
import { buildAccuracyReport } from '../scanner/src/posture/evaluation/report.js';
import { accountCosts } from '../scanner/src/posture/evaluation/economics.js';
import { evaluateGates } from '../scanner/src/posture/evaluation/gates.js';
import { protectedTermsFrom } from '../scanner/src/posture/evaluation/custody.js';
import { buildDefectLabel } from '../scanner/src/posture/evaluation/labels.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, '..', 'scanner', 'test', 'fixtures', 'evaluation-synthetic');
const argv = process.argv.slice(2);
const JSON_OUT = argv.includes('--json');
const FAULTS = ['null-engine', 'flag-everything', 'shuffled-labels', 'planted-leak'];
const faultAt = argv.indexOf('--fault');
const FAULT = faultAt >= 0 ? argv[faultAt + 1] : null;
if (faultAt >= 0 && !FAULTS.includes(FAULT)) { console.error(`usage: --fault <${FAULTS.join('|')}>`); process.exit(2); }
if (argv.some((a, i) => a !== '--json' && a !== '--fault' && argv[i - 1] !== '--fault')) { console.error('usage: public-reproduction.mjs [--json] [--fault <control>]'); process.exit(2); }

const pct = (x) => (x === null || x === undefined ? 'n/a' : `${(x * 100).toFixed(1)}%`);

// A control engine: a stand-in for the scanner that the harness drives through the same path as the real one.
const nullEngine = async () => ({ findings: [] });
const flagEverything = (suite, fixturesDir) => async (dir) => {
  // Reports every code line of every file as the family the negatives are about.
  const out = [];
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r);
      else if (e.isFile()) {
        const lines = fs.readFileSync(path.join(d, e.name), 'utf8').split('\n');
        for (let i = 0; i < lines.length; i++) if (lines[i].trim()) for (const family of ['sql-injection', 'command-injection']) out.push({ id: `flood:${r}:${i + 1}:${family}`, file: r, line: i + 1, family, cwe: family === 'sql-injection' ? 'CWE-89' : 'CWE-78', severity: 'high', parser: 'control', vuln: 'flood' });
      }
    }
  };
  walk(dir, '');
  return { findings: out };
};

async function runWith(suite, resolveTarget, scanFn, layer, split = 'all') {
  const terms = protectedTermsFrom({ defects: suite.defects, negatives: suite.negatives });
  const r = await runEvaluation({ protocol: suite.protocol, config: { layer }, resolveTarget, protectedTerms: terms, split, allowSealed: true, ...(scanFn ? { scanFn } : {}) });
  if (!r.ok) throw new Error(`run refused: ${JSON.stringify(r.errors)}`);
  return r.run;
}

async function main() {
  const suite = buildSyntheticSuite({ fixturesDir: FIXTURES });
  if (!suite.protocol) { console.error('the public suite failed to freeze', JSON.stringify(suite.freezeErrors)); return 1; }
  const resolve = syntheticResolver(FIXTURES);
  const score = (run, defects = suite.defects, negatives = suite.negatives) => scoreRun({ run, protocol: suite.protocol, defects, negatives });

  // ---- the real measuring path
  const realRun = await runWith(suite, resolve, null, 'deep-taint');
  const real = score(realRun);
  const report = buildAccuracyReport({ score: real, protocol: suite.protocol, population: 'development', run: realRun });
  const costs = accountCosts((realRun.outcomes || []).filter((o) => o.status === 'completed').map((o, i) => ({ id: `scan-${i}`, kind: 'tool', amountUsd: o.costUsd ?? undefined, targetId: o.targetId })));
  // The gates judge the SEALED split only (here: the synthetic one), exactly as a release evaluation would.
  const sealedRun = await runWith(suite, resolve, null, 'deep-taint', 'sealed');
  const gates = evaluateGates({ protocol: suite.protocol, score: score(sealedRun), defects: suite.defects, negatives: suite.negatives, run: sealedRun });

  // ---- negative controls
  const controls = [];
  const control = (name, ok, detail) => controls.push({ name, ok: !!ok, detail });

  const nullScore = score(await runWith(suite, resolve, FAULT === 'null-engine' ? null : nullEngine, 'deep-taint'));
  control('null-engine', nullScore.endToEnd.micro.recall === 0 && (real.endToEnd.micro.recall ?? 0) > nullScore.endToEnd.micro.recall,
    `null recall ${pct(nullScore.endToEnd.micro.recall)} vs engine ${pct(real.endToEnd.micro.recall)}`);

  const floodScore = score(await runWith(suite, resolve, FAULT === 'flag-everything' ? null : flagEverything(suite, FIXTURES), 'deep-taint'));
  control('flag-everything', (floodScore.endToEnd.micro.precision ?? 1) < (real.endToEnd.micro.precision ?? 0) || floodScore.endToEnd.micro.fp > real.endToEnd.micro.fp,
    `flood false positives ${floodScore.endToEnd.micro.fp} vs engine ${real.endToEnd.micro.fp}`);

  const shift = FAULT === 'shuffled-labels' ? 0 : 40;
  const moved = suite.defects.map((d) => buildDefectLabel({ ...d, id: undefined, location: { ...d.location, startLine: d.location.startLine + shift, endLine: d.location.endLine + shift } }));
  const shuffled = scoreRun({ run: realRun, protocol: suite.protocol, defects: moved, negatives: suite.negatives });
  control('shuffled-labels', shuffled.endToEnd.micro.recall === 0 && (real.endToEnd.micro.recall ?? 0) > 0,
    `recall against moved labels ${pct(shuffled.endToEnd.micro.recall)} vs ${pct(real.endToEnd.micro.recall)}`);

  // planted leak: a pinned copy of the suite whose first target also carries an answer-key file
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repro-leak-'));
  try {
    fs.cpSync(FIXTURES, root, { recursive: true });
    const firstTarget = fs.readdirSync(root).sort()[0];
    if (FAULT !== 'planted-leak') fs.writeFileSync(path.join(root, firstTarget, 'pre', 'expected-findings.json'), '{"note":"planted answer key"}\n');
    const leaky = buildSyntheticSuite({ fixturesDir: root });
    const leakRun = await runWith(leaky, syntheticResolver(root), nullEngine, 'deep-taint');
    const leakGates = evaluateGates({ protocol: leaky.protocol, score: scoreRun({ run: leakRun, protocol: leaky.protocol, defects: leaky.defects, negatives: leaky.negatives }), defects: leaky.defects, negatives: leaky.negatives, run: leakRun });
    // The leak is planted in the first target in name order; whichever split it lands in, the gate counts it.
    const quarantined = leakRun.outcomes.filter((o) => o.status === 'quarantined').length;
    control('planted-leak', quarantined >= 1 && leakGates.gates.find((g) => g.id === 'answer-key-leaks')?.status === 'fail' && leakGates.overall === 'fail',
      `${quarantined} workspace(s) quarantined, leak gate ${leakGates.gates.find((g) => g.id === 'answer-key-leaks')?.status}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }

  control('gates-need-data', gates.overall === 'insufficient-population' && gates.synthetic === true,
    `real-code gates on the public suite: ${gates.overall}`);

  const allOk = controls.every((c) => c.ok);
  const out = {
    synthetic: true, fault: FAULT, note: 'three authored files: these figures exercise the measuring path and are not engine accuracy',
    protocolHash: suite.protocol.protocolHash,
    figures: { engine: { micro: real.endToEnd.micro, completion: real.completion.rate }, nullEngine: nullScore.endToEnd.micro, flagEverything: floodScore.endToEnd.micro },
    reportHash: report.reportHash, intervals: report.aggregate.micro.intervals.f1.status, costs: { confirmedDefects: costs.ok ? costs.confirmedDefects : null, unmeasuredMachineEntries: costs.ok ? costs.unmeasuredMachineEntries : null },
    gates: { overall: gates.overall }, controls, allControlsBehaved: allOk,
  };
  if (JSON_OUT) { console.log(JSON.stringify(out, null, 2)); return allOk ? 0 : 1; }
  console.log('PUBLIC MINIATURE REPRODUCTION (offline, no sealed labels). Three authored files: figures exercise the path, not the engine.');
  console.log(`protocol ${suite.protocol.protocolHash}`);
  console.log(`engine (deep-taint): recall ${pct(real.endToEnd.micro.recall)}, precision ${pct(real.endToEnd.micro.precision)}, completion ${pct(real.completion.rate)}; 95% interval on F1: ${report.aggregate.micro.intervals.f1.status}`);
  console.log(`real-code gates: ${gates.overall}\n`);
  console.log('negative controls:');
  for (const c of controls) console.log(`  ${c.ok ? 'ok  ' : 'FAIL'} ${c.name.padEnd(16)} ${c.detail}`);
  console.log(allOk ? '\nevery control behaved: the measuring path distinguishes good results from bad ones' : '\nA CONTROL FAILED: the measuring path cannot be trusted until this is understood');
  return allOk ? 0 : 1;
}

main().then((c) => process.exit(c), (e) => { console.error(e?.stack || e); process.exit(1); });
