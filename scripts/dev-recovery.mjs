#!/usr/bin/env node
// Development recovery measurement (QA-005.AC03, QA-006.AC03): run the development case suite against ANY engine checkout and print
// what it recovers, what it keeps quiet, and what each layer contributed. Run it once per engine revision and compare the outputs;
// the before/after numbers in docs/guides/engine-mechanism-evidence.md were produced this way.
//
//   node scripts/dev-recovery.mjs [--engine <repo-root>] [--layer deep-taint|deterministic-only] [--corpus] [--json]
//
//   --engine   a repository checkout whose scanner/src/posture/evaluation/scan-child.js is used to scan (default: this checkout)
//   --corpus   also measure alert burden and IR-TAINT location accuracy over the CVE-replay `pre/` trees
//
// The scoring is the frozen policy (evaluation/score.js, matching lineWindow 3, end to end). The labels are the development labels in
// scanner/test/fixtures/engine-mechanisms/cases.json, all flagged synthetic: this is a development instrument, not an accuracy figure.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDevSuite, devResolver } from '../scanner/src/posture/evaluation/dev-cases.js';
import { runEvaluation, defaultScanFn } from '../scanner/src/posture/evaluation/runner.js';
import { scoreRun, clusterAlerts } from '../scanner/src/posture/evaluation/score.js';
import { protectedTermsFrom } from '../scanner/src/posture/evaluation/custody.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const FIXTURES = path.join(REPO, 'scanner', 'test', 'fixtures', 'engine-mechanisms');
const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : undefined; };
const engineRoot = path.resolve(flag('engine') || REPO);
const layer = flag('layer') || 'deep-taint';
const childPath = path.join(engineRoot, 'scanner', 'src', 'posture', 'evaluation', 'scan-child.js');
if (!fs.existsSync(childPath)) { console.error(`no scan child at ${childPath}`); process.exit(2); }

const scanFn = (dir, opts) => defaultScanFn(dir, { ...opts, childPath });

async function devSuite() {
  const suite = buildDevSuite({ fixturesDir: FIXTURES });
  if (!suite.protocol) throw new Error(`dev suite failed to freeze: ${JSON.stringify(suite.freezeErrors)}`);
  const terms = protectedTermsFrom({ defects: suite.defects, negatives: suite.negatives });
  const r = await runEvaluation({ protocol: suite.protocol, config: { layer }, resolveTarget: devResolver(FIXTURES), protectedTerms: terms, split: 'dev', scanFn });
  if (!r.ok) throw new Error(`run refused: ${JSON.stringify(r.errors)}`);
  const score = scoreRun({ run: r.run, protocol: suite.protocol, defects: suite.defects, negatives: suite.negatives });
  const byId = new Map(suite.defects.map((d) => [d.id, d]));
  const cases = suite.cases.map((c) => {
    const pre = r.run.outcomes.find((o) => o.targetId === c.id && o.variant === 'pre');
    const post = r.run.outcomes.find((o) => o.targetId === c.id && o.variant === 'post');
    const miss = score.misses.find((m) => byId.get(m.labelId)?.targetId === c.id);
    const fp = score.falsePositives.filter((x) => x.targetId === c.id);
    return {
      id: c.id, mechanism: c.mechanism, language: c.language,
      recovered: !miss, parsersOnPre: [...new Set((pre?.findings || []).map((f) => f.parser))].sort(),
      irTaintOnPre: (pre?.findings || []).some((f) => f.parser === 'IR-TAINT'),
      patchedStaysSilent: fp.length === 0, patchedStatus: post?.status, rawAlertsPre: (pre?.findings || []).length, rawAlertsPost: (post?.findings || []).length,
    };
  });
  return { micro: score.endToEnd.micro, cases, falsePositives: score.falsePositives.length, misses: score.misses.length };
}

async function corpus() {
  // Burden and location accuracy over the CVE-replay vulnerable trees, deep mode, via this engine's scan child.
  const root = path.join(REPO, 'bench', 'cve-replay');
  const out = { entries: 0, rawAlerts: 0, rootCauses: 0, irTaintFindings: 0, irTaintOnNonCodeLine: 0, byLanguage: {} };
  const NON_CODE = /^\s*(?:$|\}|\)|\{|\/\/.*|#.*|\*.*|\/\*.*|package\b.*|import\b.*|using\b.*|<\?php\s*)$/;
  for (const tier of ['regression', 'capability', 'deep']) {
    const dir = path.join(root, tier);
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir).sort()) {
      const pre = path.join(dir, name, 'pre');
      if (!fs.existsSync(pre)) continue;
      let res;
      try { res = await scanFn(pre, { layer: 'deep-taint', timeoutMs: 120000, env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C' } }); } catch { continue; }
      out.entries++;
      const fs_ = res.findings || [];
      out.rawAlerts += fs_.length;
      out.rootCauses += clusterAlerts(fs_, 3).length;
      for (const f of fs_) {
        if (f.parser !== 'IR-TAINT') continue;
        out.irTaintFindings++;
        let text = null;
        try { text = fs.readFileSync(path.join(pre, f.file), 'utf8').split('\n')[f.line - 1]; } catch { /* file or line missing */ }
        if (text === null || text === undefined || NON_CODE.test(text)) out.irTaintOnNonCodeLine++;
        const lang = (String(f.file).match(/\.([a-z]+)$/i) || [, '?'])[1];
        out.byLanguage[lang] = out.byLanguage[lang] || { irTaint: 0, nonCode: 0 };
        out.byLanguage[lang].irTaint++;
        if (text === null || text === undefined || NON_CODE.test(text)) out.byLanguage[lang].nonCode++;
      }
    }
  }
  return out;
}

const main = async () => {
  const dev = await devSuite();
  const result = { engine: engineRoot, layer, development: dev, ...(argv.includes('--corpus') ? { corpus: await corpus() } : {}) };
  if (argv.includes('--json')) { console.log(JSON.stringify(result, null, 2)); return 0; }
  console.log(`engine ${engineRoot}  layer ${layer}  (development labels, synthetic: a development instrument, not an accuracy figure)`);
  console.log(`defects recovered ${dev.micro.tp}/${dev.micro.tp + dev.micro.fn}; patched trees with a false positive ${dev.micro.fp}/${dev.micro.fp + dev.micro.tn}`);
  for (const c of dev.cases) console.log(`  ${c.id.padEnd(26)} ${c.mechanism.padEnd(28)} recovered=${String(c.recovered).padEnd(5)} IR-TAINT=${String(c.irTaintOnPre).padEnd(5)} patched-silent=${String(c.patchedStaysSilent).padEnd(5)} parsers=${c.parsersOnPre.join(',')}`);
  if (result.corpus) { const k = result.corpus; console.log(`corpus pre trees: ${k.entries}; raw alerts ${k.rawAlerts}; root causes ${k.rootCauses}; IR-TAINT findings ${k.irTaintFindings}, of which on a blank/brace/comment/import line ${k.irTaintOnNonCodeLine}`); }
  return 0;
};
main().then((c) => process.exit(c), (e) => { console.error(e?.stack || e); process.exit(1); });
