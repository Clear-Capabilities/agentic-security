// Measures the Haskell and Nix engine against the QA-001 corpora (PRD section 9). Reads labels from the corpus data, scans ONLY the
// label-free sources, and scores with scanner/src/language/accuracy.js. The engine never sees a label, a case id or a split: each
// case is written to an opaque scratch directory under its own source file name.
//
//   node bench/language-support/measure.mjs --split holdout|validation|train|unseen|shape-dev [--eco haskell|nix] [--suites detection,privacy,pairs,fixes,supply,parser] [--out file]
//
// Output carries confusion matrices per layer and per family, denominators, the unknown-case outcomes reported separately, and the
// hashes of the label files and the frozen holdout, so a result can show it was measured on unchanged data.
import fs from 'node:fs';
import path from 'node:path';
import { DATA, readJson, read, sha } from './lib.mjs';
import { runDetection } from './suites/detection.mjs';
import { runPrivacy } from './suites/privacy.mjs';
import { runPairs } from './suites/pairs.mjs';
import { runFixes } from './suites/fixes.mjs';
import { runSupply } from './suites/supply.mjs';
import { runParser } from './suites/parser.mjs';

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
const split = arg('split', 'validation');
const ecoArg = arg('eco', null);
const limit = Number(arg('limit', 0)) || 0;
const suites = new Set(String(arg('suites', 'detection,privacy,pairs,fixes,supply,parser')).split(','));
const out = { schema: 'agentic-security/language-support-measurement@2', split, measuredAt: new Date().toISOString().slice(0, 10), corpusVersion: readJson('manifest.json').version, ecosystems: {} };

for (const eco of ['haskell', 'nix']) {
  if (ecoArg && ecoArg !== eco) continue;
  const e = (out.ecosystems[eco] = {});
  if (suites.has('detection')) e.detection = await runDetection({ split, eco, limit });
  if (suites.has('privacy')) e.privacy = await runPrivacy({ split, eco });
  if (suites.has('pairs')) e.pairs = await runPairs({ split, eco });
  if (suites.has('parser')) e.parser = await runParser({ split, eco });
  if (suites.has('fixes')) e.fixes = await runFixes({ eco });
}
if (suites.has('supply')) out.supply = await runSupply();
// corpus-wide denominators (all splits), so a gate can state how large the corpus is, not only the split it measured
out.corpusTotals = {};
{
  const cases = readJson('labels/cases.json'); const priv = readJson('labels/privacy.json');
  for (const eco of ['haskell', 'nix']) {
    const mine = cases.filter((c) => c.ecosystem === eco);
    out.corpusTotals[eco] = {
      security: { vulnerable: mine.filter((c) => c.label === 'vulnerable').length, safe: mine.filter((c) => c.label === 'safe').length, unknown: mine.filter((c) => c.label === 'unknown').length, families: new Set(mine.filter((c) => c.label !== 'unknown').map((c) => c.family)).size },
      privacy: { positives: priv.filter((c) => c.ecosystem === eco && c.expected === 'flow').length, negatives: priv.filter((c) => c.ecosystem === eco && c.expected !== 'flow').length },
    };
  }
}
const manifest = readJson('manifest.json');
out.hashes = { unseenRollup: (manifest.unseen || {}).rollup || null, shapeDevRollup: (manifest.shapeDev || {}).rollup || null, holdoutRollup: manifest.holdoutRollup, contentRollup: manifest.contentRollup, labelsSha256: sha(read(path.join(DATA, 'labels', 'cases.json'))), privacyLabelsSha256: sha(read(path.join(DATA, 'labels', 'privacy.json'))), manifestSha256: sha(read(path.join(DATA, 'manifest.json'))) };
const dest = arg('out', null);
if (dest) fs.writeFileSync(dest, `${JSON.stringify(out, null, 2)}\n`); else process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
