#!/usr/bin/env node
// Keeps the captured example output in the engineering-excellence docs equal to what the implementation produces (E8-04).
//
// A doc marks a block with `<!-- capture: <id> -->` on its own line, immediately followed by a fenced code block. This script computes the text for each id from the
// real implementation or from a committed result file, and either rewrites the blocks (default) or fails when one differs (--check). A number in these docs is
// therefore either captured here or not in the docs; there is no hand-typed result to go stale.
//
//   node scripts/engineering-excellence/doc-captures.mjs [--check]
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const DOCS = ['docs/engineering-excellence/README.md', 'docs/guides/release-assurance.md'];
const json = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));
const cli = (...a) => spawnSync(process.execPath, [path.join(ROOT, 'scanner/bin/agentic-security.js'), ...a], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 });
const PKG = 'docs/engineering-excellence/data/e2e-demo/release-package.json'; const KEY = 'docs/engineering-excellence/data/e2e-demo/public-key.pem';

export const CAPTURES = {
  'help-release-view': () => cli('--help').stdout.split('\n').filter((l) => /release-view/.test(l)).join('\n'),
  'release-view-ciso': () => { const r = cli('release-view', PKG, '--view', 'ciso', '--format', 'text', '--public-key', KEY); return (r.stdout + r.stderr).trim(); },
  'verify-package': () => { const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/verify-release-package.mjs'), PKG, '--public-key', KEY], { cwd: ROOT, encoding: 'utf8' }); return (r.stdout + r.stderr).trim(); },
  'e2e-steps': () => json('docs/engineering-excellence/data/e2e-demo-outline.json').steps.map((s) => `[${s.id}] ${s.summary}`).join('\n'),
  'baseline-headline': () => {
    const b = json('bench/independent/runs/BASELINE.json'); const r = json(`bench/independent/runs/${b.runId}/RESULT.json`); const h = r.headline; const pct = (x) => (x * 100).toFixed(1) + '%';
    return [`run ${b.runId}, engine ${r.engineVersion}, ${r.coverage.scored} of ${r.population.selection.entries} entries scored (${r.coverage.unscored} timed out, unscored)`, `localized precision ${h.precision.n}/${h.precision.d} = ${pct(h.precision.value)}`, `localized recall    ${h.recall.n}/${h.recall.d} = ${pct(h.recall.value)}`, `localized F1        ${h.f1.toFixed(3)} (95% interval ${h.f1Interval.low.toFixed(3)} to ${h.f1Interval.high.toFixed(3)})`].join('\n');
  },
  'dci-real-app-overall': () => { const o = json('docs/engineering-excellence/data/dci-real-app.json').overall; const pct = (v) => (v === null ? 'n/a' : (v * 100).toFixed(0) + '%'); return `${o.routes} routes: TP ${o.tp}, FP ${o.fp}, FN ${o.fn}, TN ${o.tn}, unresolved ${o.unresolved}; precision ${pct(o.precision)} (${o.tp}/${o.precisionOf}), recall ${pct(o.recall)} (${o.tp}/${o.recallOf})`; },
  'perf-large-verdict': () => { const l = json('docs/engineering-excellence/data/perf-budget.json').classes.map((c) => `${c.id}: P95 ${c.summary.wallMs.p95} ms, peak RSS ${c.summary.maxRssMb.max} MB, ${c.verdict.green ? 'within budget' : 'NOT GREEN (' + c.verdict.problems.join('; ') + ')'}`); return l.join('\n'); },
};

const MARK = /(<!-- capture: ([\w-]+) -->\n```[a-z]*\n)([\s\S]*?)(\n```)/g;
export function process_(text, { write }) {
  const stale = [];
  const out = text.replace(MARK, (m, head, id, body, tail) => {
    if (!CAPTURES[id]) { stale.push(`${id}: unknown capture id`); return m; }
    const fresh = CAPTURES[id]();
    if (fresh !== body) stale.push(id);
    return write ? head + fresh + tail : m;
  });
  return { out, stale };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes('--check'); let bad = 0;
  for (const d of DOCS) {
    const p = path.join(ROOT, d); if (!fs.existsSync(p)) { console.error(`missing ${d}`); bad++; continue; }
    const { out, stale } = process_(fs.readFileSync(p, 'utf8'), { write: !check });
    if (check && stale.length) { console.error(`${d}: stale or unknown captures: ${stale.join(', ')}`); bad++; }
    if (!check && out !== fs.readFileSync(p, 'utf8')) fs.writeFileSync(p, out);
  }
  if (bad) process.exit(1);
  console.log(check ? 'doc captures are current' : 'doc captures written');
}
