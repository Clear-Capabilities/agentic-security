// Haskell core-family benchmark (PRD FR 04 / FR 11). Scores each of the six core families on its own, so strength in one family
// cannot hide an unsupported one.
//
// Cases live in manifest.json: family, label (vulnerable|safe), group (a vulnerable case and its fixed counterpart share a group and a
// split), split (dev|holdout), origin. Labels are in the manifest only; the scanned sources carry no hint of their verdict.
//
// Definitions, fixed before tuning:
//   detected  a vulnerable case has an actionable finding (disposition confirmed or needs-review) of the family's CWE set in its file.
//   confirmed a detected case whose disposition is `confirmed`. A model or the detector alone cannot confirm, so this is usually 0 until
//             execution proof or a reviewer verdict exists. It is reported, and never substituted for `detected`.
//   miss      every vulnerable case that is not detected, including a case with no result or an unresolved one.
//   false-positive  a safe case that has an actionable finding of the family.
//
// Only cases with origin other than `author-seed` count toward the 25 vulnerable + 25 safe per family requirement. A family below that
// reports `insufficient-cases` and is never claimable, whatever its recall.
//
// usage: node bench/haskell-core-families/runner.mjs [--split dev|holdout] [--json] [--min-recall 0.8]
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const argv = process.argv.slice(2);
const opt = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };

export const FAMILIES = Object.freeze({
  sql: ['CWE-89'],
  cmd: ['CWE-78', 'CWE-88'],
  path: ['CWE-22', 'CWE-23', 'CWE-73'],
  ssrf: ['CWE-918'],
  exposure: ['CWE-532', 'CWE-200', 'CWE-312', 'CWE-359'],
  crypto: ['CWE-330', 'CWE-338', 'CWE-327', 'CWE-328', 'CWE-326', 'CWE-916'],
});
export const REQUIRED_PER_LABEL = 25;
const ACTIONABLE = new Set(['confirmed', 'needs-review']);

export function summarize(results, { minRecall = 0.8 } = {}) {
  const out = {};
  for (const fam of Object.keys(FAMILIES)) {
    const rs = results.filter((r) => r.family === fam);
    const vuln = rs.filter((r) => r.label === 'vulnerable');
    const safe = rs.filter((r) => r.label === 'safe');
    const indep = (l) => rs.filter((r) => r.label === l && r.origin !== 'author-seed').length;
    const detected = vuln.filter((r) => r.detected).length;
    const confirmed = vuln.filter((r) => r.detected && r.confirmed).length;
    const fp = safe.filter((r) => r.detected).length;
    const enough = indep('vulnerable') >= REQUIRED_PER_LABEL && indep('safe') >= REQUIRED_PER_LABEL;
    const recall = vuln.length ? detected / vuln.length : null;
    out[fam] = {
      vulnerable: vuln.length, safe: safe.length, independentVulnerable: indep('vulnerable'), independentSafe: indep('safe'),
      detected, confirmed, misses: vuln.length - detected, falsePositives: fp,
      recall, safeCleanRate: safe.length ? (safe.length - fp) / safe.length : null,
      status: !vuln.length ? 'unsupported' : !enough ? 'insufficient-cases' : recall >= minRecall ? 'meets-recall-target' : 'below-recall-target',
      claimable: enough && recall !== null && recall >= minRecall,
    };
  }
  return out;
}

export async function runCases(manifest, { split = null, scanner } = {}) {
  const { runScan } = scanner || await import(pathToFileURL(path.join(REPO, 'scanner', 'src', 'runScan.js')).href);
  const results = [];
  for (const c of manifest.cases) {
    if (split && c.split !== split) continue;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-hs-fam-'));
    try {
      const rel = `src/${path.basename(c.file)}`;
      fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
      fs.copyFileSync(path.join(HERE, c.file), path.join(dir, rel));
      fs.writeFileSync(path.join(dir, 'demo.cabal'), `cabal-version: 2.4\nname: demo\nversion: 0.1\nlibrary\n  exposed-modules: ${path.basename(c.file, '.hs')}\n  hs-source-dirs: src\n  build-depends: base\n`);
      let scan = null; let error = null;
      try { scan = (await runScan(dir, {})).scan; } catch (e) { error = String(e && e.message || e); }
      const cwes = new Set(FAMILIES[c.family]);
      const hits = scan ? scan.findings.filter((f) => f.file === rel && cwes.has(f.cwe) && ACTIONABLE.has(f.disposition)) : [];
      results.push({ id: path.basename(c.file, '.hs'), family: c.family, label: c.label, group: c.group, split: c.split, origin: c.origin,
        detected: hits.length > 0, confirmed: hits.some((f) => f.disposition === 'confirmed'), cwes: [...new Set(hits.map((f) => f.cwe))], error });
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
  const results = await runCases(manifest, { split: opt('split') });
  const summary = summarize(results, { minRecall: Number(opt('min-recall', '0.8')) });
  if (argv.includes('--json')) process.stdout.write(JSON.stringify({ schema: 'haskell-core-families-result/1', summary, results }, null, 1) + '\n');
  else {
    const pct = (x) => (x == null ? 'n/a' : `${(x * 100).toFixed(0)}%`);
    console.log('family     vuln safe  indep(v/s)  detected confirmed recall  FP  status');
    for (const [f, s] of Object.entries(summary)) console.log(`${f.padEnd(10)} ${String(s.vulnerable).padStart(4)} ${String(s.safe).padStart(4)}  ${`${s.independentVulnerable}/${s.independentSafe}`.padStart(9)}  ${String(s.detected).padStart(8)} ${String(s.confirmed).padStart(9)} ${pct(s.recall).padStart(6)} ${String(s.falsePositives).padStart(3)}  ${s.status}`);
    const total = Object.values(summary).reduce((a, s) => a + s.independentVulnerable + s.independentSafe, 0);
    console.log(`\nIndependent cases: ${total} of 300 required. Claimable families: ${Object.values(summary).filter((s) => s.claimable).length} of 6.`);
  }
}
