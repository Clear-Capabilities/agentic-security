#!/usr/bin/env node
// Turn part of the independent real-code population (bench/independent: published security advisories, the upstream fix commit, the
// package before and after) into an Eval Lab dataset (PRD 6, requirement 3: "curated vulnerable commit -> fixing commit pairs from OSS
// projects where licensing permits").
//
//   node scripts/eval-lab/import-independent.mjs --split dev --language javascript --limit 20 --out ./lab-data/js-dev [--scope files|package]
//
// What it enforces, and why:
//   * Only the `dev` and `validation` splits can be exported. The `sealed` split is evaluated by the sealed-label protocol only; putting
//     it in a dataset an arm can be run on would end its sealing, so it is refused, not skippable.
//   * Only repositories whose recorded SPDX licence is on the lab's permitted list. An unknown or unrecorded licence is skipped with a reason.
//   * Only entries whose pre/post trees are present in the local cache (the cache is gitignored and fetched on demand); the rest are
//     listed as skipped, never silently dropped.
//   * The expected span is the region the fix changed, taken from the diff of the pre and post file. It is a LOCATION derived from the
//     upstream change, not from this project's detectors. A fix that only adds lines has no changed region in the old file; its span is
//     marked approximate and is the line the addition sits at.
//   * Labels (CWE, span, the advisory id) go in the manifest only. The workspace holds source files only.
// The default scope is the files the fix commit touched; `--scope package` copies the whole cached package (bounded per entry).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const MAX_FILE_BYTES = 512 * 1024;
const MAX_PACKAGE_BYTES = 5 * 1024 * 1024;

/**
 * The change between two versions of a file, as hunks, and the ONE hunk that most plausibly is the fix: the one that removes the most
 * old lines (a security fix replaces or removes the dangerous code), ties to the earliest. Unrelated edits elsewhere in the file (an
 * added import, a renamed helper) are other hunks and no longer stretch the span across the file. The old-file region of that hunk is
 * the expected span. A hunk that only adds lines has no old region; its span is the line the addition follows, marked approximate.
 * A change too big to localize to a span (`tooLarge`) is reported as such rather than given a span that means little.
 */
export function changedRegion(oldText, newText, { maxSpanLines = 150, maxLines = 4000 } = {}) {
  const a = String(oldText).split('\n'); const b = String(newText).split('\n');
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  if (pre === a.length && pre === b.length) return null; // identical
  const am = a.slice(pre, a.length - suf); const bm = b.slice(pre, b.length - suf);
  let hunks;
  if (am.length > maxLines || bm.length > maxLines) {
    hunks = [{ oldStart: pre, oldLen: am.length, newStart: pre, newLen: bm.length }]; // too large to align: one coarse hunk
  } else {
    // longest common subsequence of the differing middle, then the runs between matches are the hunks
    const n = am.length; const m = bm.length;
    const L = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let x = n - 1; x >= 0; x--) for (let y = m - 1; y >= 0; y--) L[x][y] = am[x] === bm[y] ? L[x + 1][y + 1] + 1 : Math.max(L[x + 1][y], L[x][y + 1]);
    hunks = []; let x = 0; let y = 0; let cur = null;
    const flush = () => { if (cur) { hunks.push(cur); cur = null; } };
    while (x < n || y < m) {
      if (x < n && y < m && am[x] === bm[y]) { flush(); x++; y++; continue; }
      cur ??= { oldStart: pre + x, oldLen: 0, newStart: pre + y, newLen: 0 };
      if (y < m && (x >= n || L[x][y + 1] >= L[x + 1][y])) { cur.newLen++; y++; } else { cur.oldLen++; x++; }
    }
    flush();
  }
  const main = [...hunks].sort((p, q) => q.oldLen - p.oldLen || q.newLen - p.newLen || p.oldStart - q.oldStart)[0];
  const additionOnly = main.oldLen === 0;
  const anchor = Math.min(Math.max(1, main.oldStart), a.length);
  return {
    old: additionOnly ? { startLine: anchor, endLine: anchor, approximate: true } : { startLine: main.oldStart + 1, endLine: main.oldStart + main.oldLen, approximate: false },
    new: main.newLen ? { startLine: main.newStart + 1, endLine: main.newStart + main.newLen } : null,
    hunks: hunks.length,
    tooLarge: main.oldLen > maxSpanLines || main.newLen > maxSpanLines,
  };
}

const safeRel = (r) => typeof r === 'string' && r && !r.startsWith('/') && !r.includes('\0') && !r.split(/[\\/]/).includes('..');

function copyTree(src, dest, budget) {
  let bytes = 0;
  const walk = (rel) => {
    for (const e of fs.readdirSync(path.join(src, rel), { withFileTypes: true })) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!['node_modules', '.git'].includes(e.name)) walk(r); continue; }
      if (!e.isFile()) continue;
      const st = fs.statSync(path.join(src, r));
      if (st.size > MAX_FILE_BYTES) continue;
      bytes += st.size; if (bytes > budget) throw new Error('package scope exceeds the per-entry size budget');
      fs.mkdirSync(path.dirname(path.join(dest, r)), { recursive: true });
      fs.copyFileSync(path.join(src, r), path.join(dest, r));
    }
  };
  walk('');
}

/**
 * @param {{independentDir?: string, split: string, language: string, limit?: number, out: string, scope?: 'files'|'package', permittedLicenses: readonly string[], now?: string}} o
 * @returns {{ok: boolean, reason?: string, manifestFile?: string, entries?: number, pairs?: number, skipped?: Array<{id: string, reason: string}>}}
 */
export function importIndependent({ independentDir = path.join(ROOT, 'bench/independent'), split, language, limit = 20, out, scope = 'files', permittedLicenses, now = new Date().toISOString() }) {
  if (!['dev', 'validation'].includes(split)) return { ok: false, reason: split === 'sealed' ? 'the sealed split is evaluated only by the sealed-label protocol and is never exported into a dataset an arm can run on' : `--split must be dev or validation (got ${split})` };
  if (!['files', 'package'].includes(scope)) return { ok: false, reason: '--scope must be files or package' };
  if (!language || !/^[a-z][a-z0-9+#-]{0,19}$/.test(language)) return { ok: false, reason: '--language is required (for example javascript)' };
  const readJson = (f) => JSON.parse(fs.readFileSync(path.join(independentDir, f), 'utf8'));
  let manifest; let splits; let sidecar;
  try { manifest = readJson('manifest.json'); splits = readJson('splits.json'); sidecar = readJson('provenance.sidecar.json'); } catch (e) { return { ok: false, reason: `cannot read the independent population (${String(e.message).slice(0, 80)})` }; }
  const skipped = [];
  const chosen = [];
  for (const e of manifest.entries) {
    if (e.language !== language || splits.assignment?.[e.id] !== split) continue;
    if (chosen.length >= limit) break;
    const lic = sidecar.licenses?.[e.repo]?.spdx;
    if (!lic || !permittedLicenses.includes(lic)) { skipped.push({ id: e.id, reason: `licence ${lic ?? 'not recorded'} is not on the permitted list` }); continue; }
    const cache = path.join(independentDir, 'cache', e.id);
    if (!fs.existsSync(path.join(cache, 'pre')) || !fs.existsSync(path.join(cache, 'post'))) { skipped.push({ id: e.id, reason: 'pre/post trees are not in the local cache' }); continue; }
    const files = (e.files || []).filter(safeRel);
    let region = null; let file = null; let tooLarge = false;
    for (const f of files) {
      let a; let b; try { a = fs.readFileSync(path.join(cache, 'pre', f), 'utf8'); b = fs.readFileSync(path.join(cache, 'post', f), 'utf8'); } catch { continue; }
      const r = changedRegion(a, b);
      if (r && !r.tooLarge) { region = r; file = f; break; }
      if (r) tooLarge = true;
    }
    if (!region) { skipped.push({ id: e.id, reason: tooLarge ? 'the change is too large to localize to a span' : 'no changed file could be diffed from the cached trees' }); continue; }
    chosen.push({ e, cache, files, region, file, lic });
  }
  if (!chosen.length) return { ok: false, reason: 'no entry qualified', skipped };
  fs.mkdirSync(out, { recursive: true });
  const id = (e, suffix) => `${e.id.toLowerCase().replace(/[^a-z0-9._-]/g, '-')}-${suffix}`.slice(0, 80);
  const entries = []; let built = 0;
  for (const c of chosen) {
    const cwe = /^CWE-\d{1,5}$/.test(c.e.cwe) ? c.e.cwe : null;
    if (!cwe) { skipped.push({ id: c.e.id, reason: 'the advisory has no usable CWE' }); continue; }
    try {
      for (const side of ['pre', 'post']) {
        const dest = path.join(out, 'workspaces', id(c.e, side === 'pre' ? 'vuln' : 'fixed'));
        fs.mkdirSync(dest, { recursive: true });
        if (scope === 'package') copyTree(path.join(c.cache, side), dest, MAX_PACKAGE_BYTES);
        else for (const f of c.files) { const s = path.join(c.cache, side, f); if (fs.existsSync(s) && fs.statSync(s).size <= MAX_FILE_BYTES) { fs.mkdirSync(path.dirname(path.join(dest, f)), { recursive: true }); fs.copyFileSync(s, path.join(dest, f)); } }
      }
    } catch (err) { skipped.push({ id: c.e.id, reason: String(err.message).slice(0, 100) }); continue; }
    entries.push({ id: id(c.e, 'vuln'), kind: 'vulnerable', workspace: { dir: `workspaces/${id(c.e, 'vuln')}` }, cwe, expectedSpan: { file: c.file, startLine: c.region.old.startLine, endLine: c.region.old.endLine }, source: { repo: c.e.repo, parentCommit: c.e.parentCommit, license: c.lic, spanApproximate: c.region.old.approximate } });
    entries.push({ id: id(c.e, 'fixed'), kind: 'fixed', resemblesCwe: cwe, workspace: { dir: `workspaces/${id(c.e, 'fixed')}` }, ...(c.region.new ? { lookalikeSpan: { file: c.file, startLine: c.region.new.startLine, endLine: c.region.new.endLine } } : {}), source: { repo: c.e.repo, fixCommit: c.e.fixCommit, license: c.lic } });
    built++;
  }
  if (!built) return { ok: false, reason: 'no entry could be built', skipped };
  const cwes = [...new Set(entries.filter((x) => x.kind === 'vulnerable').map((x) => x.cwe))].sort();
  const dataset = {
    dataset: {
      id: `independent-${language}-${split}`, version: `1.0.0+${now.slice(0, 10)}`, language, source: { kind: 'directory', note: 'copied from bench/independent (published advisories; upstream fix commits)' }, split, license: 'per-entry; every repository is on the permitted list',
      cwe: cwes, leakagePolicy: { mode: 'enforce', stripComments: true, renameFiles: true },
    },
    entries,
  };
  const manifestFile = path.join(out, 'dataset.json');
  fs.writeFileSync(manifestFile, `${JSON.stringify(dataset, null, 2)}\n`);
  return { ok: true, manifestFile, entries: entries.length, pairs: built, skipped };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i === -1 ? d : process.argv[i + 1]; };
  const { PERMITTED_LICENSES } = await import(path.join(ROOT, 'scanner/src/posture/evaluation/lab/dataset.js'));
  const r = importIndependent({ independentDir: arg('independent-dir', undefined), split: arg('split', 'dev'), language: arg('language', ''), limit: Number(arg('limit', 20)), out: path.resolve(arg('out', 'lab-data')), scope: arg('scope', 'files'), permittedLicenses: PERMITTED_LICENSES });
  if (!r.ok) { console.error(`import-independent: ${r.reason}`); for (const s of (r.skipped ?? []).slice(0, 10)) console.error(`  skipped ${s.id}: ${s.reason}`); process.exit(1); }
  console.log(`wrote ${r.manifestFile}: ${r.pairs} advisory pair(s), ${r.entries} entries; skipped ${r.skipped.length}`);
  for (const s of r.skipped.slice(0, 10)) console.log(`  skipped ${s.id}: ${s.reason}`);
}
