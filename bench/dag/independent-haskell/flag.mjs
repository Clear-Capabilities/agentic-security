// Runs the scanner's default scan over each declared scan root and writes a plain list
// of flagged sites (flagged.json). Only this list is read when labeling.
// Usage: node flag.mjs [--out <file>] [--only <id,id>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..', '..');
const TEST_RE = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|testing)(\/|$)|\.(test|spec|e2e-spec)\.[a-z]+$/i;

export async function flagAll({ only } = {}) {
  const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));
  await disableStateWrites();
  process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const cfg = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
  const sites = [];
  for (const p of cfg.projects) {
    if (only && !only.includes(p.id)) continue;
    const projDir = path.join(HERE, '.cache', p.id);
    for (const r of p.roots) {
      const rootDir = path.join(projDir, r);
      if (!fs.existsSync(rootDir)) throw new Error(`missing scan root ${rootDir}`);
      const { scan } = await runScan(rootDir, { deterministic: true });
      const arrays = [...(scan.findings || []), ...(scan.logicVulns || []), ...(scan.secrets || [])];
      for (const f of arrays) {
        if (!f.file || !Number.isInteger(f.line) || f.line < 1) continue; // line 0 = dependency/file-level, no code site
        const abs = path.isAbsolute(f.file) ? f.file : path.join(rootDir, f.file);
        const rel = path.relative(projDir, abs).split(path.sep).join('/');
        if (rel.startsWith('..') || TEST_RE.test(rel)) continue;
        let text = '';
        try { text = fs.readFileSync(abs, 'utf8').split('\n')[f.line - 1] ?? ''; } catch { /* unreadable */ }
        sites.push({ project: p.id, language: p.language, file: rel, line: f.line,
          vuln: f.vuln || f.family || f.id || '', family: f.family || '', severity: f.severity || '', text: text.trim().slice(0, 240) });
      }
    }
  }
  // dedupe on the join key
  const seen = new Set(); const out = [];
  for (const s of sites) { const k = `${s.project}|${s.file}|${s.line}|${s.vuln}`; if (seen.has(k)) continue; seen.add(k); out.push(s); }
  out.sort((a, b) => (a.project + a.file).localeCompare(b.project + b.file) || a.line - b.line || a.vuln.localeCompare(b.vuln));
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const o = args.indexOf('--out'); const on = args.indexOf('--only');
  const out = o >= 0 ? args[o + 1] : path.join(HERE, 'flagged.json');
  const sites = await flagAll({ only: on >= 0 ? args[on + 1].split(',') : null });
  fs.writeFileSync(out, JSON.stringify(sites, null, 1));
  const c = {}; for (const s of sites) c[s.project] = (c[s.project] || 0) + 1;
  console.log(JSON.stringify(c));
}
