#!/usr/bin/env node
// Captures REAL output of the built bundle over the Haskell, Nix and Haskell-on-Nix examples (DOC-002).
//
//   node scripts/capture-language-examples.mjs            # rewrite docs/examples/language/captured.json
//   node scripts/capture-language-examples.mjs --check    # exit 1 when the committed capture differs from a fresh run
//
// Nothing in the capture is written by hand: each entry is the projection of an actual command's output, and the documentation
// quotes it. The projection keeps what is stable between runs (identities, locations, severities, health and counts) and drops
// what is not (scan ids, timestamps, durations, host paths). `--check` is what makes a stale example fail.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, cpSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE = join(ROOT, 'scanner', 'dist', 'agentic-security.mjs');
export const OUT = join(ROOT, 'docs', 'examples', 'language', 'captured.json');
export const EXAMPLES = ['haskell-app/vulnerable', 'haskell-app/fixed', 'haskell-app/partial', 'nixos-host/vulnerable', 'nixos-host/fixed', 'haskell-on-nix/vulnerable', 'polyglot-privacy'];
const sha = (t) => createHash('sha256').update(t).digest('hex');

function run(dir, args, env = {}) {
  const e = { ...process.env, HOME: dir, AGENTIC_SECURITY_LINEAGE_DEEP: '1', ...env }; delete e.NODE_TEST_CONTEXT;
  return spawnSync(process.execPath, [BUNDLE, ...args], { cwd: dir, encoding: 'utf8', env: e, timeout: 300000, maxBuffer: 128 << 20 });
}
const json = (r) => { try { return JSON.parse(r.stdout); } catch { return null; } };

export function capture() {
  if (!existsSync(BUNDLE)) throw new Error('scanner/dist/agentic-security.mjs is missing: run npm run build in scanner/ first');
  const version = JSON.parse(readFileSync(join(ROOT, 'scanner', 'package.json'), 'utf8')).version;
  const out = { schema: 1, engineVersion: version, bundleSha256: sha(readFileSync(BUNDLE)), examples: {} };
  const work = mkdtempSync(join(tmpdir(), 'capture-'));
  try {
    for (const ex of EXAMPLES) {
      const dir = join(work, ex.replace('/', '-')); cpSync(join(ROOT, 'examples', ex), dir, { recursive: true });
      const r = run(dir, ['scan', dir, '--format', 'json']); const j = json(r);
      const lc = (j.scanHealth && j.scanHealth.languageCoverage) || {};
      const entry = {
        exitCode: r.status,
        health: { status: j.scanHealth.status, conditions: j.scanHealth.conditions || [] },
        coverage: lc.totals || null,
        limitations: (lc.limitations || []).map((l) => (l.boundary ? `${l.kind}:${l.boundary}` : l.kind)).sort(),
        findings: (j.findings || []).map((f) => ({ family: f.family, severity: f.severity, file: f.file, line: f.line, cwe: f.cwe || null, vuln: f.vuln, parser: f.parser, stableId: f.stableId || null })).sort((a, b) => `${a.file}:${String(a.line).padStart(6, '0')}:${a.family}` < `${b.file}:${String(b.line).padStart(6, '0')}:${b.family}` ? -1 : 1),
      };
      const cdx = json(run(dir, ['scan', dir, '--format', 'cyclonedx']));
      entry.sbom = ((cdx && cdx.components) || []).map((c) => `${c.name}@${c.version || '?'}`).sort();
      if (ex === 'polyglot-privacy') {
        const ai = json(run(dir, ['scan', dir, '--format', 'aibom']));
        entry.aibom = { models: ai.models.map((m) => m.modelId || m.name), endpoints: ai.endpoints.length, services: ai.services.length };
        const g = join(dir, 'df.json'); const dx = run(dir, ['dataflow', 'export', dir, '--format', 'json', '--output', g]);
        if (dx.status === 0) { const gj = JSON.parse(readFileSync(g, 'utf8')); entry.dataflow = { schemaVersion: gj.schemaVersion, nodeCount: (gj.graph.nodes || []).length, edgeCount: (gj.graph.edges || []).length, coverage: gj.coverage || null }; }
      }
      if (ex.endsWith('/vulnerable')) {
        const fixes = [];
        for (const f of (j.findings || [])) {
          const p = run(dir, ['fix', '--finding', f.id, '--preview', '--root', dir]);
          fixes.push({ family: f.family, line: f.line, exitCode: p.status, text: (p.status === 0 ? p.stdout : p.stderr).replace(/\x1b\[[0-9;]*m/g, '').split('\n').filter((l) => !/^(Verified \(|Run with --apply|Applied\.)/.test(l)).join('\n').trim().split('\n').slice(0, 24).join('\n') });
        }
        entry.fixPreviews = fixes.sort((a, b) => (a.line - b.line) || (a.family < b.family ? -1 : 1));
      }
      out.examples[ex] = entry;
    }
  } finally { rmSync(work, { recursive: true, force: true }); }
  return out;
}

const stable = (o) => { const c = JSON.parse(JSON.stringify(o)); delete c.bundleSha256; return JSON.stringify(c, null, 2); };

if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) {
  const fresh = capture();
  if (process.argv.includes('--check')) {
    const have = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : null;
    if (!have || stable(have) !== stable(fresh)) { console.error('docs/examples/language/captured.json is stale: run `node scripts/capture-language-examples.mjs` and review the diff'); process.exit(1); }
    console.log('captured examples are current'); process.exit(0);
  }
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, `${JSON.stringify(fresh, null, 2)}\n`);
  console.log(`wrote ${OUT}`);
}
