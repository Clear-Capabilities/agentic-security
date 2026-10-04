// Parser and discovery: every corpus source is parsed by the real adapter. A valid supported-syntax fixture must parse; an unknown
// or unmodelled one must parse or be DISCLOSED as a boundary or syntax gap, never crash or hang.
import { readJson, source } from '../lib.mjs';
import { parseHaskell } from '../../../scanner/src/language/haskell-parser.js';
import { parseNix } from '../../../scanner/src/language/nix-parser.js';

export async function runParser({ split, eco }) {
  const cs = readJson('labels/cases.json').filter((c) => c.ecosystem === eco && c.split === split);
  const r = { files: cs.length, parsed: 0, failed: [], crashed: [], withErrors: 0, boundaryDisclosed: 0, maxMs: 0 };
  for (const c of cs) {
    const text = source(eco, c.id, c.path);
    const t0 = Date.now();
    try {
      const parse = eco === 'haskell' ? parseHaskell(text, { file: c.path }) : parseNix(text, { file: c.path });
      const ok = eco === 'haskell' ? parse.status !== 'failed' : !!parse.ast;
      const errors = (parse.errors || []).length;
      if (ok) r.parsed++; else r.failed.push({ id: c.id, label: c.label });
      if (errors) r.withErrors++;
      if (eco === 'haskell' && (parse.boundaries || []).length) r.boundaryDisclosed++;
      if (c.label !== 'unknown' && (!ok || errors)) r.failed.push({ id: c.id, label: c.label, errors });
    } catch (e) { r.crashed.push({ id: c.id, error: String(e && e.message).slice(0, 100) }); }
    r.maxMs = Math.max(r.maxMs, Date.now() - t0);
  }
  r.validFixturesParsedCleanly = cs.filter((c) => c.label !== 'unknown').length - r.failed.filter((f) => f.label !== 'unknown').length;
  r.validFixtures = cs.filter((c) => c.label !== 'unknown').length;
  return r;
}
