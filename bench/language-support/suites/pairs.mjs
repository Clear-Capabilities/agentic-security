// Metamorphic and adversarial pairs: a semantics-PRESERVING rewrite (scrambled identifiers, comments, paths, whitespace, import
// order) must not move the verdict; a semantics-CHANGING one (a safe case made vulnerable, a vulnerable one made safe) must.
// The verdict is "an actionable in-family finding exists in the file". This scores verdict-flip correctness, not detection count.
import { readJson, source, scanFiles, answers, actionable } from '../lib.mjs';

export async function runPairs({ split, eco }) {
  const pairs = readJson('labels/pairs.json').filter((p) => p.ecosystem === eco && p.split === split);
  const cwes = Object.fromEntries(readJson('labels/cases.json').filter((c) => c.ecosystem === eco).map((c) => [c.family, c.cwe]));
  const result = { preserve: { total: 0, held: 0, broken: [] }, change: { total: 0, held: 0, broken: [] } };
  for (const p of pairs) {
    const baseText = source(`pair-${eco}`, p.id, `base/${p.basePath}`);
    const mutText = source(`pair-${eco}`, p.id, `mutant/${p.mutantPath}`);
    const has = async (rel, text) => { const r = await scanFiles({ [rel]: text }); return r.findings.some((f) => actionable(f) && answers(eco, p.family, cwes[p.family], f)); };
    const b = await has(p.basePath, baseText);
    const m = await has(p.mutantPath, mutText);
    const bucket = result[p.relation];
    bucket.total++;
    const ok = p.relation === 'preserve' ? b === m : b !== m;
    if (ok) bucket.held++; else bucket.broken.push({ id: p.id, family: p.family, transform: p.transform, base: b, mutant: m });
  }
  for (const k of ['preserve', 'change']) result[k].rate = result[k].total ? result[k].held / result[k].total : null;
  result.broken = result.preserve.broken.length + result.change.broken.length;
  return { pairs: pairs.length, ...result };
}
