// Accuracy scoring for the Haskell/Nix capability gates (PRD section 9.2).
//
// One-to-one matching: every expected label is matched by AT MOST ONE finding (same file, same family or
// CWE, and the finding's line within `lineTolerance` of the labeled line when one is given), and every
// finding matches at most one label. An unmatched finding is a false positive, an unmatched label a false
// negative, so the same vulnerability reported twice is not inflated into two true positives, and a
// missing parse or discovery is a miss, never an exclusion.
//
// A zero or absent denominator is `notMeasured`, never 100%. Layers are scored independently (a finding
// belongs to exactly one layer) and are never combined into one headline number, so a strong layer cannot
// hide a weak one.

export const LAYERS = Object.freeze({
  'security-taint': (f) => f.parser === 'IR-TAINT',
  'structural-sast': (f) => f.parser === 'HS-RULES' || f.parser === 'NIX-RULES',
  'privacy-lineage': (f) => f.parser === 'LINEAGE' || f.kind === 'privacy',
  'config-sast': (f) => f.parser === 'NIXOS-HARDENING',
});

const ratio = (n, d) => (d > 0 ? n / d : null);

export function prf(tp, fp, fn) {
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const f1 = precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : (precision !== null && recall !== null ? 0 : null);
  return { tp, fp, fn, precision, recall, f1, measured: precision !== null && recall !== null };
}

const matches = (label, f, tol) => {
  if (label.file && f.file !== label.file) return false;
  // `families`: the finding's own family must be one of these (a detector's family vocabulary differs from a corpus's; the
  // alias table lives with the harness that declares it, never in the engine). Otherwise a single family, otherwise the CWE.
  if (Array.isArray(label.families)) { if (!label.families.includes(f.family)) return false; }
  else if (label.family ? f.family !== label.family : (label.cwe && f.cwe !== label.cwe)) return false;
  if (!Array.isArray(label.families) && label.cwe && label.family && f.cwe !== label.cwe) return false;
  if (Number.isInteger(label.line) && Number.isInteger(f.line) && Math.abs(label.line - f.line) > tol) return false;
  return true;
};

// A finding the proof gate discharged (sanitized / guarded) is reported but is not a live detection.
export const isLive = (f) => !(f.proof && /^proven-/.test(f.proof.verdict));

/**
 * @param {Array<{id:string, file:string, label?:'vuln'|'safe', expect:Array<{file?:string,cwe?:string,family?:string,line?:number}>}>} cases
 * @param {object[]} findings all findings of the scan
 * @param {{layer:string, lineTolerance?:number, live?:(f:object)=>boolean}} opts
 */
export function scoreLayer(cases, findings, opts) {
  const inLayer = typeof opts.inLayer === 'function' ? opts.inLayer : LAYERS[opts.layer];
  if (!inLayer) throw new Error(`unknown layer ${opts.layer}`);
  const tol = opts.lineTolerance ?? 0;
  const live = opts.live || isLive;
  const pool = findings.filter((f) => inLayer(f) && live(f)).map((f) => ({ f, used: false }));
  const perFamily = {};
  let tp = 0, fp = 0, fn = 0, tn = 0;
  const misses = [];
  const strays = [];
  const bump = (fam, key) => { (perFamily[fam] ||= { tp: 0, fp: 0, fn: 0 })[key]++; };
  for (const c of cases) {
    const here = pool.filter((p) => p.f.file === c.file);
    const expected = c.expect || [];
    for (const label of expected) {
      const hit = here.find((p) => !p.used && matches({ file: c.file, ...label }, p.f, tol));
      const fam = c.family || label.family || label.cwe || 'unknown';
      if (hit) { hit.used = true; tp++; bump(fam, 'tp'); } else { fn++; bump(fam, 'fn'); misses.push({ case: c.id, label }); }
    }
    if (!expected.length && !here.length) tn++;
  }
  let crossFamily = 0;
  for (const p of pool) {
    if (p.used) continue;
    // Family-scoped scoring (the convention of per-category benchmarks): a finding of a DIFFERENT CWE than the case it sits in
    // answers a different question and is counted separately, never as a false positive of this case's family. Strict mode
    // (the default) counts it as a stray, so both numbers can always be reported side by side.
    if (opts.familyScoped) {
      const own = cases.find((c) => c.file === p.f.file);
      if (own && Array.isArray(own.families) ? !own.families.includes(p.f.family) : (own && own.cwe && p.f.cwe !== own.cwe)) { crossFamily++; continue; }
    }
    // only findings located in labeled files count against precision: an unrelated file is not scored
    const owner = cases.find((c) => c.file === p.f.file);
    if (owner) { fp++; bump(owner.family || p.f.family || p.f.cwe || 'unknown', 'fp'); strays.push({ file: p.f.file, line: p.f.line, cwe: p.f.cwe }); }
  }
  const families = Object.fromEntries(Object.entries(perFamily).map(([k, v]) => [k, prf(v.tp, v.fp, v.fn)]));
  return { layer: opts.layer, cases: cases.length, tn, ...prf(tp, fp, fn), families, misses, strays, ...(opts.familyScoped ? { crossFamilyFindingsNotScored: crossFamily } : {}) };
}

/** Per-layer results side by side. Deliberately NO combined headline number. */
export function scoreAllLayers(cases, findings, layerList, opts = {}) {
  return Object.fromEntries(layerList.map((layer) => [layer, scoreLayer(cases, findings, { ...opts, layer })]));
}
