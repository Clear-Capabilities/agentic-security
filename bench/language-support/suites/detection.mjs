// SAST and security-taint measurement over the labeled security cases (PRD 9.2). Layers are scored independently, over the
// families each layer is responsible for; a finding counts for a layer by its producing detector, so a layer cannot cover for
// another. Family-scoped scoring (a finding of a different family in a case is counted separately, never as this family's false
// positive) is reported next to the strict number.
import { scoreLayer } from '../../../scanner/src/language/accuracy.js';
import { readJson, source, unseenSource, scanFiles, TAINT_FAMILIES, NIX_FAMILY_ALIAS, layerPredicate } from '../lib.mjs';

const score = (cases, findings, inLayer, familyScoped) => scoreLayer(cases, findings, { layer: 'custom', inLayer, lineTolerance: 1e9, familyScoped });

export async function runDetection({ split, eco, limit = 0 }) {
  const unseen = split === 'unseen';
  let cs = readJson(unseen ? 'labels/unseen.json' : 'labels/cases.json').filter((c) => c.ecosystem === eco && c.split === split);
  if (limit) cs = cs.slice(0, limit);
  const findings = []; const scored = []; const unknown = []; let advisory = 0;
  for (const c of cs) {
    const text = (unseen ? unseenSource : source)(eco, c.id, c.path);
    const r = await scanFiles({ [c.path]: text });
    const mine = r.findings.filter((f) => f.file === c.path || f.file === `./${c.path}`).map((f) => ({ ...f, file: `${c.id}/${c.path}` }));
    // `info` is advisory, not an actionable finding: counted and reported, never scored as a detection.
    const live = mine.filter((f) => f.severity !== 'info');
    advisory += mine.length - live.length;
    findings.push(...live);
    const file = `${c.id}/${c.path}`;
    if (c.label === 'unknown') {
      // Unknown/unmodeled cases are NOT binary results: the assertion is truthful uncertainty. Every case with a construct the
      // analysis cannot see (preprocessor, foreign import, Template Haskell) must come back DISCLOSED; a case with neither a
      // finding nor a disclosure is false assurance and must not exist.
      unknown.push({ id: c.id, reported: live.length, disclosed: r.disclosed, mustDisclose: /^#if|\$\(|foreign import|\{-# LANGUAGE TemplateHaskell/m.test(text) });
      continue;
    }
    const alias = eco === 'nix' ? NIX_FAMILY_ALIAS[c.family] : null;
    scored.push({ id: c.id, file, label: c.label === 'vulnerable' ? 'vuln' : 'safe', cwe: c.cwe, ...(alias ? { families: alias } : {}), expect: c.label === 'vulnerable' ? [alias ? { families: alias } : { cwe: c.cwe }] : [], family: c.family });
  }
  const layers = {};
  for (const [layer, inTaint] of [['sast', false], ['taint', true]]) {
    const lc = scored.filter((c) => TAINT_FAMILIES[eco].has(c.family) === inTaint);
    const sc = score(lc, findings, layerPredicate[layer], true);
    const strict = score(lc, findings, layerPredicate[layer], false);
    layers[layer] = { cases: sc.cases, tp: sc.tp, fp: sc.fp, fn: sc.fn, tn: sc.tn, precision: sc.precision, recall: sc.recall, f1: sc.f1, measured: sc.measured, families: sc.families, misses: sc.misses, strays: sc.strays, crossFamilyFindingsNotScored: sc.crossFamilyFindingsNotScored, strict: { fp: strict.fp, precision: strict.precision, f1: strict.f1 } };
  }
  const perFamilyCases = {};
  for (const c of cs) if (c.label !== 'unknown') { const k = (perFamilyCases[c.family] ||= { vulnerable: 0, safe: 0 }); k[c.label]++; }
  return {
    cases: cs.length, scored: scored.length, advisoryFindingsNotScored: advisory, layers, perFamilyCases,
    unknownOutcomes: {
      total: unknown.length, disclosed: unknown.filter((u) => u.disclosed).length, withFinding: unknown.filter((u) => u.reported > 0).length,
      silentClean: unknown.filter((u) => !u.disclosed && !u.reported).length,
      requiredDisclosure: unknown.filter((u) => u.mustDisclose).length, requiredDisclosureMissing: unknown.filter((u) => u.mustDisclose && !u.disclosed).length,
    },
  };
}
