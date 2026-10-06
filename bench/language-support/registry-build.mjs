// Pure builders for the support registry and its rendered table: shared by promote.mjs (which writes them) and check.mjs (which
// recomputes them from the stored measurement and fails on any difference).
import { evaluateSupport, checkPromotion, verifyRegistry, SUPPORT_REGISTRY_VERSION, TARGETS, PAIR_GATE } from '../../scanner/src/language/support-registry.js';
import { HS_PACKAGES, HS_WEB_FRAMEWORKS } from '../../scanner/src/language/haskell-models.js';

export const LIMITS = Object.freeze([
  'The corpus is synthetic and template-generated (QA-001): holdout cases vary nouns, fields and paths over the SAME shapes as the development cases, so a holdout score measures robustness to those variations, not accuracy on arbitrary real-world code.',
  'No real-world canary projects and no real advisory records beyond the pinned HSEC fixtures are in the measurement: real-project accuracy is NOT measured.',
  'No GHC, cabal, stack or nix is installed where the measurement ran: compile-based verification, optional Nix evaluation and any NixOS host behaviour are blocked, never reported as passing.',
  'Findings of a different family inside a case are reported separately (family-scoped scoring); the strict precision, which counts them, is stored next to every layer.',
  'Parameters of an exported Haskell function are treated as caller-controlled text or customer records: a flow from such a parameter is reported with that source label, which is a weaker claim than a request or stdin read.',
]);

/** The limits that depend on what was and was not available where the measurement ran. */
function limitsFor(tools, unseen) {
  const out = [...LIMITS].filter((l) => !/^No GHC, cabal, stack or nix is installed/.test(l));
  const missing = ['ghc', 'cabal', 'stack', 'nix', 'nixos'].filter((t) => !tools[t]);
  out.splice(2, 0, missing.length
    ? `Not available where the measurement ran: ${missing.join(', ')}. Capabilities that need them are blocked, never reported as passing.${tools.ghc ? ' GHC was present, so the Haskell route fixtures were compiled.' : ''}`
    : 'Every tool the capabilities need was available where the measurement ran.');
  out.push(unseen
    ? 'The "supported" status is defined on the frozen holdout (section 9.2 of the PRD). Shapes that no other split contains (the unseen-v2 split: 3 vulnerable and 3 safe single-flaw code forms per family, author-labelled, written after the fixes the earlier set motivated, measured once and never tuned against) are reported beside it, with intervals over shapes (two near-identical cases per shape). Where they fall below the same targets the row says so. The earlier unseen-v1 set was used to change the engine and is a development set (shape-dev), not a generalisation measure.'
    : 'No unseen-shape measurement is recorded: the holdout score says nothing about code shapes the templates did not contain.');
  return out;
}

/** @returns {{registry: object, allSupported: boolean}} */
export function buildRegistry(measurement, suites, frozen, probe, unseen = null) {
  const tools = suites.tools || probe || {};
  const registry = { schema: 'agentic-security/language-support@1', version: SUPPORT_REGISTRY_VERSION, generatedAt: measurement.measuredAt, node: suites.node, targets: TARGETS, pairGate: PAIR_GATE, languages: {} };
  let allSupported = true;
  for (const language of ['haskell', 'nix']) {
    const evaluated = evaluateSupport(language, { measurement, suites: suites.results, capabilitySuites: suites.capabilitySuites[language], tools, frozen, unseen });
    const rows = {};
    for (const [cap, r] of Object.entries(evaluated.rows)) {
      const check = checkPromotion(language, cap, r.status, r.evidence, evaluated);
      if (!check.ok) { r.status = 'unverified'; r.reasons = [...r.reasons, ...check.reasons]; }
      rows[cap] = r;
    }
    allSupported = allSupported && Object.values(rows).every((r) => r.status === 'supported');
    const eco = measurement.ecosystems[language] || {};
    registry.languages[language] = {
      frozen, measuredOn: { split: measurement.split, measuredAt: measurement.measuredAt, corpusVersion: measurement.corpusVersion, hashes: measurement.hashes, corpusTotals: measurement.corpusTotals[language] },
      rows, summary: evaluated.summary, generalizationGaps: evaluated.generalizationGaps || [], metamorphic: evaluated.metamorphic || null,
      unknownOutcomes: eco.detection ? eco.detection.unknownOutcomes : null,
      modelledVersions: language === 'haskell' ? { packages: Object.fromEntries(Object.entries(HS_PACKAGES).map(([k, v]) => [k, v.tested])), webFrameworks: Object.fromEntries(Object.entries(HS_WEB_FRAMEWORKS).map(([k, v]) => [k, v.tested])) } : null,
    };
  }
  registry.tools = tools;
  registry.generalization = unseen ? { split: 'unseen', measuredAt: unseen.measuredAt, corpusVersion: unseen.corpusVersion, unseenRollup: unseen.unseenRollup || null } : null;
  registry.limits = limitsFor(tools, unseen);
  registry.verified = verifyRegistry(registry, frozen);
  return { registry, allSupported };
}

const pct = (x) => (x == null ? 'n/a' : `${(x * 100).toFixed(1)}%`);

export function renderTable(registry) {
  const first = Object.values(registry.languages)[0];
  const lines = ['# Haskell and Nix support', '', `Generated by \`node bench/language-support/promote.mjs\` from the frozen holdout (corpus ${first.frozen.corpusVersion}, measured ${registry.generatedAt}). Do not edit by hand.`, '', 'A row is **supported** only from passing evidence of its own metric kind. Read the limits below before quoting any number.', ''];
  for (const [lang, entry] of Object.entries(registry.languages)) {
    lines.push(`## ${lang === 'haskell' ? 'Haskell' : 'Nix and NixOS'}`, '', '| Capability | Status | Evidence on the frozen holdout (95% intervals) | Unseen shapes | Why not supported |', '|---|---|---|---|---|');
    for (const r of Object.values(entry.rows)) {
      const e = r.evidence || {};
      const ev = e.precision !== undefined ? `P ${pct(e.precision)} / R ${pct(e.recall)} / F1 ${pct(e.f1)} (${e.tp ?? '?'} TP, ${e.fp ?? '?'} FP, ${e.fn ?? '?'} FN)` : e.manifests ? `manifests ${e.manifests}; advisory ranges ${e.advisoryRanges ?? 'n/a'}` : e.accepted ? `accepted ${e.accepted}; rejected ${e.rejected}; advertised ${e.advertised}` : e.parsed !== undefined ? `${e.parsed}/${e.files} parsed; ${e.crashed} crashed` : '';
      const iv = e.ci ? ` [P ${pct(e.ci.precision && e.ci.precision[0])}-${pct(e.ci.precision && e.ci.precision[1])}, R ${pct(e.ci.recall && e.ci.recall[0])}-${pct(e.ci.recall && e.ci.recall[1])}]` : '';
      const strict = e.strictPrecision != null ? `; strict P ${pct(e.strictPrecision)}` : '';
      const g = r.generalization;
      const gen = !g ? '' : g.status === 'not-measured' ? 'not measured' : `${g.status === 'below-target' ? 'BELOW TARGET' : 'meets targets'}: P ${pct(g.precision)} / R ${pct(g.recall)} / F1 ${pct(g.f1)} (${g.tp} TP, ${g.fp} FP, ${g.fn} FN)`;
      lines.push(`| ${r.capability} | ${r.status} | ${ev}${iv}${strict} | ${gen} | ${(r.reasons || []).slice(0, 2).join('; ').replace(/\|/g, '/')} |`);
    }
    const u = entry.unknownOutcomes;
    lines.push('', `Unknown and unmodelled cases: ${u ? `${u.total} total, ${u.silentClean} silent-clean (false assurance), ${u.requiredDisclosureMissing} undisclosed required boundary` : 'not measured'}.`);
    if (entry.metamorphic) lines.push(`Metamorphic pairs: semantics-changing ${pct(entry.metamorphic.change)}, semantics-preserving ${pct(entry.metamorphic.preserve)} (this project's own gate; the PRD sets none).`);
    lines.push('');
  }
  lines.push('## Limits', '', ...registry.limits.map((l) => `- ${l}`), '');
  return `${lines.join('\n')}\n`;
}
