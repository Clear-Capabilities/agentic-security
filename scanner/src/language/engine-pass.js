// Language supply-chain pass for the scan engine. Nix fetch/build/cache trust findings are
// supply-chain entries, so they join the ordinary `supplyChain` bucket (and from there SCA
// policy, scan health and every report) instead of a side channel. Static only: nothing here
// evaluates Nix, fetches a URL or runs a builder.

import { resolvedHackageComponents, analyzeNixClosure } from './resolved-pass.js';
import { analyzeNixBuildTrust } from './nix-build-trust.js';
import { isLanguageExcludedPath, buildImportGraph } from './discovery.js';
import { analyzeHaskellSupply } from './haskell-supply.js';
import { analyzeNixScripts } from './nix-script-taint.js';
import { analyzeNixSecrets } from './nix-secrets.js';
import { analyzeNixAgents } from './nix-agents.js';
import { analyzeNixosHardening } from './nixos-hardening.js';

const isNixSource = (p) => /\.nix$/i.test(p);
const isFlakeLock = (p) => /(^|\/)flake\.lock$/i.test(p);

/**
 * @param {Record<string,string>} files rel path -> content (sources and manifests as the engine read them)
 * @returns {{supplyChain: object[], gaps: object[], analyzed: number}}
 */
const NIXOS_OPTION = /(?:^|[\s;{])(?:services|networking|security|systemd|users|environment|programs|boot|virtualisation|nix)\.[A-Za-z_]|(?:^|[\s;{])(?:services|networking|security|systemd|users|environment|programs|boot|virtualisation)\s*=\s*\{/m;

/** NixOS entry points of a Nix file set: every configuration.nix, else every module nothing imports (capped). */
export function nixosEntries(nix, { max = 15 } = {}) {
  const conf = Object.keys(nix).filter((p) => /(?:^|\/)configuration\.nix$/i.test(p)).sort().slice(0, 5);
  const imported = new Set();
  try { const { graph } = buildImportGraph(nix); for (const deps of graph.values()) for (const d of deps) imported.add(d); } catch { /* no import graph */ }
  const standalone = Object.keys(nix).filter((p) => !conf.includes(p) && !imported.has(p) && !/(?:^|\/)flake\.nix$/i.test(p) && NIXOS_OPTION.test(nix[p])).sort().slice(0, max);
  return [...conf, ...standalone];
}

function _baseSupplyChain(files = {}, opts = {}) {
  const nix = {};
  for (const [p, text] of Object.entries(files)) {
    if (typeof text !== 'string') continue;
    if (!(isNixSource(p) || isFlakeLock(p))) continue;
    if (isLanguageExcludedPath(p)) continue;
    nix[p] = text;
  }
  // Haskell: Hackage advisories and source/name policy (manifests, a freeze or a plan, and the .hs imports).
  const hs = analyzeHaskellSupply(files, { root: opts.scanRoot || null, resolved: opts.resolved || null });
  const sources = Object.keys(nix).filter(isNixSource);
  if (!sources.length) {
    if (!hs.components.length) return { supplyChain: [], gaps: [], analyzed: 0 };
    return { supplyChain: hs.supplyChain, gaps: hs.gaps, analyzed: hs.components.length, haskell: hs };
  }
  // The effective configuration is decided from an ENTRY: configuration.nix when there is one, otherwise each NixOS module that
  // nothing imports (a flake's host file under any name). With no entry at all only the file-local rules run.
  const entries = nixosEntries(nix);
  const reports = entries.length ? entries.map((entry) => analyzeNixBuildTrust({ files: nix, entry })) : [analyzeNixBuildTrust({ files: nix })];
  const seenIds = new Set(); const merged = []; const gaps = [];
  for (const r of reports) {
    for (const f of r.findings) { const k = f.id || `${f.rule}|${f.file}|${f.line}`; if (!seenIds.has(k)) { seenIds.add(k); merged.push(f); } }
    for (const g of r.gaps) gaps.push(g);
  }
  return { supplyChain: [...hs.supplyChain, ...merged], gaps: [...hs.gaps, ...gaps], analyzed: sources.length + hs.components.length, haskell: hs };
}

/**
 * Findings (not supply-chain entries) from Nix: embedded-shell taint (NIX-003). Returns the findings plus the
 * coverage gaps (unsupported shells, scripts built by expressions) so scan health can report them.
 */
export function analyzeLanguageFindings(files = {}) {
  const nix = {};
  for (const [p, text] of Object.entries(files)) {
    if (typeof text !== 'string' || !isNixSource(p) || isLanguageExcludedPath(p)) continue;
    nix[p] = text;
  }
  if (!Object.keys(nix).length) return { findings: [], gaps: [], analyzed: 0 };
  const r = analyzeNixScripts({ files: nix });
  // secret placement sees referenced data files (sopsFile / agenix file) as well as the Nix sources
  const sec = analyzeNixSecrets({ files: { ...files, ...nix } });
  let agents = { findings: [] };
  try { agents = analyzeNixAgents(files); } catch { /* agent/MCP rules are best effort */ }
  // NIX-004: effective-configuration hardening, judged per NixOS entry point (configuration.nix). A finding with no
  // option source (a catalog default decided it) is anchored to the entry file at line 1 and says so, so it can be
  // reported, attributed and suppressed instead of being lineless. The files that decided the value travel with it.
  const hardening = [];
  const effective = [];
  // Entry points: every configuration.nix, plus NixOS modules NOTHING imports (a standalone module, a flake's host file under any
  // name): its options are the only place their values are decided, and a file name is not what makes a configuration real.
  const confEntries = Object.keys(nix).filter((p) => /(?:^|\/)configuration\.nix$/i.test(p)).sort().slice(0, 5);
  const entryList = nixosEntries(nix);
  for (const entry of entryList) {
    try {
      const h = analyzeNixosHardening({ entry, files: nix });
      effective.push({ entry, completeness: h.reconciliation && h.reconciliation.completeness, unresolved: (h.reconciliation && h.reconciliation.unanalyzed) || [], truncated: [], target: h.target });
      for (const f of h.findings) {
        const ctl = [...new Set((f.evidence || []).flatMap((e) => (e.sources || []).map((x) => x.file)).filter(Boolean))];
        const anchored = Number.isInteger(f.line) && f.file;
        hardening.push({ ...f, file: anchored ? f.file : entry, line: anchored ? f.line : 1, locationKind: anchored ? 'option-source' : 'target-level', controlFiles: ctl, entry, entryKind: confEntries.includes(entry) ? 'configuration' : 'standalone-module', optionEvidence: f.evidence, option: f.evidence && f.evidence[0] ? f.evidence[0].option : null });
      }
    } catch (e) { r.gaps.push({ kind: 'hardening-failed', file: entry, reason: String((e && e.message) || e) }); }
  }
  // Two different rules of one family can land on the same line (a one-line configuration, or several defaults that
  // anchor at the entry). The engine's per-(file, line, family) de-duplication must not merge them into one finding, so
  // each carries a site key built from what makes it a different finding. The key also feeds the stable id.
  const keyed = (list, parts) => list.map((f) => (f && f.siteKey ? f : { ...f, siteKey: parts(f).filter((x) => x !== null && x !== undefined && x !== '').join('|') }));
  const out = [
    ...keyed(r.findings, (f) => [f.rule, f.attrPath, f.sink && f.sink.command, f.generatedLocation && `${f.generatedLocation.line}:${f.generatedLocation.startColumn}`]),
    ...keyed(sec.findings, (f) => [f.rule, f.source && f.source.detail, f.destination && f.destination.label]),
    ...agents.findings,
    ...keyed(hardening, (f) => [f.rule, f.subject]),
  ];
  return { findings: out, gaps: [...r.gaps, ...sec.gaps], analyzed: r.analyzed, effectiveConfigs: effective };
}

/**
 * The language supply chain: declared and resolved Hackage dependencies, Nix inputs and build trust, and (when the project exported
 * one) the Nix closure matched against an advisory snapshot. The resolved data comes from EXPLICIT export files only.
 */
export function analyzeLanguageSupplyChain(files = {}, opts = {}) {
  let resolved = null; let closure = null;
  try { resolved = resolvedHackageComponents(files); } catch { resolved = null; }
  try { closure = analyzeNixClosure(files, { scanRoot: opts.scanRoot || null }); } catch (e) { closure = { findings: [], gaps: [{ kind: 'closure-analysis-failed', detail: String((e && e.message) || e).slice(0, 160) }], statuses: [], sources: [], status: 'failed' }; }
  const base = _baseSupplyChain(files, { ...opts, resolved });
  if (!closure) return resolved && resolved.summary ? { ...base, resolved: resolved.summary } : base;
  return { ...base, supplyChain: [...base.supplyChain, ...closure.findings], gaps: [...(base.gaps || []), ...closure.gaps], analyzed: (base.analyzed || 0) + closure.statuses.length, resolved: resolved && resolved.summary, nixClosure: closure };
}
