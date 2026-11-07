// Report view over dispositions (PRD FR 09). Display only: it reads a scan and
// returns groups and counts, and never changes stored findings, so hiding a
// category here cannot mark anything assessed or imply remediation. Raw and
// displayed counts reconcile: raw = shown + every hidden bucket.

import { DISPOSITIONS as D } from '../llm-validator/disposition.js';

export const VIEW_SCHEMA = 'report-view/1';
export const EXCLUDABLE_KINDS = Object.freeze(['sca', 'generated', 'secrets', 'logic']);

const LANG_BY_EXT = { js: 'javascript', mjs: 'javascript', cjs: 'javascript', ts: 'typescript', tsx: 'typescript', jsx: 'javascript', py: 'python', java: 'java', go: 'go', rb: 'ruby', rs: 'rust', cs: 'csharp', kt: 'kotlin', php: 'php', hs: 'haskell', lhs: 'haskell', nix: 'nix', yml: 'yaml', yaml: 'yaml', tf: 'terraform' };
export function languageOf(file) {
  const m = /\.([A-Za-z0-9]+)$/.exec(String(file || ''));
  return (m && LANG_BY_EXT[m[1].toLowerCase()]) || 'other';
}

const GENERATED = /(?:^|\/)(?:dist|build|buck-out|dist-newstyle|\.stack-work|generated|gen)\//i;

function groupOf(f) {
  const d = f.disposition;
  if (d === D.CONFIRMED) return 'confirmed';
  if (d === D.HARDENING) return 'hardening';
  if (d === D.REFUTED) return 'history';
  if (d === D.NEEDS_REVIEW) return 'needsReview';
  return 'unvalidated';
}

/** Parse `--exclude-kind sca,generated` style values. Returns { kinds, errors }. */
export function parseExcludeKinds(v) {
  const kinds = []; const errors = [];
  for (const k of String(v ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
    if (EXCLUDABLE_KINDS.includes(k)) kinds.push(k); else errors.push(`--exclude-kind: unknown kind "${k}" (known: ${EXCLUDABLE_KINDS.join(', ')})`);
  }
  return { kinds, errors };
}

/**
 * @param {object} scan
 * @param {{excludeKinds?: string[], filters?: {category?: string, language?: string, package?: string, path?: string, disposition?: string, minConfidence?: number}}} [o]
 */
export function buildDispositionView(scan, { excludeKinds = [], filters = {} } = {}) {
  const buckets = [
    ['code', scan.findings || [], null],
    ['secrets', scan.secrets || [], 'secrets'],
    ['logic', scan.logicVulns || [], 'logic'],
    ['sca', scan.supplyChain || [], 'sca'],
  ];
  const hidden = { byKind: {}, byFilter: 0 };
  const groups = { confirmed: [], needsReview: [], unvalidated: [], hardening: [], history: [] };
  let raw = 0;
  for (const [bucket, items, kind] of buckets) {
    for (const f of items) {
      raw++;
      const isSca = bucket === 'sca';
      const k = kind || (GENERATED.test(String(f.file || '')) ? 'generated' : null);
      if (k && excludeKinds.includes(k)) { hidden.byKind[k] = (hidden.byKind[k] || 0) + 1; continue; }
      if (filters.category && String(f.family || f.category || '') !== filters.category) { hidden.byFilter++; continue; }
      if (filters.language && languageOf(f.file) !== filters.language) { hidden.byFilter++; continue; }
      if (filters.package && String(f.package || f.component || f.name || '') !== filters.package) { hidden.byFilter++; continue; }
      if (filters.path && !String(f.file || '').startsWith(filters.path)) { hidden.byFilter++; continue; }
      if (filters.disposition && (isSca ? 'unvalidated' : groupOf(f)) !== filters.disposition && f.disposition !== filters.disposition) { hidden.byFilter++; continue; }
      if (typeof filters.minConfidence === 'number' && (typeof f.confidence === 'number' ? f.confidence : 1) < filters.minConfidence) { hidden.byFilter++; continue; }
      groups[isSca ? 'unvalidated' : groupOf(f)].push(f);
    }
  }
  // Refuted findings were moved to the suppression ledger by the engine; they appear as history.
  for (const s of scan.suppressions || []) if (s && s.disposition === D.REFUTED) groups.history.push(s);
  const counts = Object.fromEntries(Object.entries(groups).map(([k, v]) => [k, v.length]));
  // History comes from the ledger, not from the live buckets, so it is outside the raw/shown reconciliation.
  const shown = counts.confirmed + counts.needsReview + counts.unvalidated + counts.hardening;
  const hiddenTotal = Object.values(hidden.byKind).reduce((a, b) => a + b, 0) + hidden.byFilter;
  return {
    schema: VIEW_SCHEMA,
    excludeKinds: [...excludeKinds],
    filters: { ...filters },
    counts,
    actionable: counts.confirmed + counts.needsReview,
    raw, shown, hidden,
    reconciles: raw === shown + hiddenTotal,
    note: hiddenTotal ? 'Hidden items are still stored in the scan and are not assessed or remediated by hiding them.' : null,
  };
}

export function viewLine(v) {
  if (!v) return null;
  const hid = Object.entries(v.hidden.byKind).map(([k, n]) => `${n} ${k}`);
  if (v.hidden.byFilter) hid.push(`${v.hidden.byFilter} filtered`);
  return `Findings: ${v.counts.confirmed} confirmed, ${v.counts.needsReview} needs review, ${v.counts.unvalidated} unvalidated, ${v.counts.hardening} hardening advice, ${v.counts.history} refuted history`
    + (hid.length ? `; hidden from this view (still stored, not assessed): ${hid.join(', ')}` : '');
}
