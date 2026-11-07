// Equivalent detector claims (PRD FR 05 validation flow, FR 07 "group multiple detector claims without merging independent sinks").
//
// Two detectors often report the same weakness at the same place: a regex rule and a language analyzer both see `pickle.loads(x)`,
// a structural rule and a password-hash rule both see `createHash('md5')` on a password. Shown twice, one weakness is counted twice
// and reviewed twice. Grouped, it is one actionable result that names every detector that found it.
//
// Claims are equivalent only when ALL of these hold:
//   - same report category (kind), same file, same integer line, same CWE
//   - neither is a composite (chain) claim
//   - different detectors (parser). Two claims from ONE detector at one line are two findings it chose to emit (two calls, two
//     sources), so they are never merged here.
//   - neither names a sink line the other contradicts (independent sinks stay apart)
//   - neither is a dependency finding
// The primary is the claim that locates the most of the path (source and sink, then the sink alone), then one the IR taint engine
// produced over a lexical rule, then the highest severity, then the lowest id, so the choice is deterministic. Nothing is deleted: every grouped claim is returned for the raw export, pointing at its primary.

const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// A composite claim (an attack chain, an agent chain) asserts that several weaknesses combine; it is never the same claim as one of
// its hops, even where it is anchored on that hop's line.
const isComposite = (f) => Array.isArray(f.chain) || f.parser === 'CHAIN' || /chain/i.test(String(f.family || ''));

function groupKey(f) {
  if (!f || typeof f !== 'object' || f.kind === 'sca' || f.type === 'vulnerable_dep' || isComposite(f)) return null;
  if (!Number.isInteger(f.line) || f.line <= 0 || !f.file || !f.cwe) return null;
  return `${f.kind || 'sast'}\0${f.file}\0${f.line}\0${f.cwe}`;
}

// How much of the path a claim locates (both ends, the sink alone, or neither), then whether the IR taint engine located it
// (semantic) or a lexical rule did. A reviewer starts from the claim that points at the most code.
const IR_TRACED = new Set(['IR-TAINT', 'MULTI-SINK', 'IR-PRIVACY-TAINT']);
const located = (f) => (f.source && f.sink ? 2 : f.sink ? 1 : 0);

function rank(a, b) {
  const l = located(b) - located(a);
  if (l) return l;
  const p = (IR_TRACED.has(b.parser) ? 1 : 0) - (IR_TRACED.has(a.parser) ? 1 : 0);
  if (p) return p;
  const s = (SEV[b.severity] ?? -1) - (SEV[a.severity] ?? -1);
  if (s) return s;
  return String(a.stableId || a.id || '').localeCompare(String(b.stableId || b.id || ''));
}

const sinkLine = (f) => (f.sink && Number.isInteger(f.sink.line) ? f.sink.line : null);

const claimOf = (f) => ({ id: f.id ?? null, stableId: f.stableId ?? null, parser: f.parser ?? null, vuln: f.vuln ?? null, severity: f.severity ?? null });

/**
 * Group equivalent claims. Returns { kept, grouped, groups } where `kept` is the input order with grouped members removed, `grouped`
 * holds each removed claim (annotated `groupedInto`), and `groups` counts the groups formed. The primary gains `claims` (every
 * claim in its group, itself first). Severity and confidence are never changed.
 */
export function groupEquivalentClaims(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const byKey = new Map();
  for (const f of list) {
    const k = groupKey(f);
    if (k === null) continue;
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(f);
  }
  const drop = new Set();
  const grouped = [];
  let groups = 0;
  for (const members of byKey.values()) {
    if (members.length < 2) continue;
    const sorted = [...members].sort(rank);
    const primary = sorted[0];
    const taken = [primary];
    const seenParsers = new Set([primary.parser]);
    for (const m of sorted.slice(1)) {
      if (seenParsers.has(m.parser)) continue;
      const a = sinkLine(primary); const b = sinkLine(m);
      if (a !== null && b !== null && a !== b) continue;
      seenParsers.add(m.parser);
      taken.push(m);
    }
    if (taken.length < 2) continue;
    groups++;
    primary.claims = taken.map(claimOf);
    for (const m of taken.slice(1)) {
      m.groupedInto = primary.stableId || primary.id || null;
      drop.add(m);
      grouped.push(m);
    }
  }
  return { kept: list.filter((f) => !drop.has(f)), grouped, groups };
}

/**
 * One reconciliation of the candidate counts, so no candidate is counted twice:
 *   raw = grouped + refuted + (confirmed + needs-review + hardening + unvalidated)
 * `suppressed` counts candidates removed before this stage (pragmas, rules, accepted risk); it is reported beside raw, not inside it.
 */
export function reconcileCounts({ raw, grouped, refuted, dispositionCounts, suppressed = 0 }) {
  const d = dispositionCounts || {};
  const active = ['confirmed', 'needs-review', 'hardening', 'unvalidated'].reduce((n, k) => n + (d[k] || 0), 0);
  const out = {
    raw, grouped, refuted, deduplicated: raw - grouped,
    confirmed: d.confirmed || 0, needsReview: d['needs-review'] || 0, hardening: d.hardening || 0, unvalidated: d.unvalidated || 0,
    suppressedBeforeValidation: suppressed,
  };
  out.balanced = raw === grouped + refuted + active;
  return out;
}
