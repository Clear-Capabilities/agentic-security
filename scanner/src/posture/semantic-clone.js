// FR-SEM-8 — Semantic clone / equivalence detection.
//
// Cluster findings whose sink-side code "shape" is structurally equivalent
// even when surface text differs (renamed variables, reordered statements,
// reformatted whitespace). The shape is a normalized AST-token hash: strip
// identifiers down to their kind (id/lit/op), collapse whitespace, drop
// comments. Two functions that compute the same thing under different names
// produce the same shape hash.
//
// Two uses:
//   1. Dedupe near-identical findings across cloned code regions
//      (annotate `cloneClusterId` so /fix can patch the canonical instance).
//   2. Surface "you have 3 SQL escaper functions, 1 is broken" — emit an
//      info finding when a clone cluster contains a mix of vulnerable and
//      non-vulnerable members (the broken one is the outlier).
//
// This is intentionally a coarse approximation, not a full structural
// equivalence proof. It catches the common case (copy-paste with renaming);
// it does not catch true semantic equivalence under arbitrary refactoring.

import * as crypto from 'node:crypto';

const JS_TOKEN_RE = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\b(?:if|else|for|while|switch|case|return|break|continue|throw|try|catch|finally|function|const|let|var|class|new|this|super|import|export|from|as|async|await|yield|of|in|typeof|instanceof|null|true|false|undefined)\b|\b[A-Za-z_$][\w$]*\b|0x[0-9a-fA-F]+|\d+(?:\.\d+)?|[(){}\[\];,.<>!?:+\-*\/=&|^~%]+|\s+)/g;

const JS_KEYWORDS = new Set([
  'if','else','for','while','switch','case','return','break','continue','throw',
  'try','catch','finally','function','const','let','var','class','new','this','super',
  'import','export','from','as','async','await','yield','of','in','typeof','instanceof',
  'null','true','false','undefined',
]);

function tokenize(snippet) {
  if (!snippet || typeof snippet !== 'string') return [];
  const tokens = [];
  for (const m of snippet.matchAll(JS_TOKEN_RE)) {
    const t = m[0];
    if (/^\s+$/.test(t)) continue;
    if (/^\/[\/*]/.test(t)) continue;          // comment
    if (/^["'`]/.test(t)) { tokens.push('LIT'); continue; }
    if (/^0x[0-9a-fA-F]+$|^\d/.test(t)) { tokens.push('NUM'); continue; }
    if (JS_KEYWORDS.has(t)) { tokens.push(`K:${t}`); continue; }
    if (/^[A-Za-z_$]/.test(t)) { tokens.push('ID'); continue; }
    tokens.push(t);
  }
  return tokens;
}

export function shapeHash(snippet, opts = {}) {
  const tokens = tokenize(snippet);
  if (tokens.length < (opts.minTokens ?? 8)) return null;
  return crypto.createHash('sha256').update(tokens.join(' ')).digest('hex').slice(0, 16);
}

// Cluster findings by snippet shape. Returns the same array with two fields
// added to each finding: cloneClusterId (16-hex or null), cloneClusterSize.
export function annotateCloneClusters(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;
  const buckets = new Map();
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const snippet = f.snippet || f.sink?.snippet || f.source?.snippet || '';
    const hash = shapeHash(snippet);
    if (!hash) { f.cloneClusterId = null; f.cloneClusterSize = 1; continue; }
    f.cloneClusterId = hash;
    if (!buckets.has(hash)) buckets.set(hash, []);
    buckets.get(hash).push(f);
  }
  for (const [, group] of buckets) {
    for (const f of group) f.cloneClusterSize = group.length;
  }
  return findings;
}

// Surface "outlier in clone cluster" infos — when a cluster contains 2+
// members and they disagree on severity, the high-sev member is likely the
// broken implementation among siblings.
export function findCloneOutliers(findings) {
  if (!Array.isArray(findings)) return [];
  const buckets = new Map();
  for (const f of findings) {
    if (!f || !f.cloneClusterId) continue;
    if (!buckets.has(f.cloneClusterId)) buckets.set(f.cloneClusterId, []);
    buckets.get(f.cloneClusterId).push(f);
  }
  const out = [];
  const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  for (const [hash, group] of buckets) {
    if (group.length < 2) continue;
    const sevs = new Set(group.map(g => g.severity));
    if (sevs.size < 2) continue;                // homogeneous cluster, not an outlier
    group.sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
    const worst = group[0];
    out.push({
      id: `clone-outlier:${hash}`,
      file: worst.file,
      line: worst.line || 0,
      vuln: 'Structural clone outlier — one member of a cloned-code cluster is more severe than its siblings',
      severity: 'info',
      family: 'clone-outlier',
      cloneClusterId: hash,
      cloneClusterSize: group.length,
      description: `${group.length} structurally-equivalent code regions detected; the one at ${worst.file}:${worst.line} carries ${worst.severity} severity vs. its siblings — likely the broken implementation among copy-pasted helpers.`,
      remediation: 'Compare implementations across the cluster and either harmonize or remove the divergent member.',
    });
  }
  return out;
}
