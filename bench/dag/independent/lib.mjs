import crypto from 'node:crypto';
export const canonicalLabels = (labels) => [...labels].sort((a, b) => a.id.localeCompare(b.id)).map(l => ({
  id: l.id, project: l.project, language: l.language, file: l.file, line: l.line, vuln: l.vuln, verdict: l.verdict, evidence: l.evidence }));
export const digestOf = (labels) => crypto.createHash('sha256').update(JSON.stringify(canonicalLabels(labels))).digest('hex');
export function wilson(k, n, z = 1.959964) {
  if (n === 0) return null;
  const p = k / n, d = 1 + z * z / n, c = p + z * z / (2 * n), m = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return [Math.max(0, (c - m) / d), Math.min(1, (c + m) / d)];
}
