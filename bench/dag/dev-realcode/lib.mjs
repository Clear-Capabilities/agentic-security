// Shared by sample.mjs, score.mjs, worklist.mjs and bench/realcode-precision/runner.mjs. Importing this file runs nothing.
export const TAINT_PARSERS = new Set(['IR-TAINT', 'MULTI-SINK']);
export const stratumOf = (vuln, cwe) => (cwe ? String(cwe) : (/^Path Traversal/i.test(vuln || '') ? 'path-traversal' : String(vuln || '').replace(/\s*\(.*$/, '').slice(0, 60)));
export const siteKey = (project, r) => `${project}:${r.file}:${r.line}:${stratumOf(r.vuln, r.cwe)}`;
