// Language metadata for findings the taint engine emits over Haskell IR. The engine is
// language-neutral; this adds the additive contract fields (language, capability, analysisKind,
// evidenceKind, originalLocation, model version) and a stable family from the CWE, so a Haskell
// finding is distinguishable, filterable and compliance-mappable without a second finding schema.

import { HS_MODEL_VERSION } from './haskell-models.js';

const HS_FILE = /\.(?:hs|lhs|hsc)$/i;

// CWE -> the family vocabulary the compliance maps and reports already use.
export const HS_FAMILY_BY_CWE = Object.freeze({
  'CWE-78': 'command-injection',
  'CWE-88': 'argument-injection',
  'CWE-22': 'path-traversal',
  'CWE-89': 'sql-injection',
  'CWE-918': 'ssrf',
  'CWE-79': 'xss',
});

export const isHaskellFile = (file) => typeof file === 'string' && HS_FILE.test(file);

/**
 * Mutates and returns the array: stamps every IR-TAINT finding located in a Haskell file.
 * `fileContents` (path -> text) supplies the original source line as the finding's snippet. Without
 * it two findings of one rule in one file share a stable id (the id is derived from rule + snippet +
 * path shape), which silently merges their triage state and sanitizer evidence.
 */
export function annotateHaskellFindings(findings, fileContents = null) {
  for (const f of findings || []) {
    if (!f || !isHaskellFile(f.file)) continue;
    if (!f.snippet && fileContents && typeof fileContents[f.file] === 'string' && Number.isInteger(f.line) && f.line >= 1) {
      const text = fileContents[f.file].split('\n')[f.line - 1];
      if (typeof text === 'string') f.snippet = text.trim().slice(0, 240);
    }
    f.language = 'haskell';
    f.capability = f.capability || 'taint';
    f.analysisKind = f.analysisKind || 'application';
    f.evidenceKind = f.evidenceKind || 'source';
    f.modelVersion = HS_MODEL_VERSION;
    if (HS_FAMILY_BY_CWE[f.cwe]) f.family = HS_FAMILY_BY_CWE[f.cwe];
    if (Number.isInteger(f.line) && f.line >= 1) f.originalLocation = { file: f.file, line: f.line, column: 0 };
  }
  return findings;
}
