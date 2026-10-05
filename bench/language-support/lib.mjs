// Shared pieces of the Haskell/Nix support measurement (PRD section 9). Everything here reads the QA-001 corpus under
// scanner/test/language/corpora/data and calls the REAL engine; the engine never reads the corpus (a test enforces that).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

// Every scan here is of a scratch directory, and a measurement must never leave state in what it measured.
await disableStateWrites();

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.join(HERE, '..', '..');
export const DATA = path.join(REPO, 'scanner', 'test', 'language', 'corpora', 'data');
export const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
export const read = (p) => fs.readFileSync(p, 'utf8');
export const readJson = (rel) => JSON.parse(read(path.join(DATA, rel)));
export const source = (eco, id, rel) => read(path.join(DATA, 'sources', eco, id, rel));
/** Unseen-shape cases live in their own directory, so no existing label file or source directory changes. */
export const unseenSource = (eco, id, rel) => read(path.join(DATA, 'sources-unseen', eco, id, rel));
/** The shape-dev set (the former unseen-v1, used to change the engine): same layout, its own directory. */
export const shapeDevSource = (eco, id, rel) => read(path.join(DATA, 'sources-shape-dev', eco, id, rel));

// Which layer is RESPONSIBLE for a family: declared here, never derived from engine output (see measure.mjs README).
export const TAINT_FAMILIES = {
  haskell: new Set(['sql-injection', 'command-injection', 'path-traversal', 'ssrf', 'html-injection']),
  nix: new Set(['script-interpolation']),
};
// Nix: a detector's family vocabulary -> the corpus family it answers. Declared from the detectors' published family names.
export const NIX_FAMILY_ALIAS = {
  'script-interpolation': ['cmdi'], 'secret-in-store': ['hardcoded-secret'], 'unpinned-source': ['nix-fetch-integrity', 'nix-fetch-pin'],
  'binary-cache-trust': ['nix-cache-trust'], 'trusted-users': ['nix-privilege'], 'native-eval': ['nix-eval-native'], 'sandbox-trust': ['nix-sandbox'],
  'ssh-access': ['ssh-access'], 'service-privilege': ['service-identity', 'systemd-privilege'], 'firewall-exposure': ['firewall-exposure'],
  'privilege-escalation-policy': ['privilege-escalation'], 'tls-secret-runtime': ['tls-runtime'],
};
export const TAINT_PARSERS = new Set(['IR-TAINT', 'NIX-SCRIPT']);
export const NON_SAST_PARSERS = new Set(['IR-TAINT', 'NIX-SCRIPT', 'LINEAGE', 'SECRET-CONCAT', 'SECRET-DEPURL', 'HS-SUPPLY', 'NIX-SCA', 'HS-LLM', 'NIX-AGENT']);
export const layerPredicate = { taint: (f) => TAINT_PARSERS.has(f.parser), sast: (f) => !NON_SAST_PARSERS.has(f.parser) };

/** Writes `files` (rel path -> text) to a scratch directory, scans it, removes it. */
export async function scanFiles(files, opts = {}) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'lsm-')));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    for (const [rel, text] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), text); }
    const r = await runScan(dir, { deep: true, ...opts });
    const all = [...(r.scan.findings || []), ...(r.scan.secrets || []), ...(r.scan.supplyChain || []).filter((f) => f && f.cwe)];
    const lc = (r.scan.scanHealth && r.scan.scanHealth.languageCoverage) || {};
    const disclosed = Boolean((lc.totals && (lc.totals.unresolved || lc.totals.failed || lc.totals.timedOut || lc.totals.missingGrammar)) || (lc.limitations && lc.limitations.length) || (lc.conditions && lc.conditions.length));
    return { findings: all, scan: r.scan, disclosed };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

/** Does `f` answer the corpus family `family` of ecosystem `eco`? (alias table for Nix, CWE for Haskell) */
export function answers(eco, family, cwe, f) {
  if (eco === 'nix') return (NIX_FAMILY_ALIAS[family] || []).includes(f.family);
  return f.cwe === cwe;
}
export const actionable = (f) => f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict));
