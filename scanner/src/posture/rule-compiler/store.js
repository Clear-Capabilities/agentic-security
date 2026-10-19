// Persistence for the rule compiler: one directory per rule under `.agentic-security/rule-compiler/<id>/`
// (`ir.json`, `ledger.json`, `evaluation.json`), the promoted custom-rule document at
// `.agentic-security/rules/<id>.yml` (so the EXISTING `loadCustomRules`/`rule test` machinery picks it up with no
// change), and a regression fixture pair at `.agentic-security/rule-compiler/fixtures/<id>/{vulnerable,clean}/`
// using the SAME filename convention `runRuleTests` already reads (`vulnerable`/`clean` in the path).
import fs from 'node:fs';
import path from 'node:path';
import { statePath, ensureStateDir, safeWriteState } from '../state-dir.js';
import { newLedger, verifyLedger } from './lifecycle.js';
import { compileToCustomRule } from './ir.js';
import { verifyRulePack, loadTrustedKeys, signRulePack } from '../rule-pack-signing.js';

const DIR = 'rule-compiler';
const EXT = { javascript: 'js', typescript: 'ts', python: 'py', go: 'go', ruby: 'rb', java: 'java', rust: 'rs', csharp: 'cs', php: 'php', any: 'txt' };

function ruleDir(scanRoot, id) { return statePath(scanRoot, DIR, id); }

export function loadLedger(scanRoot) {
  const f = statePath(scanRoot, DIR, 'ledger.json');
  if (!fs.existsSync(f)) return newLedger();
  try {
    const ledger = JSON.parse(fs.readFileSync(f, 'utf8'));
    const v = verifyLedger(ledger);
    return v.ok ? ledger : { ...newLedger(), tampered: true, tamperReason: v.reason };
  } catch { return newLedger(); }
}

export function saveLedger(scanRoot, ledger) {
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = statePath(scanRoot, DIR, 'ledger.json');
  return { ok: safeWriteState(f, JSON.stringify(ledger, null, 2)) };
}

export function saveIR(scanRoot, ir) {
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = path.join(ruleDir(scanRoot, ir.id), 'ir.json');
  return { ok: safeWriteState(f, JSON.stringify(ir, null, 2)), file: f };
}

export function loadIR(scanRoot, id) {
  const f = path.join(ruleDir(scanRoot, id), 'ir.json');
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

function saveJson(scanRoot, id, name, doc) {
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = path.join(ruleDir(scanRoot, id), name);
  return { ok: safeWriteState(f, JSON.stringify(doc, null, 2)), file: f };
}
function loadJson(scanRoot, id, name) { try { return JSON.parse(fs.readFileSync(path.join(ruleDir(scanRoot, id), name), 'utf8')); } catch { return null; } }
/** The corpus a rule was synthesized on, kept so `rules evaluate <id>` needs no flag and the evidence is the same corpus. */
export const saveCorpus = (r, id, spec) => saveJson(r, id, 'corpus.json', spec);
export const loadCorpus = (r, id) => loadJson(r, id, 'corpus.json');
/** Every synthesis attempt: strategy, match, score and why it did not pass. */
export const saveSynthesis = (r, id, syn) => saveJson(r, id, 'synthesis.json', syn);
export const loadSynthesis = (r, id) => loadJson(r, id, 'synthesis.json');
/** The rule's provenance record (PRD 3 requirement 7). */
export const saveProvenance = (r, id, doc) => saveJson(r, id, 'provenance.json', doc);
export const loadProvenance = (r, id) => loadJson(r, id, 'provenance.json');

export function saveEvaluation(scanRoot, id, evaluation) {
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = path.join(ruleDir(scanRoot, id), 'evaluation.json');
  return { ok: safeWriteState(f, JSON.stringify(evaluation, null, 2)) };
}

/** Write the regression fixtures a promoted rule needs: the SAME vulnerable/clean convention `runRuleTests`
 * already reads, scored against the exact corpus the rule was promoted on. */
export function writeFixtures(scanRoot, ir, corpus) {
  const ext = EXT[ir.languages[0]] || 'txt';
  const base = path.join(ruleDir(scanRoot, ir.id), 'fixtures');
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const written = [];
  for (const p of corpus.positives) {
    const f = path.join(base, 'vulnerable', `${p.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if (safeWriteState(f, p.code)) written.push(f);
  }
  for (const n of corpus.negatives) {
    const f = path.join(base, 'clean', `${n.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if (safeWriteState(f, n.code)) written.push(f);
  }
  return { ok: true, written, glob: path.join(base, '**', '*') };
}

/** Promote: write the compiled custom-rule document to the live rules directory. Does not touch the ledger —
 * the caller records the PROMOTED transition itself, so a failed write here can never produce an inconsistent
 * "promoted but not live" or "live but not recorded" state silently. */
export function publishCustomRule(scanRoot, ir) {
  const { ok, doc, errs } = compileToCustomRule(ir);
  if (!ok) return { ok: false, reason: `invalid rule IR: ${errs.join('; ')}` };
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = statePath(scanRoot, 'rules', `${ir.id}.yml`);
  const yamlText = [
    `# Compiled by the rule compiler from finding ${ir.provenance.originatingFindingId} (${ir.provenance.evidenceState}).`,
    `- id: ${doc.id}`,
    `  title: ${JSON.stringify(doc.title)}`,
    `  severity: ${doc.severity}`,
    `  cwe: ${doc.cwe}`,
    `  languages: [${doc.languages.join(', ')}]`,
    `  match:`,
    ...(doc.match.pattern ? [`    pattern: ${JSON.stringify(doc.match.pattern)}`] : []),
    ...(doc.match.allOf ? [`    allOf:`, ...doc.match.allOf.map((p) => `      - ${JSON.stringify(p)}`), `    window: ${doc.match.window}`] : []),
    ...(doc.match.notMatch ? [`    notMatch: ${JSON.stringify(doc.match.notMatch)}`] : []),
    ...(doc.match.fileRequires ? [`    fileRequires:`, ...doc.match.fileRequires.map((p) => `      - ${JSON.stringify(p)}`)] : []),
    ...(doc.match.guardedBy ? [`    guardedBy: ${JSON.stringify(doc.match.guardedBy)}`, `    guardWindow: ${doc.match.guardWindow}`] : []),
    ...(doc.match.excludeLine ? [`    excludeLine:`, ...doc.match.excludeLine.map((p) => `      - ${JSON.stringify(p)}`)] : []),
    `  message: ${JSON.stringify(doc.message)}`,
    '',
  ].join('\n');
  return { ok: safeWriteState(f, yamlText), file: f };
}

/** Sign a published rule with the operator's key (the same Ed25519 scheme `agentic-security-rule sign` uses). The key is never stored here. */
export function signPublishedRule(file, privateKeyB64) {
  try { signRulePack(file, privateKeyB64); return { ok: true }; } catch (e) { return { ok: false, reason: String(e.message).slice(0, 120) }; }
}

/**
 * Will the scanner actually LOAD this promoted rule? Publishing a file is not the same as the scanner trusting it: rule packs are
 * signature-checked (posture/rule-pack-signing.js) so that a rule dropped into a repository cannot run in someone's CI. A promoted rule
 * the scanner would refuse is not a capability yet, so this is reported next to the lifecycle state instead of being assumed.
 */
export function packTrust(scanRoot, id) {
  const file = statePath(scanRoot, 'rules', `${id}.yml`);
  if (!fs.existsSync(file)) return { live: false, reason: 'not published', remediation: null };
  let r;
  const origErr = console.error; console.error = () => {};
  try { r = verifyRulePack(file, loadTrustedKeys(scanRoot)); } finally { console.error = origErr; }
  if (r.ok) return { live: true, via: r.passThrough ? 'signed, accepted in pass-through mode (no trusted keys are configured)' : `signed by ${r.keyId}`, reason: null, remediation: null };
  if (r.reason === 'unsigned' && r.allowUnsigned) return { live: true, via: 'unsigned, accepted because AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1', reason: null, remediation: null };
  const remediation = r.reason === 'unsigned'
    ? `sign it (agentic-security-rule sign ${path.relative(process.cwd(), file) || file} with your key, or re-run promote with --sign-key <base64>), or opt in for this environment with AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1`
    : (r.remediation ?? 'see the signing setup in bin/agentic-security-rule.js');
  return { live: false, reason: r.reason, remediation };
}

export function unpublishCustomRule(scanRoot, id) {
  const f = statePath(scanRoot, 'rules', `${id}.yml`);
  try { for (const x of [f, `${f}.sig`]) if (fs.existsSync(x)) fs.unlinkSync(x); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}
