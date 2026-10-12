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
    `  message: ${JSON.stringify(doc.message)}`,
    '',
  ].join('\n');
  return { ok: safeWriteState(f, yamlText), file: f };
}

export function unpublishCustomRule(scanRoot, id) {
  const f = statePath(scanRoot, 'rules', `${id}.yml`);
  try { if (fs.existsSync(f)) fs.unlinkSync(f); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}
