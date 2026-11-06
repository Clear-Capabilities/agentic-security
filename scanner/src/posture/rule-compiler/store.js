// Persistence for the rule compiler: one directory per rule under `.agentic-security/rule-compiler/<id>/`
// (`ir.json`, `ledger.json`, `evaluation.json`), the promoted custom-rule document at
// `.agentic-security/rules/<id>.yml` (so the EXISTING `loadCustomRules`/`rule test` machinery picks it up with no
// change), and a regression fixture pair at `.agentic-security/rule-compiler/fixtures/<id>/{vulnerable,clean}/`
// using the SAME filename convention `runRuleTests` already reads (`vulnerable`/`clean` in the path).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { statePath, ensureStateDir, safeWriteState } from '../state-dir.js';
import { newLedger, verifyLedger } from './lifecycle.js';
import { signLastScan, verifyLastScan } from '../integrity.js';
import { compileToCustomRule } from './ir.js';
import { verifyRulePack, loadTrustedKeys, signRulePack } from '../rule-pack-signing.js';

const DIR = 'rule-compiler';
const EXT = { javascript: 'js', typescript: 'ts', python: 'py', go: 'go', ruby: 'rb', java: 'java', rust: 'rs', csharp: 'cs', php: 'php', any: 'txt' };

function ruleDir(scanRoot, id) { return statePath(scanRoot, DIR, id); }

/**
 * The lifecycle ledger is hash-chained (lifecycle.js) AND signed with the per-install HMAC key (the same key as last-scan.json),
 * since 0.195.23 (GA-07): the chain alone could be recomputed by anyone who could edit the file. A ledger that fails either check,
 * or that cannot be parsed, is returned WITH `tampered: true` and its reason, and `saveLedger` refuses to write it, so a bad ledger
 * is never quietly replaced by a fresh one and its history lost. An unsigned ledger with entries (written before 0.195.23) is
 * accepted only with AGENTIC_SECURITY_RULES_UNSIGNED=1, the same switch that accepts an unsigned rules override, and is signed on
 * its next save.
 */
export function loadLedger(scanRoot, env = process.env) {
  const f = statePath(scanRoot, DIR, 'ledger.json');
  if (!fs.existsSync(f)) return newLedger();
  let text;
  try { text = fs.readFileSync(f, 'utf8'); } catch (e) { return { ...newLedger(), tampered: true, tamperReason: `cannot read the ledger: ${e.message}` }; }
  let ledger;
  try { ledger = JSON.parse(text); } catch (e) { return { ...newLedger(), tampered: true, tamperReason: `the ledger is not valid JSON: ${e.message}` }; }
  if (!ledger || !Array.isArray(ledger.entries)) return { ...newLedger(), tampered: true, tamperReason: 'the ledger has no entries array' };
  const v = verifyLedger(ledger);
  if (!v.ok) return { ...ledger, tampered: true, tamperReason: v.reason };
  const sig = verifyLastScan(text, `${f}.sig`);
  if (sig === true) return { ...ledger, verifiedBy: 'install-key' };
  // GA-07 §3 (0.195.27): the install key never leaves the machine that promoted the rule, so on a CI runner (or any other
  // clone) the HMAC cannot verify. A ledger that `promote --sign-key` also signed with the operator's Ed25519 key is accepted
  // when that signature verifies against a key the environment trusts: AGENTIC_SECURITY_RULES_PUBLIC_KEY (set outside the
  // repository, a CI variable) or the trusted-keys store the rule packs already use. The chain check above still applies, and
  // the signature covers the whole file, so a dropped last entry fails it like any other edit. A project-local key file alone
  // is not trust (an author who can write .agentic-security/ could add one), which is why the env variable is the CI route.
  const author = verifyAuthorSignature(text, `${f}${AUTHOR_SIG_SUFFIX}`, authorKeysFrom(scanRoot, env));
  if (author.ok) return { ...ledger, verifiedBy: 'author-key', authorKeyId: author.keyId };
  if (sig === false) return { ...ledger, tampered: true, tamperReason: `the ledger signature does not verify under this install key${author.present ? ` and its author signature does not verify against any trusted key (${author.reason})` : ' and it carries no author signature (promote with --sign-key to make it portable)'}` };
  if (sig === null && ledger.entries.length && env.AGENTIC_SECURITY_RULES_UNSIGNED !== '1') {
    return { ...ledger, tampered: true, tamperReason: 'the ledger is unsigned (written before 0.195.23 or by another tool); set AGENTIC_SECURITY_RULES_UNSIGNED=1 once to accept and re-sign it' };
  }
  return { ...ledger, verifiedBy: sig === null ? 'unsigned-accepted' : 'install-key' };
}

const AUTHOR_SIG_SUFFIX = '.author.sig';
const PUBLIC_KEY_ENV = 'AGENTIC_SECURITY_RULES_PUBLIC_KEY';

/** The Ed25519 public keys a ledger's author signature may verify against: the environment variable (one or more base64 raw keys,
 * comma separated) first, then the rule-pack trust store (bundled keys, and the project file only when the operator honours it). */
function authorKeysFrom(scanRoot, env) {
  const keys = [];
  for (const k of String(env[PUBLIC_KEY_ENV] || '').split(',').map((s) => s.trim()).filter(Boolean)) keys.push({ id: 'env', publicKey: k, alg: 'ed25519' });
  const origErr = console.error; console.error = () => {};
  try { keys.push(...loadTrustedKeys(scanRoot)); } catch { /* no trust store */ } finally { console.error = origErr; }
  return keys;
}

function verifyAuthorSignature(text, sigPath, keys) {
  let sig;
  try { sig = fs.readFileSync(sigPath); } catch { return { ok: false, present: false, reason: 'no author signature' }; }
  if (!keys.length) return { ok: false, present: true, reason: `no trusted key (set ${PUBLIC_KEY_ENV})` };
  const body = Buffer.from(text, 'utf8');
  for (const k of keys) {
    try {
      const keyBytes = Buffer.from(k.publicKey, 'base64');
      if (keyBytes.length !== 32) continue;
      const keyObj = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: keyBytes.toString('base64url') }, format: 'jwk' });
      if (crypto.verify(null, body, keyObj, sig)) return { ok: true, present: true, keyId: k.id || '(unnamed)' };
    } catch { /* next key */ }
  }
  return { ok: false, present: true, reason: 'bad signature' };
}

function signWithAuthorKey(text, privateKeyB64) {
  const privBytes = Buffer.from(privateKeyB64, 'base64');
  if (privBytes.length !== 32) throw new Error('private key must be 32 bytes (raw ed25519)');
  const keyObj = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), privBytes]), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(text, 'utf8'), keyObj);
}

/** The public key (base64 raw) that pairs with a raw Ed25519 private key; printed by `promote` so the operator can set it in CI. */
export function publicKeyOf(privateKeyB64) {
  const privBytes = Buffer.from(privateKeyB64, 'base64');
  if (privBytes.length !== 32) return null;
  const keyObj = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), privBytes]), format: 'der', type: 'pkcs8' });
  return Buffer.from(crypto.createPublicKey(keyObj).export({ format: 'jwk' }).x, 'base64url').toString('base64');
}

/**
 * Write the ledger with its install-key signature and, when the operator's Ed25519 key is given, an author signature beside it
 * (`ledger.json.author.sig`) that another machine can verify (see loadLedger). Without a key an existing author signature is
 * removed rather than left stale: a signature that no longer matches the file would read as tampering on the next clone.
 */
export function saveLedger(scanRoot, ledger, { authorKey = null } = {}) {
  if (ledger?.tampered) return { ok: false, reason: `refusing to overwrite a ledger that failed its integrity check (${ledger.tamperReason})` };
  if (!ensureStateDir(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = statePath(scanRoot, DIR, 'ledger.json');
  const { verifiedBy, authorKeyId, ...body } = ledger;
  const text = JSON.stringify(body, null, 2);
  let ok = safeWriteState(f, text) && safeWriteState(`${f}.sig`, signLastScan(text));
  let authorSigned = false;
  if (ok && authorKey) {
    try { ok = safeWriteState(`${f}${AUTHOR_SIG_SUFFIX}`, signWithAuthorKey(text, authorKey)); authorSigned = ok; } catch (e) { return { ok: false, reason: `cannot author-sign the ledger: ${String(e.message).slice(0, 120)}` }; }
  } else if (ok) {
    try { fs.unlinkSync(`${f}${AUTHOR_SIG_SUFFIX}`); } catch { /* none to remove */ }
  }
  return { ok, authorSigned };
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
