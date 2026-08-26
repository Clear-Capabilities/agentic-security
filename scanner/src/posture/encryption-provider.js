// FR-705 (assurance-hardening PRD): "Encrypt state classes marked
// confidential when an encryption provider is configured or required |
// Required encryption absence fails before sensitive state is written."
//
// SCOPE (Phase 1 of a deliberately staged rollout — see this module's own
// header for what is and is not covered, and D-0039-style honesty about
// what remains):
//
//   - Confidentiality is a NEW `confidential: true` field on specific
//     artifact-registry.js entries (see that module for the exact list and
//     the reasoning for each). `last-scan.json`/`findings.json` are
//     DELIBERATELY EXCLUDED from Phase 1: dozens of commands read them
//     directly as plain JSON, so encrypting them is a much larger,
//     separate migration (every reader needs a decrypt-on-read hook) —
//     doing that alongside a handful of narrow, low-traffic audit/evidence
//     artifacts in one pass would repeat exactly the "large, structurally-
//     coupled epic attempted in one unplanned cycle" mistake this session
//     has deliberately avoided elsewhere (see D-0028, D-0039).
//   - ONE provider is implemented: 'local-key' — AES-256-GCM with a
//     per-install key generated the first time encryption is actually
//     used, stored at the same $XDG_CONFIG_HOME/agentic-security/ directory
//     integrity.js already uses for its own signing key (a SEPARATE key
//     file — never reuse one key across different cryptographic purposes).
//     A KMS/envelope-encryption provider is a real future extension point
//     (the provider interface is already shaped to allow one) but is out
//     of scope here: this codebase makes no runtime cloud calls, and a KMS
//     call is unavoidably a network call.
//   - "Configured or required" is a per-project opt-in policy file
//     (.agentic-security/encryption-policy.yml: `provider: local-key`,
//     `required: true|false`). No file means "not configured, not
//     required" — every confidential artifact keeps writing exactly as it
//     always has, so this feature is inert until an operator opts in,
//     matching every other policy surface in this codebase
//     (retention-policy.yml, risk-config.yml, sca-policy.yml, ...).
//   - The FAIL-CLOSED half of the acceptance criterion is
//     `maybeEncryptForWrite`'s own contract: when `required: true` is set
//     for a confidential artifact but no working provider is available,
//     it returns `{ok:false}` — the caller must not write ANYTHING in that
//     case, plaintext or otherwise. This is checked BEFORE any bytes touch
//     disk, per the literal "fails before sensitive state is written"
//     wording.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as yaml from '../util/yaml.js';
import { statePath } from './state-dir.js';
import { confidentialOf } from './artifact-registry.js';

export const ENCRYPTION_POLICY_FILE = 'encryption-policy.yml';
export const ENCRYPTION_MARKER = '__agentic_security_encrypted_v1__';
const KEY_FILE_NAME = 'encryption-key';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;

function _keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && xdg.length ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'agentic-security');
}
function _keyPath() { return path.join(_keyDir(), KEY_FILE_NAME); }

// Same atomic-publish shape as integrity.js's _publishKeyAtomically — a
// hard-link into place is atomic and fails EEXIST rather than clobbering,
// closing the same first-writer-wins race a plain exclusive-create alone
// leaves open on filesystems without hard-link support (documented in
// integrity.js's own header; reproduced here rather than imported, since
// this is a genuinely separate key with its own purpose and no reason to
// couple the two modules' internals together).
function _publishKeyAtomically(fp, contents) {
  const dir = _keyDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `${KEY_FILE_NAME}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(tmp, contents, { mode: 0o600 });
    try {
      fs.linkSync(tmp, fp);
      return 'created';
    } catch (e) {
      if (e.code === 'EEXIST') return 'exists';
      try {
        fs.writeFileSync(fp, contents, { mode: 0o600, flag: 'wx' });
        return 'created';
      } catch (e2) {
        if (e2.code === 'EEXIST') return 'exists';
        throw e2;
      }
    }
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* best effort */ }
  }
}

function _readOrGenerateKey() {
  const fromEnv = process.env.AGENTIC_SECURITY_ENCRYPTION_KEY;
  if (fromEnv && /^[0-9a-fA-F]{64}$/.test(fromEnv.trim())) return Buffer.from(fromEnv.trim(), 'hex');
  const fp = _keyPath();
  try {
    if (fs.existsSync(fp)) {
      const hex = fs.readFileSync(fp, 'utf8').trim();
      if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
    }
  } catch { /* fall through to generate */ }
  const buf = crypto.randomBytes(32);
  try {
    const outcome = _publishKeyAtomically(fp, buf.toString('hex') + '\n');
    if (outcome === 'created') return buf;
    const hex = fs.readFileSync(fp, 'utf8').trim();
    return Buffer.from(hex, 'hex');
  } catch {
    return buf; // ephemeral — a write can proceed this run, but nothing encrypted with it will ever decrypt again. Degraded, not blocked.
  }
}

/**
 * Read `.agentic-security/encryption-policy.yml`. Never throws; a missing
 * or malformed file is "not configured, not required" (the safe,
 * inert-by-default state every other policy file in this codebase uses).
 */
export function loadEncryptionPolicy(scanRoot) {
  let fp;
  try { fp = statePath(scanRoot, ENCRYPTION_POLICY_FILE); } catch { return null; }
  let raw;
  try { raw = fs.readFileSync(fp, 'utf8'); } catch { return null; }
  try {
    const doc = yaml.load(raw);
    if (!doc || typeof doc !== 'object') return null;
    const provider = doc.provider === 'local-key' ? 'local-key' : null;
    return { provider, required: doc.required === true };
  } catch { return null; }
}

function _encryptBuffer(plaintext, key) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
}

function _decryptBuffer(envelope, key) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
}

/**
 * Is `parsed` (an already-JSON.parsed value) an encryption envelope this
 * module produced?
 */
export function isEncryptedEnvelope(parsed) {
  return !!(parsed && typeof parsed === 'object' && parsed[ENCRYPTION_MARKER] === true);
}

/**
 * The fail-closed gate. `artifactName` is matched against
 * artifact-registry.js's `confidential` flag — an artifact not marked
 * confidential is always {ok:true, content} unchanged, regardless of
 * policy, so this function is a safe no-op to call for every write site
 * without needing to duplicate the confidentiality check at each caller.
 *
 * @returns {{ok:true, content:string, encrypted:boolean} | {ok:false, reason:string}}
 */
export function maybeEncryptForWrite(scanRoot, artifactName, content) {
  if (!confidentialOf(artifactName)) return { ok: true, content, encrypted: false };

  const policy = loadEncryptionPolicy(scanRoot);
  if (!policy || !policy.provider) {
    if (policy && policy.required) {
      return { ok: false, reason: `encryption is required for confidential artifact "${artifactName}" but no provider is configured (.agentic-security/${ENCRYPTION_POLICY_FILE})` };
    }
    return { ok: true, content, encrypted: false };
  }

  try {
    const key = _readOrGenerateKey();
    const envelope = _encryptBuffer(Buffer.from(content, 'utf8'), key);
    return { ok: true, content: JSON.stringify({ [ENCRYPTION_MARKER]: true, provider: 'local-key', ...envelope }), encrypted: true };
  } catch (e) {
    if (policy.required) return { ok: false, reason: `encryption required but failed for "${artifactName}": ${e.message}` };
    return { ok: true, content, encrypted: false };
  }
}

/**
 * Transparent decrypt-on-read: if `rawContent` parses as an envelope this
 * module produced, decrypt and return the original plaintext string;
 * otherwise return `rawContent` unchanged (a plaintext file, or a file
 * from before encryption was ever configured). Never throws — a corrupt
 * or undecryptable envelope degrades to returning the raw envelope JSON
 * back (a caller expecting markdown/plaintext will visibly get neither,
 * which is the correct, honest failure mode for a decrypt this module
 * cannot perform, rather than silently returning empty content).
 */
export function maybeDecryptForRead(rawContent) {
  let parsed;
  try { parsed = JSON.parse(rawContent); } catch { return rawContent; }
  if (!isEncryptedEnvelope(parsed)) return rawContent;
  try {
    const key = _readOrGenerateKey();
    return _decryptBuffer(parsed, key).toString('utf8');
  } catch { return rawContent; }
}

export const _internals = { _readOrGenerateKey, _encryptBuffer, _decryptBuffer, _keyPath };
