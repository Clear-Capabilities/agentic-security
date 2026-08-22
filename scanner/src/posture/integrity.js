// Tamper-evidence for `.agentic-security/last-scan.json`.
//
// Writes a sibling `.sig` file containing an HMAC-SHA256 of the JSON body.
// Readers verify the signature before trusting findings counts / file paths.
//
// KEY MATERIAL (premortem #1):
//   The key is read from one of:
//     1. $AGENTIC_SECURITY_HMAC_KEY  — explicit operator-provided key (hex)
//     2. $XDG_CONFIG_HOME/agentic-security/scan-key  (or ~/.config/agentic-security/scan-key)
//        — a per-install 32-byte random key, mode 0600, generated on first use.
//   The old hostname-derived key is accepted in VERIFY-ONLY mode for one
//   release so existing signed `last-scan.json` files keep verifying. New
//   signatures only use the random key.
//
// Threat model: this is a guardrail against accidental corruption, naive
// manual edits, CI-cache poisoning, and supply-chain planting of a fake
// last-scan.json designed to weaponize MCP `apply_fix`. An attacker who
// reads $AGENTIC_SECURITY_HMAC_KEY or the on-disk key file can forge — so
// the key file is mode 0600, and the env-var variant is intended for
// operators who manage secrets separately (Doppler/Infisical/etc.).

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const _HMAC_SALT = 'agentic-security:last-scan:v1';

function _keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && xdg.length ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'agentic-security');
}
function _keyPath() { return path.join(_keyDir(), 'scan-key'); }

// Where the active key came from. A signature is only as meaningful as the key
// behind it, and `env` means "whoever set the environment could sign this" —
// a reader of a scan artifact deserves to know which case they are in.
let _keySource = null;
export function keyProvenance() { return _keySource || 'unresolved'; }

// `writeFileSync(fp, …, {flag:'wx'})` is exclusive-CREATE, not atomic
// create-with-content: it creates the file and THEN writes it. A concurrent
// process that opens the path in that window reads an empty or partial file,
// fails the hex check, and falls through to an ephemeral key — whose signatures
// verify nowhere, forever, indistinguishable from real tampering. That is the
// same failure the `wx` flag was added to prevent, just through a narrower
// window, and CI caught it: 1 of 8 concurrently-generated signatures failed to
// verify under the install key.
//
// Writing the full content to a temp file and hard-LINKING it into place closes
// the window. link(2) is atomic and fails with EEXIST rather than clobbering, so
// the destination path only ever appears with complete content, and the
// first-writer-wins guarantee is preserved. Some filesystems (and Windows in
// places) refuse hard links, so an unsupported link degrades to the previous
// exclusive-create behaviour rather than failing the scan.
function _publishKeyAtomically(fp, contents) {
  const dir = _keyDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `scan-key.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(tmp, contents, { mode: 0o600 });
    try {
      fs.linkSync(tmp, fp);
      return 'created';
    } catch (e) {
      if (e.code === 'EEXIST') return 'exists';
      // Hard links unsupported here — fall back, accepting the narrower race.
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
  const fromEnv = process.env.AGENTIC_SECURITY_HMAC_KEY;
  if (fromEnv && /^[0-9a-fA-F]{32,}$/.test(fromEnv.trim())) {
    _keySource = 'env';
    return Buffer.from(fromEnv.trim(), 'hex');
  }
  const fp = _keyPath();
  try {
    if (fs.existsSync(fp)) {
      const hex = fs.readFileSync(fp, 'utf8').trim();
      if (/^[0-9a-fA-F]{32,}$/.test(hex)) { _keySource = 'per-install'; return Buffer.from(hex, 'hex'); }
    }
  } catch { /* fall through to generate */ }
  // Generate, mode 0600. `wx` — exclusive create, same TOCTOU fix
  // evidence-bundle.js's ensureKeyPair() already applies to its own key
  // material: on first use, two concurrent processes can both pass the
  // existsSync check above as false and both reach here. Without exclusive
  // create, the last writer's key silently wins on disk while every OTHER
  // process keeps signing with the key it generated and lost — a key that
  // now exists nowhere, so every signature made under it fails to verify
  // forever after, indistinguishable from real tampering.
  const buf = crypto.randomBytes(32);
  try {
    const outcome = _publishKeyAtomically(fp, buf.toString('hex') + '\n');
    if (outcome === 'created') { _keySource = 'per-install-new'; return buf; }
    // Another process published first — fall through to the EEXIST path and
    // adopt ITS key, exactly as before.
    const e = new Error('key already published'); e.code = 'EEXIST'; throw e;
  } catch (e) {
    if (e.code === 'EEXIST') {
      // Another process won the race and persisted its key first — use
      // THAT key instead of the one we generated, or we'd return a key
      // that matches nothing on disk.
      // Bounded retry, defence-in-depth. With the atomic link publish above the
      // winner's key is complete the instant the path exists, so one read is
      // enough. It is NOT enough when the link fell back to exclusive-create
      // (filesystems without hard links), or when an older version of this file
      // left a torn key behind — there the content can still be arriving. A few
      // short retries cost nothing and the alternative is an ephemeral key whose
      // signatures never verify again.
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const hex = fs.readFileSync(fp, 'utf8').trim();
          if (/^[0-9a-fA-F]{32,}$/.test(hex)) { _keySource = 'per-install'; return Buffer.from(hex, 'hex'); }
        } catch { /* not readable yet */ }
        try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2); } catch { /* no sleep available */ }
      }
    }
    // Could not persist (or the winner's key was unreadable/malformed) —
    // this key lives for this process only, so nothing signed with it will
    // verify on any later run. Callers must be able to see that, or a
    // permanently-unverifiable signature looks like a valid one.
    _keySource = 'ephemeral';
    return buf;
  }
}

// REMOVED (2026-08-08): the legacy hostname-derived key.
//
// It was `sha256(_HMAC_SALT + ':' + os.hostname())`. `_HMAC_SALT` is a constant
// in published, npm-shipped source and a hostname is not a secret — it appears
// in CI logs, build artifacts and error messages. So the "signature" could be
// forged by anyone who knew the target's hostname, which is to say by anyone.
//
// This was known. The 0.62.0 changelog introduced the per-install key precisely
// because the old one was "hostname-derived and publicly forgeable in CI /
// containers", and kept verification of the legacy key "for one release to
// migrate existing signed scans". The comment here said "Remove after one minor
// release." It was still accepted at 0.132.0 — SEVENTY minor releases later.
//
// What it cost: `rule-overrides.js` gates the `disable:` list on
// `verifyLastScan`, so a forged signature silently switched off arbitrary
// detectors and the scan reported clean. Demonstrated end to end before removal:
// with a hostname-forged `rules.yml.sig`, a command-injection finding went from
// 1 reported to 0.
//
// A migration window that nobody closes is not a migration window; it is the
// vulnerability, kept on purpose. Signatures made under the legacy key no longer
// verify — that is the intended consequence. Re-sign with `agentic-security
// rules sign`.

let _cachedKey = null;
function _key() {
  if (_cachedKey) return _cachedKey;
  _cachedKey = _readOrGenerateKey();
  return _cachedKey;
}

export function signLastScan(body) {
  return crypto.createHmac('sha256', _key()).update(body).digest('hex');
}

// Verify body against a sibling .sig file.
// Returns true if valid under the current install key OR the legacy hostname
// key (for one-release migration), false if invalid, null if sig file is
// absent (first-run case — call sites decide whether absent == fail-closed).
export function verifyLastScan(body, sigFile) {
  if (!fs.existsSync(sigFile)) return null;
  let stored;
  try { stored = fs.readFileSync(sigFile, 'utf8').trim(); }
  catch { return false; }
  const tryKey = (k) => {
    try {
      const expected = crypto.createHmac('sha256', k).update(body).digest('hex');
      if (stored.length !== expected.length) return false;
      return crypto.timingSafeEqual(Buffer.from(stored, 'hex'), Buffer.from(expected, 'hex'));
    } catch { return false; }
  };
  // ONE key. There is deliberately no fallback: a second accepted key is a
  // second thing that can be forged, and the last one was forgeable by anyone
  // who could read a hostname.
  if (tryKey(_key())) return true;
  return false;
}

// Test-only helpers (premortem-tracked):
export function _resetKeyCacheForTests() { _cachedKey = null; _keySource = null; }
export function _keyFilePathForTests() { return _keyPath(); }
