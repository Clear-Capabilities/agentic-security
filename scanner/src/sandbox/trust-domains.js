// Trust domains for verification (CORE-003).
//
// Four domains stay separate, and this module is the single place that says
// which one may do what. It is deliberately data plus small pure functions: the
// ENFORCEMENT lives at the process boundary (`trust-boundary.js`, the sandbox
// profile, file modes), not here. A table nobody consults at the boundary would
// be documentation pretending to be a control, so every entry below has an
// attack test that tries the forbidden action through the real boundary.
//
//   target    analyzed code and anything it spawns. Adversarial by assumption.
//   worker    the model/agent that proposes hypotheses, scenarios and patches.
//             Adversarial for authority purposes: may be prompt-injected by the
//             target. Authors proposals, never truth.
//   verifier  the protected verifier / evaluation custodian. Holds sealed labels,
//             runs oracles, writes authoritative evidence.
//   signer    holds signing key material and issues signatures over evidence the
//             verifier produced. Never executes target or worker code.
//
// What a lower-trust domain may NEVER do, whatever it prints or writes:
//   - read signing keys, the install HMAC key or sealed labels
//   - write authoritative evidence
//   - set a verification status (only verifier-observed evidence can)
//   - read host paths unrelated to its own workspace (credential directories)
import os from 'node:os';
import path from 'node:path';

export const DOMAINS = Object.freeze({
  TARGET: 'target',
  WORKER: 'worker',
  VERIFIER: 'verifier',
  SIGNER: 'signer',
});

export const RESOURCES = Object.freeze({
  SIGNING_KEY: 'signing-key',
  HMAC_KEY: 'hmac-key',
  SEALED_LABELS: 'sealed-labels',
  AUTHORITATIVE_EVIDENCE: 'authoritative-evidence',
  VERIFICATION_STATUS: 'verification-status',
  HOST_CREDENTIALS: 'host-credentials',
  WORKSPACE: 'workspace',
});

// domain -> resource -> allowed actions. Absence means DENIED (default deny).
const POLICY = Object.freeze({
  [DOMAINS.TARGET]: { [RESOURCES.WORKSPACE]: ['read', 'write'] },
  [DOMAINS.WORKER]: { [RESOURCES.WORKSPACE]: ['read', 'write'] },
  [DOMAINS.VERIFIER]: {
    [RESOURCES.WORKSPACE]: ['read'],
    [RESOURCES.SEALED_LABELS]: ['read'],
    [RESOURCES.AUTHORITATIVE_EVIDENCE]: ['read', 'write'],
    [RESOURCES.VERIFICATION_STATUS]: ['write'],
    [RESOURCES.HMAC_KEY]: ['read'],
  },
  [DOMAINS.SIGNER]: {
    [RESOURCES.SIGNING_KEY]: ['read'],
    [RESOURCES.AUTHORITATIVE_EVIDENCE]: ['read'],
  },
});

/** Default-deny policy lookup. */
export function mayDo(domain, resource, action) {
  return !!POLICY[domain]?.[resource]?.includes(action);
}

/** Domains that execute or are influenced by untrusted content. */
export function isUntrusted(domain) {
  return domain === DOMAINS.TARGET || domain === DOMAINS.WORKER;
}

// ---- protected host paths --------------------------------------------------

/** Config directory holding the Ed25519 keys and the install HMAC key. */
export function keyDirectory(env = process.env) {
  const xdg = env.XDG_CONFIG_HOME;
  const base = xdg && xdg.length ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'agentic-security');
}

// Credential locations under the user's home that no target has a reason to
// read. A denylist can never be complete, so it is the floor, not the claim:
// the caller adds sealed-label and evidence directories explicitly.
const HOME_CREDENTIAL_PATHS = Object.freeze([
  '.ssh', '.aws', '.gnupg', '.azure', '.kube', '.docker', '.netrc', '.npmrc',
  '.pypirc', '.git-credentials', '.claude', '.config/gcloud', '.config/gh',
]);

/**
 * Every host path a target process must not read. The signing/HMAC key
 * directory is always included.
 */
export function protectedReadPaths({
  home = os.homedir(), env = process.env, labelDirs = [], evidenceDirs = [], extra = [],
} = {}) {
  const out = [keyDirectory(env)];
  for (const rel of HOME_CREDENTIAL_PATHS) out.push(path.join(home, rel));
  for (const p of [...labelDirs, ...evidenceDirs, ...extra]) if (p) out.push(path.resolve(p));
  return [...new Set(out)];
}

// ---- secret material in worker environments --------------------------------

const SECRET_NAME = /(?:^|_)(?:secret|token|password|passwd|api_?key|private_?key|credential|hmac|signing|auth)(?:_|$)|^(?:AWS_|GITHUB_|NPM_|ANTHROPIC_|OPENAI_)/i;
const PEM_PRIVATE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
// An explicit allowlist wins over the name heuristic: these carry no secret.
const SAFE_NAMES = new Set(['PATH', 'HOME', 'TMPDIR', 'LANG', 'ROOT', 'LC_ALL', 'TZ', 'CI']);

/** Names (never values) of environment entries that look like secret material. */
export function secretEnvNames(env = {}) {
  const out = [];
  for (const [k, v] of Object.entries(env || {})) {
    if (SAFE_NAMES.has(k)) continue;
    if (SECRET_NAME.test(k) || PEM_PRIVATE.test(String(v ?? ''))) out.push(k);
  }
  return out.sort();
}

/** `{ ok:false, offenders }` when an environment bound for a worker holds secrets. */
export function assertNoSecretMaterial(env = {}) {
  const offenders = secretEnvNames(env);
  return { ok: offenders.length === 0, offenders };
}

/** Copy of `env` without secret-looking entries. */
export function scrubEnv(env = {}) {
  const drop = new Set(secretEnvNames(env));
  return Object.fromEntries(Object.entries(env || {}).filter(([k]) => !drop.has(k)));
}

// ---- verification status ---------------------------------------------------

// Mirrors the PRD state model. Only this module decides how a status is formed
// from a boundary run, and it never reads target output.
export const VERIFICATION_STATUSES = Object.freeze(
  ['not-run', 'unsupported', 'inconclusive', 'error', 'refuted', 'confirmed'],
);

/**
 * Status from what the BOUNDARY observed (did it run, did it error). A run on
 * its own can never confirm anything: that takes verifier-observed evidence
 * (`settleVerification`).
 */
export function classifyRun(run) {
  if (!run || run.executed !== true) return 'not-run';
  if (run.status === 'error') return 'error';
  return 'inconclusive';
}

/**
 * Settle a verification status. `evidence` must come from verifier-domain code
 * (`observedBy: 'verifier'`) that examined state the target cannot write (for
 * example by re-running the oracle outside the target's reach). Target stdout,
 * stderr and workspace files are NOT evidence. `confirmed` is only reachable
 * from an executed run plus satisfied verifier evidence; `refuted` needs the
 * oracle to declare its preconditions held.
 */
export function settleVerification(run, evidence) {
  const base = classifyRun(run);
  if (base !== 'inconclusive') return base;
  if (!evidence || evidence.observedBy !== DOMAINS.VERIFIER) return base;
  if (evidence.satisfied === true) return 'confirmed';
  if (evidence.satisfied === false && evidence.preconditionsHeld === true) return 'refuted';
  return base;
}

const STATUS_LIKE = /\b(?:verified|confirmed|execution-proven|status\s*[:=])\b/i;

/** Count of target-output lines that merely LOOK like a status claim (informational). */
export function countStatusLikeLines(text) {
  return String(text || '').split('\n').filter((l) => STATUS_LIKE.test(l)).length;
}
