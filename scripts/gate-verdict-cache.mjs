#!/usr/bin/env node
// Gate verdict cache — PRD R1.
//
// WHY THIS EXISTS
// ---------------
// `npm test`, the corpus gate and the self-scan gate run in THREE places for a
// single commit: the pre-push gate, hosted CI, and release-check. Measured on
// 2026-08-09, a push-then-publish spent roughly eight minutes of local wall
// clock re-deriving identical facts about one immutable commit. That is not a
// safety/speed trade — the inputs are byte-identical, and this engine already
// stakes its reputation on determinism over exactly those inputs
// (posture/attestation.js, posture/scan-checkpoint.js).
//
// So: remember that a check passed for a given set of inputs, and skip it while
// those inputs hold.
//
// WHAT MAKES THIS SAFE RATHER THAN A HOLE IN THE GATE
// ---------------------------------------------------
//  1. THE KEY IS THE WHOLE POINT. It covers every input that could change an
//     outcome — the commit, the TREE (so a dirty working tree never reuses a
//     clean verdict), the built bundle, the ruleset, the Node version, the
//     platform, and every AGENTIC_SECURITY_* variable. Miss one and the cache
//     starts lying. This mirrors scan-checkpoint.js's run key deliberately:
//     redoing work is slow, reusing stale work is a correctness bug.
//  2. ONLY A PASS IS EVER CACHED. A failure is re-run every time. Caching a
//     failure would strand a developer who has fixed it, and "still failing
//     after I fixed it" destroys trust in the gate faster than slowness does.
//  3. IT FAILS OPEN INTO WORK, NEVER INTO A PASS. Unreadable, corrupt,
//     tampered, expired, or unparseable all mean "run the check". There is no
//     path from a bad cache to a skipped check.
//  4. IT IS TAMPER-EVIDENT. Records are HMAC-signed with the existing
//     per-install key (posture/integrity.js#signLastScan) — the same mechanism
//     last-scan.json uses. No second key mechanism was invented. The signature
//     is symmetric, so this is tamper-evidence for the operator, not
//     third-party non-repudiation; that is all it needs to be, because the
//     cache only ever skips work already done ON THIS MACHINE.
//  5. NOTHING IS SILENT. A cached check prints when it was verified, by which
//     gate, and for which commit. A gate that quietly skips work is
//     indistinguishable from a gate that is not running.
//
// WHAT IT DELIBERATELY DOES NOT DO
// --------------------------------
// It is never shared between machines. A cross-machine cache would require the
// cross-machine reproducibility claim this project explicitly does NOT make
// (see posture/attestation.js's "DOES NOT PROVE" section). CI must always run
// its own checks, and the release workflow passes --no-cache for that reason.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const SCANNER = path.join(REPO, 'scanner');

export const CACHE_FILE = '.agentic-security/gate-verdicts.json';

/**
 * How long a verdict may be reused. A backstop against machine state the key
 * does not model — an OS upgrade, a rotated toolchain, a rebuilt native module.
 * Expiry means re-run, never fail.
 */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

const CACHE_SCHEMA = 'agentic-security/gate-verdicts@1';

// ---------------------------------------------------------------------------
// Pure decision functions. No I/O — the tests drive these on constructed input.
// ---------------------------------------------------------------------------

/**
 * Every AGENTIC_SECURITY_* name and value, sorted, as one string.
 *
 * Values, not just names: AGENTIC_SECURITY_DEEP=1 and AGENTIC_SECURITY_DEEP=0
 * are different runs. Sorted so the key does not depend on environment
 * enumeration order, which is not guaranteed stable.
 */
export function envFingerprint(env = process.env) {
  return Object.keys(env)
    .filter(k => k.startsWith('AGENTIC_SECURITY_'))
    .sort()
    .map(k => `${k}=${env[k]}`)
    .join(' ');
}

/**
 * Reduce the inputs to one hex digest. Every component is required; a missing
 * one yields null, and a null key means "cannot cache", which means "run it".
 * An absent input must never silently collapse into a shared key.
 */
export function computeVerdictKey(parts) {
  const required = ['commitSha', 'treeSha', 'bundleSha', 'rulesetVersion', 'nodeVersion', 'platform', 'envFingerprint'];
  // `envFingerprint` is legitimately EMPTY when no AGENTIC_SECURITY_* variable
  // is set, which is the ordinary case. Treating empty as missing made the key
  // null on every normal run, so caching silently never engaged — the whole
  // feature would have looked present and done nothing. Only genuinely absent
  // values (undefined/null, i.e. an input that could not be read) invalidate.
  const mayBeEmpty = new Set(['envFingerprint']);
  for (const f of required) {
    const v = parts?.[f];
    if (v === undefined || v === null) return null;
    if (v === '' && !mayBeEmpty.has(f)) return null;
  }
  const material = required.map(f => `${f}=${parts[f]}`).join('\n');
  return crypto.createHash('sha256').update(material).digest('hex');
}

/**
 * Decide whether a stored record may be reused for `checkId` under `key`.
 * Every rejection names itself, so the caller can print WHY it is re-running.
 */
export function evaluateCachedVerdict({ record, key, checkId, now = Date.now(), ttlMs = DEFAULT_TTL_MS }) {
  if (!record) return { usable: false, reason: 'no cached verdict' };
  if (record.checkId !== checkId) return { usable: false, reason: 'record is for a different check' };
  if (record.key !== key) return { usable: false, reason: 'inputs changed since it was recorded' };
  if (record.verdict !== 'pass') return { usable: false, reason: 'only a passing verdict is ever reused' };
  const at = Date.parse(record.at || '');
  if (!Number.isFinite(at)) return { usable: false, reason: 'record has no readable timestamp' };
  const age = now - at;
  if (age < 0) return { usable: false, reason: 'record is dated in the future' };
  if (age > ttlMs) return { usable: false, reason: `record is older than the ${Math.round(ttlMs / 3600000)}h reuse window` };
  return { usable: true, reason: null, ageMs: age };
}

/** One line stating where a reused verdict came from. Never optional. */
export function renderProvenance(record, { now = Date.now() } = {}) {
  const mins = Math.max(0, Math.round((now - Date.parse(record.at)) / 60000));
  const age = mins < 60 ? `${mins}m ago` : `${Math.round(mins / 60)}h ago`;
  const took = Number.isFinite(record.durationMs) ? `, took ${(record.durationMs / 1000).toFixed(0)}s` : '';
  return `cached: verified ${age} by the ${record.by} gate for ${String(record.commitSha).slice(0, 7)}${took}`;
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', shell: false, ...opts });
  return r.status === 0 ? String(r.stdout || '').trim() : null;
}

// `git stash create` has a real, reproducible upstream quirk (confirmed live:
// ~1 in 20-40 calls on a genuinely clean tree, no load needed to trigger it):
// it sometimes exits 1 instead of 0 for the exact same "nothing to stash"
// case, with BOTH stdout and stderr completely empty either way — there is no
// message distinguishing "nothing to stash" from a real failure when this
// happens. Treating every non-zero exit as a hard failure (this module's own
// `run()` helper, correct for every OTHER git call here) made
// `computeWorkingTreeSha` intermittently return null for a genuinely clean
// tree, which failed `test/gate-verdict-cache.test.js`'s own
// reverting-an-edit-returns-the-original-hash test on the pre-push gate and
// hosted CI, though never locally in isolation (not load-dependent — the
// repro above shows it happening on an otherwise-idle machine). Since a
// GENUINE error from `git stash create` (a corrupt repo, a permission issue)
// would print something to stdout or stderr, only a non-zero exit with BOTH
// streams empty is treated as "nothing to stash" (equivalent to the
// documented exit-0-empty-string case); any non-zero exit that prints
// anything still returns null, preserving this module's own "fail open into
// work, never into a pass" principle for every real failure mode.
function runStashCreate(cwd) {
  const r = spawnSync('git', ['stash', 'create'], { encoding: 'utf8', shell: false, cwd });
  if (r.status === 0) return String(r.stdout || '').trim();
  if (!r.stdout && !r.stderr) return '';
  return null;
}

function readTextOrNull(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}

// Adversarial-premortem-style finding, caught incidentally while publishing
// 0.151.1: `git rev-parse HEAD^{tree}` is the tree of the last COMMIT — it
// is byte-identical before and after editing a tracked file, confirmed live
// (`git rev-parse HEAD^{tree}` printed the same hash before and after
// appending a line to a tracked file and reverting it). That directly
// contradicts this module's own header claim ("the TREE, so a dirty
// working tree never reuses a clean verdict") — the key never actually
// captured working-tree dirtiness at all, so a stale PASS could be reused
// across an uncommitted, potentially-breaking change for up to the 24h TTL,
// as long as nothing else in the key (bundle hash, ruleset, node version,
// platform, env) happened to also change. `computeWorkingTreeSha` replaces
// the bare `HEAD^{tree}` read with one that genuinely reflects the current
// working tree: `git stash create` (non-destructive — confirmed live that
// `git status --short` is unchanged after calling it) captures staged +
// unstaged changes to TRACKED files as a real commit-ish, but confirmed
// live it does NOT cover untracked files (a brand-new file added this
// session was absent from its resulting tree) — so untracked files
// (path + content, sorted) are hashed in separately. Any failure at any
// step yields null, per this module's own stated principle #3 ("fails open
// into work, never into a pass") — an unreadable git state must re-run the
// check, never silently fall back to the old, provably-wrong behavior.
export function computeWorkingTreeSha(repo) {
  const baseTree = run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: repo });
  if (!baseTree) return null;
  // `git stash create` prints a commit SHA when there are tracked changes,
  // or an EMPTY string (exit 0) when the tracked tree is clean — that empty
  // string is a real, meaningful signal ("no tracked dirt"), not a failure,
  // so only a non-zero exit (→ run() returns null) is treated as an error.
  const stashish = runStashCreate(repo);
  if (stashish === null) return null;
  const untrackedList = run('git', ['ls-files', '--others', '--exclude-standard'], { cwd: repo });
  if (untrackedList === null) return null;
  const untrackedFiles = untrackedList.split('\n').filter(Boolean).sort();
  const untrackedDigestParts = [];
  for (const rel of untrackedFiles) {
    let content;
    try { content = fs.readFileSync(path.join(repo, rel)); }
    catch { return null; } // a file listed then unreadable is a race — fail closed, don't guess.
    untrackedDigestParts.push(`${rel}:${crypto.createHash('sha256').update(content).digest('hex')}`);
  }
  const material = [`base=${baseTree}`, `stash=${stashish}`, `untracked=${untrackedDigestParts.join(',')}`].join('\n');
  return crypto.createHash('sha256').update(material).digest('hex');
}

/** Gather the key inputs. Any failure yields a null field, hence a null key. */
export function gatherKeyParts({ repo = REPO, env = process.env } = {}) {
  const sidecar = readTextOrNull(path.join(SCANNER, 'dist', 'agentic-security.mjs.sha256'));
  let rulesetVersion = null;
  try {
    // Read rather than import: this script must not pull the engine into memory
    // just to compute a cache key.
    const raw = readTextOrNull(path.join(SCANNER, 'src', 'posture', 'ruleset-version.js')) || '';
    rulesetVersion = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  } catch { rulesetVersion = null; }

  return {
    commitSha: run('git', ['rev-parse', 'HEAD'], { cwd: repo }),
    treeSha: computeWorkingTreeSha(repo),
    bundleSha: sidecar ? sidecar.split(/\s+/)[0] : null,
    rulesetVersion,
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    envFingerprint: envFingerprint(env),
  };
}

function cachePath(repo = REPO) { return path.join(repo, CACHE_FILE); }

/** Load the signed cache. Anything wrong yields an empty cache — never a throw. */
export function loadCache(repo = REPO, { signer = null } = {}) {
  const raw = readTextOrNull(cachePath(repo));
  if (!raw) return { schema: CACHE_SCHEMA, records: {} };
  let doc;
  try { doc = JSON.parse(raw); } catch { return { schema: CACHE_SCHEMA, records: {}, rejected: 'unparseable' }; }
  if (doc?.schema !== CACHE_SCHEMA || !doc.records) {
    return { schema: CACHE_SCHEMA, records: {}, rejected: 'unrecognised schema' };
  }
  if (signer) {
    const expect = signer(JSON.stringify(doc.records));
    if (expect !== doc.signature) {
      // Tamper-evidence: a record set that does not verify is discarded whole.
      // Partially trusting it would be worse than not caching at all.
      return { schema: CACHE_SCHEMA, records: {}, rejected: 'signature mismatch' };
    }
  }
  return { schema: CACHE_SCHEMA, records: doc.records };
}

/** Persist a PASS. Failure to write is non-fatal: the next run just re-checks. */
export function recordVerdict(repo, { checkId, key, commitSha, by, durationMs }, { signer = null, now = () => new Date() } = {}) {
  if (!key || !checkId) return false;
  try {
    const cache = loadCache(repo, { signer });
    cache.records[checkId] = {
      checkId, key, verdict: 'pass', commitSha, by,
      durationMs: Number.isFinite(durationMs) ? durationMs : null,
      at: now().toISOString(),
    };
    const body = { schema: CACHE_SCHEMA, records: cache.records };
    if (signer) body.signature = signer(JSON.stringify(cache.records));
    const p = cachePath(repo);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(body, null, 2) + '\n');
    return true;
  } catch {
    return false;
  }
}

/** True when caching is switched off for this run. */
export function cachingDisabled(argv = [], env = process.env) {
  // Hosted CI never reuses a verdict: a cache file found there was not written by this gate on this machine.
  return argv.includes('--no-cache') || env.AGENTIC_SECURITY_GATE_NO_CACHE === '1' || env.GITHUB_ACTIONS === 'true';
}

// ---------------------------------------------------------------------------
// PER-CHECK SCOPED KEYS
// ---------------------------------------------------------------------------
//
// The whole-tree key above answers "is the ENTIRE repository unchanged". That
// is sound but coarse: touching a README re-runs every bench. The scoped key
// answers the narrower question "is everything THIS check can read unchanged",
// using the scope written down in gate-check-scopes.mjs.
//
// It is sound under the same five rules as the header, plus:
//  6. The digest covers file CONTENT (never mtime), the file's presence, and
//     symlink targets. A file that is listed but cannot be read makes the whole
//     key null (run the check), exactly like an unreadable whole-tree input.
//  7. The key covers the check's command text, Node version, platform, python3
//     version, the bundle, the AGENTIC_SECURITY_* environment and the named
//     ambient variables below. Changing any of them invalidates.
//  8. A check whose scope says it runs the VCS against this repository also keys
//     on HEAD; one that does not, keys on content alone, so an amend or rebase
//     that leaves the bytes identical still hits.
import { scopeFor, pathInScope } from './gate-check-scopes.mjs';

/** Ambient variables that change what a check does without being AGENTIC_SECURITY_*. */
export const AMBIENT_ENV = ['CI', 'GITHUB_ACTIONS', 'NODE_OPTIONS', 'NODE_ENV', 'TZ', 'LANG', 'LC_ALL', 'NO_COLOR', 'FORCE_COLOR'];

export function ambientEnvFingerprint(env = process.env) {
  return AMBIENT_ENV.map(k => `${k}=${env[k] ?? ''}`).join(' ');
}

const SCOPED_PREFIX = 'scoped:';
export const scopedRecordId = (checkId) => `${SCOPED_PREFIX}${checkId}`;

/** Files in the working tree (tracked + untracked-not-ignored), or null on failure. */
export function listWorkingTreeFiles(repo) {
  // A hook hands down repository-redirecting variables; they must not point this listing at some other repository.
  const env = { ...process.env };
  for (const k of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_PREFIX', 'GIT_COMMON_DIR']) delete env[k];
  const r = spawnSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
    { cwd: repo, encoding: 'utf8', shell: false, env, maxBuffer: 256 * 1024 * 1024 });
  if (r.status !== 0 || r.error) return null;
  return [...new Set(String(r.stdout).split('\0').filter(Boolean))].sort();
}

// Ignored directories that checks nonetheless read (the build's code-split
// chunks, the vendored runtimes, the installed dependency set). Hashed directly.
const IGNORED_ROOTS = ['scanner/dist', 'scanner/vendor'];
const IGNORED_FILES = ['scanner/node_modules/.package-lock.json'];

function walk(dirAbs, relBase, out) {
  let entries;
  try { entries = fs.readdirSync(dirAbs, { withFileTypes: true }); } catch { return false; }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const rel = `${relBase}/${e.name}`;
    const abs = path.join(dirAbs, e.name);
    let isDir = e.isDirectory();
    if (e.isSymbolicLink()) { try { isDir = fs.statSync(abs).isDirectory(); } catch { return false; } }
    if (isDir) { if (!walk(abs, rel, out)) return false; } else out.push(rel);
  }
  return true;
}

function hashOne(abs) {
  let st;
  try { st = fs.lstatSync(abs); } catch { return null; }
  if (st.isSymbolicLink()) {
    let target;
    try { target = fs.readlinkSync(abs); } catch { return null; }
    let real;
    try { real = fs.statSync(abs); } catch { return `symlink:${target}:dangling`; }
    if (real.isDirectory()) return `symlink-dir:${target}`;
  } else if (st.isDirectory()) {
    return 'dir';
  }
  try { return crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex'); } catch { return null; }
}

/**
 * Digest of every file in `scope`: `{ digest, fileCount }`, or null when the
 * file list or any in-scope file could not be read (the caller then runs the
 * check). `files` may be supplied so the tree is listed once per gate run.
 */
export function digestScope(repo, scope, { files = null } = {}) {
  const listed = files || listWorkingTreeFiles(repo);
  if (!listed) return null;
  const set = new Set(listed.filter(f => pathInScope(scope, f)));
  for (const root of IGNORED_ROOTS) {
    if (!pathInScope(scope, `${root}/x`)) continue;
    const found = [];
    if (fs.existsSync(path.join(repo, root)) && !walk(path.join(repo, root), root, found)) return null;
    for (const f of found) set.add(f);
  }
  for (const f of IGNORED_FILES) if (fs.existsSync(path.join(repo, f))) set.add(f);
  const lines = [];
  for (const rel of [...set].sort()) {
    const h = hashOne(path.join(repo, rel));
    if (h === null) return null; // listed but unreadable: fail closed, never skip it
    lines.push(`${rel}\0${h}`);
  }
  return { digest: crypto.createHash('sha256').update(lines.join('\n')).digest('hex'), fileCount: lines.length };
}

/** python3 version: the IR layer and one suite run it. 'absent' is also a keyed fact. */
export function pythonVersion() {
  const r = spawnSync('python3', ['--version'], { encoding: 'utf8', shell: false });
  return r.error ? 'absent' : `${r.stdout}${r.stderr}`.trim();
}

/**
 * The scoped key for one check, or null when any input could not be read.
 * `command` is the check's own invocation text (the package.json script body),
 * so editing what a check RUNS invalidates it even if no scanned file changed.
 */
export function computeScopedKey({
  check, command, repo = REPO, env = process.env, files = null, headSha = null, bundleSha = null,
  nodeVersion = process.version, platform = `${process.platform}-${process.arch}`, python = null, scope = null,
}) {
  if (!check || !command) return null;
  const sc = scope || scopeFor(check.id);
  const d = digestScope(repo, sc, { files });
  if (!d) return null;
  if (sc.usesHistory && !headSha) return null;
  if (!bundleSha) return null;
  const material = [
    'schema=scoped-key@1', `check=${check.id}`, `command=${command}`,
    `scope=${JSON.stringify({ all: sc.all, include: sc.include })}`,
    `inputs=${d.digest}`, `files=${d.fileCount}`, `bundle=${bundleSha}`, `node=${nodeVersion}`, `platform=${platform}`,
    `python=${python ?? pythonVersion()}`, `env=${envFingerprint(env)}`, `ambient=${ambientEnvFingerprint(env)}`,
    `head=${sc.usesHistory ? headSha : '-'}`,
  ].join('\n');
  return { key: crypto.createHash('sha256').update(material).digest('hex'), digest: d.digest, fileCount: d.fileCount };
}

/** The script body for `npm run <script>` in scanner/package.json, or null if absent. */
export function npmScriptBody(script, scannerDir = SCANNER) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(scannerDir, 'package.json'), 'utf8'));
    const body = pkg.scripts?.[script];
    return typeof body === 'string' ? body : null;
  } catch { return null; }
}

/** Provenance line for a scoped hit. Printed loudly, never omitted. */
export function renderScopedProvenance(record) {
  return `cached (inputs unchanged since ${record.at})`;
}

/**
 * Scan state is a hidden input: `.agentic-security/` directories are gitignored, so no file listing sees them, yet a scan reads
 * rules, policy and triage files from them and writes more as it goes. For a check that scans a tree of corpus entries the gate
 * therefore removes those directories (derived state, the same hygiene the repository's own docs ask for before benchmarking)
 * BEFORE computing the key and again before running, so the key describes a state-free tree. Only a directory that git reports as
 * IGNORED is ever removed; tracked or unignored content is left alone, and is then covered by the file digest.
 * Returns the number of directories removed, or null when ignore status could not be established (the caller then runs the check).
 */
export function wipeIgnoredState(repo, roots) {
  let removed = 0;
  const env = { ...process.env };
  for (const k of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_PREFIX', 'GIT_COMMON_DIR']) delete env[k];
  const visit = (rel) => {
    let entries;
    try { entries = fs.readdirSync(path.join(repo, rel), { withFileTypes: true }); } catch { return true; }
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      const child = path.posix.join(rel, e.name);
      if (e.name === '.agentic-security') {
        const r = spawnSync('git', ['check-ignore', '-q', '--', child], { cwd: repo, env, shell: false });
        if (r.error || (r.status !== 0 && r.status !== 1)) return false;
        if (r.status === 0) { fs.rmSync(path.join(repo, child), { recursive: true, force: true }); removed++; }
        continue;
      }
      if (e.name === 'node_modules' || e.name === '.git') continue;
      if (!visit(child)) return false;
    }
    return true;
  };
  for (const root of roots) if (!visit(root.replace(/\/$/, ''))) return null;
  return removed;
}
