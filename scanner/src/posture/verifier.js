// Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7 — Phase-1 P1.2).
//
// Consumes the PoC artifacts produced by P1.1 (`f.poc`) and assigns a
// per-finding `verifier_verdict` in:
//
//   verified-exploit       — PoC ran against a live target and exited 0
//   verified-by-llm        — Layer-3 LLM accepted the finding (no PoC ran)
//   verified-sanitizer-absence — pattern-based proof that no sanitizer is on the flow
//   unverified-by-design   — CWE family for which v1 explicitly doesn't ship a PoC
//   cannot-verify          — PoC failed to run / LLM returned escalate / sandbox error
//
// Honest scope for v1:
//   * Default mode is "validate-only": parse the PoC, refuse to ship one that
//     contains a destructive payload, but do NOT execute it. Findings get
//     `verifier_verdict` set from the static signals.
//   * Live execution mode (AGENTIC_SECURITY_VERIFY_LIVE=1) runs each PoC
//     against a caller-provided target URL (AGENTIC_SECURITY_VERIFY_TARGET).
//     Without a target, live mode falls back to validate-only with a
//     `cannot-verify` verdict + reason 'no-target'.
//   * Sandbox: live execution runs through src/sandbox/index.js's confined
//     execution facility (the same one execution-proof.js uses) — never a
//     bare, unconfined subprocess. When no confinement primitive is
//     available on the host, live verification refuses rather than falling
//     back to running the PoC unconfined.
//
// Fail-closed semantics (FR-VER-7): any error — Docker missing, target down,
// PoC throws — produces `cannot-verify`, never `rejected`. An attacker who
// can break the verifier can only make findings UNVERIFIED, never SILENCED.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runConfined, sandboxAvailable } from '../sandbox/index.js';
import { isExplicitlyNoPoc } from './poc-cwe-map.js';
import { isSafeStateDir, stateDir, statePath, stateWritesEnabled } from './state-dir.js';

// ─── PoC static validation ──────────────────────────────────────────────────
//
// Refuse to ship a PoC that:
//   - is too long (template runaway)
//   - mentions a banned pattern (destructive shell, fork bomb)
//   - hardcodes a real cloud-metadata IP
//   - doesn't end with a `process.exit(...)` so verdict assignment is reliable

const MAX_POC_BYTES = 16_384;

const BANNED_PATTERNS = [
  /rm\s+-rf\s+\//,        // recursive destructive
  /mkfs/,
  /dd\s+if=\/dev\/(?:zero|random|urandom)/,
  /:\(\)\s*\{\s*:\s*\|\s*:/,  // fork bomb
  /shutdown\b/,
  /reboot\b/,
  /chmod\s+777\s+\//,
];

const BANNED_HOSTS = [
  '169.254.169.254',
  'metadata.google.internal',
  'fd00:ec2::254',
];

export function validatePoc(poc) {
  if (!poc || typeof poc !== 'object') return { ok: false, reason: 'no-poc' };
  if (typeof poc.code !== 'string' || poc.code.length === 0) return { ok: false, reason: 'empty-code' };
  if (poc.code.length > MAX_POC_BYTES) return { ok: false, reason: 'code-too-long' };
  for (const re of BANNED_PATTERNS) {
    if (re.test(poc.code)) return { ok: false, reason: `banned-pattern:${re.source.slice(0, 30)}` };
  }
  for (const h of BANNED_HOSTS) {
    if (poc.code.includes(h)) return { ok: false, reason: `banned-host:${h}` };
  }
  if (!/process\.exit\s*\(/.test(poc.code) && poc.lang === 'node') {
    return { ok: false, reason: 'no-deterministic-exit' };
  }
  return { ok: true };
}

// ─── Sanitizer-absence proof ────────────────────────────────────────────────
//
// For a flow-based finding with a clear source → sink path, we can prove a
// SANITIZER IS ABSENT by checking that none of the family's known sanitizers
// appears in the surrounding code window.

const SANITIZER_TABLE = {
  'sql-injection':           /\bprepare(?:Statement)?\s*\(|parameterized|\$\d+\b(?![=A-Za-z])|sequelize\.literal\b|\bescape\s*\(|(?:\bquery|\bexecute|\b\$queryRaw|\b\$executeRaw)\s*\([^)]*,\s*\[/i,
  'command-injection':       /execFile\s*\(|spawn\s*\(\s*['"][^'"]+['"]\s*,\s*\[|shlex\.quote/i,
  'xss':                     /escapeHtml|sanitize-html|DOMPurify|encodeURIComponent\(|textContent\s*=|res\.json\(/i,
  'path-traversal':          /path\.resolve\s*\(|path\.basename\s*\(|\.startsWith\s*\(\s*\w+\s*\)/i,
  'ssrf':                    /isPrivateIP|new\s+URL\s*\(|allowlist|allowedHosts|trustedHosts/i,
  'code-injection':          /(?!eval).*?\beval\s*\(.*JSON/i,    // very weak; intentionally narrow
  'open-redirect':           /allowed(?:Redirects|Urls|Hosts)|\.includes\s*\(\s*\w+\s*\)\s*\?/i,
  'xxe':                     /\bnoent\s*[:=]\s*false|resolve_entities\s*=\s*False|XMLInputFactory.*IS_SUPPORTING_EXTERNAL_ENTITIES.*false/i,
  'insecure-deserialization':/JSON\.parse|yaml\.safe_load|safe_load_all/i,
};

function _windowAroundLine(file, line, fileContents) {
  if (!file || !line || !fileContents || !fileContents[file]) return '';
  const lines = fileContents[file].split('\n');
  const start = Math.max(0, line - 11);
  const end = Math.min(lines.length, line + 10);
  return lines.slice(start, end).join('\n');
}

export function proveSanitizerAbsence(finding, fileContents) {
  const fam = finding.family;
  if (!fam) return { ok: false, reason: 'no-family' };
  const rx = SANITIZER_TABLE[fam];
  if (!rx) return { ok: false, reason: 'no-rule' };
  const file = finding.file || finding.sink?.file;
  const line = finding.line || finding.sink?.line || 0;
  const window = _windowAroundLine(file, line, fileContents);
  if (!window) return { ok: false, reason: 'no-source-window' };
  if (rx.test(window)) return { ok: false, reason: 'sanitizer-present' };
  return { ok: true, reason: `no-sanitizer-in-window`, window: window.length };
}

// ─── Sandbox execution ──────────────────────────────────────────────────────
//
// Runs the PoC and returns { ok, exitCode, stderr, runner }.
// Caller decides what to do with the result. Internal — surfaced via
// `_internals.runSandboxed` for tests; the public contract is
// `annotateVerifierVerdicts`.

function runSandboxed(poc, opts = {}) {
  const target = opts.target;
  if (!target) return { ok: false, reason: 'no-target' };
  if (!sandboxAvailable() && !opts.force) {
    return { ok: false, reason: 'no confinement primitive available on this host; refusing to execute the PoC unconfined', runner: 'disabled' };
  }
  // Materialise the PoC into a fresh sandbox root.
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'as-poc-')));
  const file = poc.lang === 'python' ? 'poc.py' : 'poc.mjs';
  try {
    fs.writeFileSync(path.join(dir, file), _patchTarget(poc.code, target));
  } catch (e) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    return { ok: false, reason: `write-failed:${e.message}` };
  }
  try {
    const argv = poc.lang === 'python' ? ['python3', file] : [process.execPath, file];
    // allowNetwork: the whole point of live verification is reaching the
    // caller-provided target — writes and everything else stay confined.
    const r = runConfined(argv, { root: dir, timeoutMs: opts.timeoutMs || 15000, allowNetwork: true, force: opts.force });
    if (r.status === 'disabled') {
      return { ok: false, reason: 'confined execution is disabled; the PoC was refused and never executed', runner: r.backend };
    }
    if (r.status === 'error') {
      return { ok: false, reason: `sandbox-error:${(r.stderr || '').trim() || 'unknown'}`, runner: r.backend };
    }
    if (r.timedOut) {
      return { ok: false, reason: 'poc-timeout', runner: r.backend };
    }
    return { ok: true, exitCode: r.exitCode, stderr: r.stderr || '', stdout: r.stdout || '', runner: r.backend, denied: r.denied };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

function _patchTarget(code, target) {
  // Replace the localhost:3000 placeholder with the caller-provided target.
  return code.replace(/http:\/\/localhost:3000/g, target);
}

// ─── Per-finding verdict assignment ─────────────────────────────────────────

export function verdictForFinding(finding, ctx = {}) {
  // 1. Families we explicitly do not ship a PoC for.
  if (isExplicitlyNoPoc(finding.family)) {
    return { verdict: 'unverified-by-design', reason: `family-no-poc:${finding.family}` };
  }
  // 2. Validator already passed it via the LLM.
  if (finding.validator_verdict === 'accept') {
    return { verdict: 'verified-by-llm', reason: 'llm-accept' };
  }
  // 3. PoC present and live mode is on — run it.
  const liveMode = process.env.AGENTIC_SECURITY_VERIFY_LIVE === '1';
  const target = ctx.target || process.env.AGENTIC_SECURITY_VERIFY_TARGET || null;
  if (finding.poc && liveMode && target) {
    const v = validatePoc(finding.poc);
    if (!v.ok) return { verdict: 'cannot-verify', reason: `poc-rejected:${v.reason}` };
    const r = runSandboxed(finding.poc, { target, timeoutMs: ctx.timeoutMs });
    if (!r.ok) return { verdict: 'cannot-verify', reason: r.reason || 'sandbox-error', runner: r.runner };
    if (r.exitCode === 0) return { verdict: 'verified-exploit', reason: 'poc-exit-0', runner: r.runner };
    return { verdict: 'cannot-verify', reason: `poc-exit:${r.exitCode}`, runner: r.runner, stderr: (r.stderr || '').slice(0, 240) };
  }
  // 4. PoC present but we're not running it — static validate only.
  if (finding.poc) {
    const v = validatePoc(finding.poc);
    if (!v.ok) return { verdict: 'cannot-verify', reason: `poc-validation-failed:${v.reason}` };
    // Static validation says the PoC is shippable; absent live execution we
    // can't claim verified-exploit. Try the sanitizer-absence proof next.
  }
  // 5. Sanitizer-absence proof.
  if (ctx.fileContents) {
    const sa = proveSanitizerAbsence(finding, ctx.fileContents);
    if (sa.ok) return { verdict: 'verified-sanitizer-absence', reason: sa.reason };
  }
  return { verdict: 'cannot-verify', reason: 'no-poc-no-sanitizer-rule' };
}

// ─── Batch annotation ───────────────────────────────────────────────────────

export function annotateVerifierVerdicts(findings, opts = {}) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    try {
      const v = verdictForFinding(f, opts);
      f.verifier_verdict = v.verdict;
      f.verifier_reason = v.reason || null;
      if (v.runner) f.verifier_runner = v.runner;
    } catch (e) {
      // Defense in depth: any exception → cannot-verify, never throws upward.
      f.verifier_verdict = 'cannot-verify';
      f.verifier_reason = `verifier-exception:${e.message?.slice(0, 80)}`;
    }
  }
}

// ─── Summary helpers ────────────────────────────────────────────────────────

export function verifierCoverageSummary(findings) {
  const out = { 'verified-exploit': 0, 'verified-by-llm': 0, 'verified-sanitizer-absence': 0, 'unverified-by-design': 0, 'cannot-verify': 0 };
  for (const f of findings || []) {
    const v = f?.verifier_verdict;
    if (v && v in out) out[v]++;
  }
  return out;
}

// ─── Run persistence (adversarial premortem Q1, 2026-09-07) ────────────────
//
// `compliance-frameworks/*.json` has mapped `module:verifier` to
// `verifier-runs/` since this framework's control-to-artifact table was
// written, but nothing ever wrote to it: `cmdVerify` (bin/agentic-security.js)
// ran the loop and printed a summary, but never persisted one. That made
// NIST 800-171 `03.12.01` (Security Assessment) and NIST CSF 2.0 `RC.RP`
// (Recovery plans executed and improved) permanently unable to read
// 'present' via this leg of their mapping, on any project, ever — worse than
// a self-referential mapping (which can at least clear, dishonestly), a
// mapping that can never clear at all. This closes that gap for real, one
// record per `agentic-security verify` run, same shape as fix-metrics.js's
// append-per-attempt pattern (that file uses one growing JSONL; this one
// uses one file per run, because the table entry it satisfies is a
// directory, not a file, and a per-run file is what a reader would expect
// under a name like "verifier-runs/").
const RUN_DIR = 'verifier-runs';

/**
 * Persist one record of an `agentic-security verify` invocation. Best-effort
 * and silent on failure, same convention as every other posture writer: a
 * verify run's own findings must never be lost because the record of having
 * run could not be written.
 *
 * @returns {boolean} whether the record was written (for tests, not callers).
 */
export function recordVerifierRun(scanRoot, summary) {
  if (!scanRoot || !summary || typeof summary !== 'object') return false;
  try {
    const dir = stateDir(scanRoot);
    if (!isSafeStateDir(dir)) return false;
    if (!stateWritesEnabled()) return false;
    const runsDir = statePath(scanRoot, RUN_DIR);
    fs.mkdirSync(runsDir, { recursive: true });
    const now = new Date();
    // Millisecond Date timestamps collide under back-to-back calls (two
    // `verify` invocations in the same test, or a scripted loop). hrtime is
    // monotonic and nanosecond-resolution within this process, so appending
    // it guarantees both a distinct filename AND correct chronological sort
    // order (alphabetical == call order), which a random suffix alone would
    // not: two records written in the same millisecond would sort by random
    // bytes, not by which call happened first.
    const stamp = now.toISOString().replace(/[^0-9TZ]/g, '-');
    const seq = process.hrtime.bigint().toString().padStart(20, '0');
    const record = { timestamp: now.toISOString(), ...summary };
    // One writeFileSync of one complete file: a concurrent reader sees a
    // whole record or nothing (never a partial one, unlike an append target).
    fs.writeFileSync(path.join(runsDir, `${stamp}-${seq}.json`), JSON.stringify(record, null, 2), 'utf8');
    return true;
  } catch { return false; }
}

/**
 * Read every well-formed run record, oldest first. A file that does not
 * parse is skipped, not thrown on — same tolerant-read convention as
 * fix-metrics.js's readFixAttempts.
 */
export function readVerifierRuns(scanRoot) {
  try {
    const runsDir = statePath(scanRoot, RUN_DIR);
    const files = fs.readdirSync(runsDir).filter((f) => f.endsWith('.json')).sort();
    const out = [];
    for (const f of files) {
      try { out.push(JSON.parse(fs.readFileSync(path.join(runsDir, f), 'utf8'))); } catch { /* skip malformed */ }
    }
    return out;
  } catch { return []; }
}

// For tests and the no-dead-modules check.
export const _internals = { MAX_POC_BYTES, BANNED_HOSTS, SANITIZER_TABLE, runSandboxed };
