// Cross-repo intelligence — a per-developer store of fix patterns and
// triage decisions that span every repo this developer has used the
// plugin against.
//
// Location: ~/.claude/agentic-security/cross-repo/
//   patterns.jsonl    — append-only log of "developer fixed family X
//                       in repo Y at commit Z using pattern P"
//   triage.jsonl      — append-only log of "developer marked family X
//                       in repo Y wont-fix with reason R"
//
// When a finding lands in the current repo, surface matching patterns
// and triage decisions from sibling repos — "you fixed this exact shape
// in repo-A last week; same fix here?"
//
// Privacy:
//   - All data stored locally under the developer's $HOME
//   - Nothing transmitted; no network calls
//   - Repo identifiers are git-remote-derived SHA fingerprints, not
//     bare names — so the store doesn't accidentally reveal repo names
//     to anyone reading the local file
//   - Opt-out: AGENTIC_SECURITY_NO_CROSS_REPO=1

import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';

// Lazy — process.env.HOME may be mutated mid-process (e.g. tests isolating).
function _storeDir() {
  const HOME = process.env.HOME || process.env.USERPROFILE || '/tmp';
  return path.join(HOME, '.claude', 'agentic-security', 'cross-repo');
}
function _patternsFile() { return path.join(_storeDir(), 'patterns.jsonl'); }
function _triageFile()   { return path.join(_storeDir(), 'triage.jsonl'); }
const MAX_LINES  = 5000;

function _ensureDir() { try { fs.mkdirSync(_storeDir(), { recursive: true }); } catch {} }

/**
 * Stable, privacy-preserving repo fingerprint: SHA-256 of the git remote
 * URL (or scan-root absolute path if no remote). Truncated to 12 chars.
 */
export function repoFingerprint(scanRoot) {
  let source = String(scanRoot || '');
  try {
    // `scanRoot` is the scanned project's repository, not this project's
    // own trusted checkout — hardened per FR-PROV-024 / the second Finding
    // Provenance PRD audit (same exposure class as
    // provenance/git-evidence.js's `_run`).
    const remote = cp.execFileSync('git', hardenGitArgs(['remote', 'get-url', 'origin']),
      { cwd: scanRoot, encoding: 'utf8', timeout: 800, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() }).trim();
    if (remote) source = remote;
  } catch {}
  return crypto.createHash('sha256').update(source).digest('hex').slice(0, 12);
}

function _appendLine(fp, obj) {
  if (process.env.AGENTIC_SECURITY_NO_CROSS_REPO === '1') return;
  _ensureDir();
  try { fs.appendFileSync(fp, JSON.stringify(obj) + '\n'); } catch {}
  _rotateIfNeeded(fp);
}

function _rotateIfNeeded(fp) {
  try {
    const stat = fs.statSync(fp);
    if (stat.size < 1_000_000) return;
    const lines = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
    if (lines.length <= MAX_LINES) return;
    fs.writeFileSync(fp, lines.slice(-MAX_LINES).join('\n') + '\n');
  } catch {}
}

function _readAll(fp) {
  if (process.env.AGENTIC_SECURITY_NO_CROSS_REPO === '1') return [];
  try {
    return fs.readFileSync(fp, 'utf8')
      .split('\n').filter(Boolean)
      .map(ln => { try { return JSON.parse(ln); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

/**
 * Record that a finding was fixed. Caller passes the finding object +
 * a short description of the fix pattern (often extracted from the
 * synthesize_fix replacement text).
 */
export function recordFix({ scanRoot, finding, fixPattern, commitSha }) {
  if (!finding || !finding.family) return null;
  const entry = {
    at: new Date().toISOString(),
    kind: 'fix',
    repo: repoFingerprint(scanRoot),
    family: finding.family,
    severity: finding.severity || null,
    cwe: finding.cwe || null,
    vuln: String(finding.vuln || '').slice(0, 160),
    fixPattern: String(fixPattern || '').slice(0, 280),
    commitSha: commitSha || null,
  };
  _appendLine(_patternsFile(), entry);
  return entry;
}

/**
 * Record a triage decision into the cross-repo store as well. (The
 * existing posture/triage-memory.js handles the per-repo case; this
 * mirrors it cross-repo so sibling repos benefit too.)
 */
export function recordTriage({ scanRoot, finding, decision, reason }) {
  if (!finding || !decision) return null;
  if (!['wont-fix', 'false-positive'].includes(decision)) return null;
  const entry = {
    at: new Date().toISOString(),
    kind: 'triage',
    repo: repoFingerprint(scanRoot),
    family: finding.family || null,
    cwe: finding.cwe || null,
    vuln: String(finding.vuln || '').slice(0, 160),
    decision,
    reason: String(reason || '').slice(0, 280),
  };
  _appendLine(_triageFile(), entry);
  return entry;
}

/**
 * Look up cross-repo signals matching a new finding. Returns:
 *   { siblingFixes: [], siblingTriage: [] }
 *
 * Matching is family + (cwe optional). Same-repo entries are excluded
 * so the result is genuinely cross-repo learning.
 */
export function findSiblingSignals(scanRoot, finding) {
  if (!finding || !finding.family) return { siblingFixes: [], siblingTriage: [] };
  const here = repoFingerprint(scanRoot);
  const fam = finding.family;
  const fixes  = _readAll(_patternsFile()).filter(e => e.repo !== here && e.family === fam);
  const triage = _readAll(_triageFile())  .filter(e => e.repo !== here && e.family === fam);
  return {
    siblingFixes:  fixes.slice(-5).reverse(),  // most recent 5
    siblingTriage: triage.slice(-5).reverse(),
  };
}

/**
 * Render a short Markdown note suitable for surfacing on a finding card.
 */
export function renderSiblingNote(signals) {
  if (!signals || (!signals.siblingFixes.length && !signals.siblingTriage.length)) return '';
  const lines = [];
  lines.push('### Cross-repo signal');
  lines.push('');
  if (signals.siblingFixes.length) {
    lines.push(`Past fixes for this family in other repos:`);
    for (const f of signals.siblingFixes) {
      const ago = _ago(f.at);
      lines.push(`- \`${f.repo}\` ${ago} — ${f.fixPattern || '(no pattern recorded)'}`);
    }
    lines.push('');
  }
  if (signals.siblingTriage.length) {
    lines.push(`Past triage for this family in other repos:`);
    for (const t of signals.siblingTriage) {
      const ago = _ago(t.at);
      lines.push(`- \`${t.repo}\` ${ago} — ${t.decision} (${t.reason || 'no reason'})`);
    }
  }
  return lines.join('\n');
}

function _ago(iso) {
  if (!iso) return '';
  const ms = Date.now() - new Date(iso).getTime();
  const d  = Math.floor(ms / 86_400_000);
  if (d <= 1) return 'today';
  if (d < 7) return `${d}d ago`;
  if (d < 30) return `${Math.floor(d / 7)}w ago`;
  if (d < 365) return `${Math.floor(d / 30)}mo ago`;
  return `${Math.floor(d / 365)}y ago`;
}

export const _internals = { _storeDir, _ensureDir, _ago };
