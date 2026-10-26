// Git-history-aware finding annotation.
//
// For each finding, looks up the introducing commit via `git blame -L
// <line>,<line>`. Adds:
//
//   introducedBy        — author name (or 'AI' if commit message marks it)
//   introducedIn        — commit SHA (12 chars)
//   introducedAt        — commit ISO date
//   introducedInMessage — commit subject line (cap 120 chars)
//   originatingPrompt   — extracted from commit body when present
//
// Then can render a Slack-ready / PR-comment-ready author-ping draft.
//
// Conservative: any subprocess error / non-git repo / file-not-tracked
// leaves the finding unannotated. Caps blame to 1 line per finding (so
// 200 findings = 200 blame calls). Set AGENTIC_SECURITY_NO_GIT_HISTORY=1
// to skip entirely.

import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';

const MAX_BLAME_PER_SCAN = 500;
const SUBPROC_TIMEOUT_MS = 1500;
const PROMPT_MARKER_RE = /(?:^|\n)(?:Prompt|User asked|Original request|Co-Authored-By:\s*Claude)/i;

// `scanRoot` is the scanned project's repository, not this project's own
// trusted checkout — every call below is hardened per FR-PROV-024 / the
// second Finding Provenance PRD audit (same exposure class as
// provenance/git-evidence.js's `_run`).
function _isGitRepo(scanRoot) {
  try {
    cp.execFileSync('git', hardenGitArgs(['rev-parse', '--git-dir']), { cwd: scanRoot, stdio: 'ignore', timeout: SUBPROC_TIMEOUT_MS, env: hardenGitEnv() });
    return true;
  } catch { return false; }
}

function _blame(scanRoot, file, line) {
  if (!file || !line || line < 1) return null;
  const rel = path.isAbsolute(file) ? path.relative(scanRoot, file) : file;
  if (rel.startsWith('..')) return null;
  try {
    // `--no-textconv`: VERIFIED exploitable without it — `git blame`
    // applies a hostile `.gitattributes` textconv driver by default in
    // current git, same as provenance/git-evidence.js's blameLine.
    const stdout = cp.execFileSync(
      'git',
      hardenGitArgs(['blame', '-L', `${line},${line}`, '--porcelain', '--no-textconv', '--', rel]),
      { cwd: scanRoot, encoding: 'utf8', timeout: SUBPROC_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() },
    );
    return _parsePorcelain(stdout);
  } catch { return null; }
}

// One `git blame` per file for every wanted line, instead of one per line.
// Porcelain output repeats the full metadata only the first time a commit
// appears, so metadata is kept per sha and each line's block is resolved
// against it. Returns Map(line -> meta), or null on any failure so the caller
// falls back to the per-line path (a line past the end of the file fails the
// whole call, and that must not lose the other lines).
function _blameFile(scanRoot, file, lines) {
  const rel = path.isAbsolute(file) ? path.relative(scanRoot, file) : file;
  if (rel.startsWith('..')) return null;
  const wanted = [...new Set(lines)].filter((n) => Number.isInteger(n) && n >= 1).sort((a, b) => a - b);
  if (!wanted.length) return null;
  const args = ['blame', '--porcelain', '--no-textconv'];
  for (const n of wanted) args.push('-L', `${n},${n}`);
  args.push('--', rel);
  try {
    const out = cp.execFileSync('git', hardenGitArgs(args), {
      cwd: scanRoot, encoding: 'utf8', timeout: SUBPROC_TIMEOUT_MS * 4, maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv(),
    });
    const bySha = new Map();
    const result = new Map();
    let cur = null;
    let curLine = null;
    const flush = () => {
      if (cur && curLine != null) result.set(curLine, cur);
      cur = null; curLine = null;
    };
    for (const ln of out.split('\n')) {
      const head = /^([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$/.exec(ln);
      if (head) {
        flush();
        if (!bySha.has(head[1])) bySha.set(head[1], { raw: [], sha40: head[1] });
        cur = bySha.get(head[1]);
        curLine = parseInt(head[3], 10);
        continue;
      }
      if (!cur) continue;
      if (ln.charCodeAt(0) === 9) cur.rawDone = true;
      else if (!cur.rawDone) cur.raw.push(ln);
    }
    flush();
    const parsed = new Map();
    const resolved = new Map();
    for (const [n, c] of result) {
      if (!parsed.has(c.sha40)) parsed.set(c.sha40, _parsePorcelain(`${c.sha40} 1 1 1\n${c.raw.join('\n')}`));
      resolved.set(n, parsed.get(c.sha40));
    }
    return resolved;
  } catch { return null; }
}

function _parsePorcelain(out) {
  if (!out) return null;
  const lines = out.split('\n');
  // First line: <sha> <orig-line> <final-line> <num-lines>
  const head = lines[0].split(' ');
  const sha = head[0];
  if (!sha || sha === '0000000000000000000000000000000000000000') return null;
  const meta = { sha: sha.slice(0, 12) };
  for (const ln of lines) {
    if (ln.startsWith('author '))         meta.author = ln.slice(7);
    else if (ln.startsWith('author-mail '))  meta.email = ln.slice(12).replace(/[<>]/g, '');
    else if (ln.startsWith('author-time '))  meta.ts = parseInt(ln.slice(12), 10);
    else if (ln.startsWith('summary '))      meta.summary = ln.slice(8);
  }
  if (meta.ts) meta.at = new Date(meta.ts * 1000).toISOString();
  return meta;
}

function _fullMessage(scanRoot, sha) {
  try {
    return cp.execFileSync(
      'git', hardenGitArgs(['show', '-s', '--no-textconv', '--format=%B', sha]),
      { cwd: scanRoot, encoding: 'utf8', timeout: SUBPROC_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() },
    );
  } catch { return ''; }
}

// Every distinct commit message in one `git log --no-walk` call instead of one
// `git show` per commit. Returns Map(sha prefix as given -> body); a sha missing
// from the result is looked up individually by the caller.
function _fullMessages(scanRoot, shas) {
  const out = new Map();
  const list = [...new Set(shas)].filter((x) => /^[0-9a-f]{7,40}$/.test(x));
  if (!list.length) return out;
  try {
    const raw = cp.execFileSync(
      'git', hardenGitArgs(['log', '--no-walk=unsorted', '--no-textconv', '--format=%H%x1f%B%x1e', ...list, '--']),
      { cwd: scanRoot, encoding: 'utf8', timeout: SUBPROC_TIMEOUT_MS * 4, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() },
    );
    for (const rec of raw.split('\x1e')) {
      const i = rec.indexOf('\x1f');
      if (i < 0) continue;
      const full = rec.slice(0, i).replace(/^\s+/, '');
      const body = rec.slice(i + 1).replace(/^\n+/, '');
      for (const sha of list) if (full.startsWith(sha)) out.set(sha, body);
    }
  } catch { /* the caller falls back per commit */ }
  return out;
}

function _extractPrompt(body) {
  if (!body || !PROMPT_MARKER_RE.test(body)) return null;
  // Take the line(s) that follow a "Prompt:" or "User asked:" marker, up to
  // the next blank line. Truncate to 280 chars.
  const m = body.match(/(?:Prompt|User asked|Original request)\s*[:\-]\s*([\s\S]*?)(?=\n\s*\n|$)/i);
  if (!m) return null;
  return m[1].trim().slice(0, 280);
}

/**
 * Annotate findings with git blame + commit context. Returns
 * { annotated, cached, skipped } counts.
 */
export function annotateGitHistory(scanRoot, findings) {
  if (process.env.AGENTIC_SECURITY_NO_GIT_HISTORY === '1') return { annotated: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { annotated: 0 };
  if (!_isGitRepo(scanRoot)) return { annotated: 0, reason: 'not-a-git-repo' };

  const messageCache = new Map();  // sha → body
  let annotated = 0, skipped = 0;

  // Batch the blame per file; a file whose batch fails is blamed line by line.
  const wantedByFile = new Map();
  for (let i = 0; i < findings.length && i < MAX_BLAME_PER_SCAN; i++) {
    const f = findings[i];
    if (!f || !f.file || !f.line) continue;
    if (!wantedByFile.has(f.file)) wantedByFile.set(f.file, []);
    wantedByFile.get(f.file).push(f.line);
  }
  const blameByFile = new Map();
  for (const [file, lines] of wantedByFile) blameByFile.set(file, _blameFile(scanRoot, file, lines));

  const wantedShas = [];
  for (const m of blameByFile.values()) if (m) for (const meta of m.values()) if (meta && meta.sha) wantedShas.push(meta.sha);
  for (const [sha, body] of _fullMessages(scanRoot, wantedShas)) messageCache.set(sha, body);

  for (let i = 0; i < findings.length && i < MAX_BLAME_PER_SCAN; i++) {
    const f = findings[i];
    if (!f || !f.file || !f.line) { skipped++; continue; }
    const batch = blameByFile.get(f.file);
    const blame = batch && batch.has(f.line) ? batch.get(f.line) : _blame(scanRoot, f.file, f.line);
    if (!blame) { skipped++; continue; }

    f.introducedBy = blame.author || null;
    f.introducedIn = blame.sha;
    f.introducedAt = blame.at || null;

    let body = messageCache.get(blame.sha);
    if (body === undefined) {
      body = _fullMessage(scanRoot, blame.sha);
      messageCache.set(blame.sha, body);
    }
    if (body) {
      const subj = body.split('\n')[0].slice(0, 120);
      f.introducedInMessage = subj;
      const prompt = _extractPrompt(body);
      if (prompt) f.originatingPrompt = prompt;
      // Mark AI-authored when commit message carries the Claude co-author trailer.
      if (/Co-Authored-By:\s*Claude/i.test(body)) f.aiAuthored = true;
    }
    annotated++;
  }
  return { annotated, skipped, capped: findings.length > MAX_BLAME_PER_SCAN };
}

/**
 * Generate a Slack-ready / PR-comment author-ping for a finding. Returns
 * a Markdown string with a per-finding callout.
 */
export function generateAuthorPing(finding) {
  if (!finding || !finding.introducedBy) return null;
  const where = `${finding.file || '?'}:${finding.line || 0}`;
  const lines = [];
  lines.push(`Hey @${finding.introducedBy.replace(/\s+/g, '.')} — heads-up on \`${where}\`:`);
  lines.push('');
  lines.push(`- **${(finding.severity || '?').toUpperCase()}** ${finding.vuln || finding.family || 'finding'}`);
  if (finding.introducedIn) lines.push(`- Introduced in \`${finding.introducedIn}\`${finding.introducedInMessage ? ` — _"${finding.introducedInMessage}"_` : ''}`);
  if (finding.originatingPrompt) lines.push(`- Originating prompt: _"${finding.originatingPrompt}"_`);
  lines.push(`- Could you take a look?`);
  return lines.join('\n');
}

export const _internals = { _parsePorcelain, _extractPrompt, _isGitRepo };
