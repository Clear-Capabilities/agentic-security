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

const MAX_BLAME_PER_SCAN = 500;
const SUBPROC_TIMEOUT_MS = 1500;
const PROMPT_MARKER_RE = /(?:^|\n)(?:Prompt|User asked|Original request|Co-Authored-By:\s*Claude)/i;

function _isGitRepo(scanRoot) {
  try {
    cp.execFileSync('git', ['rev-parse', '--git-dir'], { cwd: scanRoot, stdio: 'ignore', timeout: SUBPROC_TIMEOUT_MS });
    return true;
  } catch { return false; }
}

function _blame(scanRoot, file, line) {
  if (!file || !line || line < 1) return null;
  const rel = path.isAbsolute(file) ? path.relative(scanRoot, file) : file;
  if (rel.startsWith('..')) return null;
  try {
    const stdout = cp.execFileSync(
      'git',
      ['blame', '-L', `${line},${line}`, '--porcelain', '--', rel],
      { cwd: scanRoot, encoding: 'utf8', timeout: SUBPROC_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'] },
    );
    return _parsePorcelain(stdout);
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
      'git', ['show', '-s', '--format=%B', sha],
      { cwd: scanRoot, encoding: 'utf8', timeout: SUBPROC_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'] },
    );
  } catch { return ''; }
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

  for (let i = 0; i < findings.length && i < MAX_BLAME_PER_SCAN; i++) {
    const f = findings[i];
    if (!f || !f.file || !f.line) { skipped++; continue; }
    const blame = _blame(scanRoot, f.file, f.line);
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
