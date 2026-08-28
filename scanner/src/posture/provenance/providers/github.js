// GitHub provider enrichment (Finding Provenance PRD, M3 §3.4). Strictly
// opt-in — see config.js's resolveProviderConfig. Every export returns null
// immediately, with zero network calls, when unconfigured.
import { resolveProviderConfig } from './config.js';

const DEFAULT_API_BASE = 'https://api.github.com';

function ownerRepoFromRemote(remoteUrl) {
  // Handles both "git@github.com:owner/repo.git" and
  // "https://github.com/owner/repo.git" — the two forms `git remote -v`
  // actually produces.
  const m = String(remoteUrl || '').match(/github\.com[:/]([^/]+)\/([^/.]+?)(?:\.git)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

export async function fetchPRMetadata(scanRoot, commitSha, remoteUrl, config) {
  if (!config || !config.token) return null;
  const or = ownerRepoFromRemote(remoteUrl);
  if (!or) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  try {
    const r = await fetch(`${base}/repos/${or.owner}/${or.repo}/commits/${commitSha}/pulls`, {
      headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/vnd.github+json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    const prs = await r.json();
    if (!Array.isArray(prs) || prs.length === 0) return null;
    const pr = prs[0];
    return {
      prNumber: pr.number,
      reviewers: (pr.requested_reviewers || []).map((u) => u.login),
      approvals: null, // GitHub's PR-list-by-commit endpoint doesn't include review state; a real approvals count needs a second call, deliberately not made here to keep this a single-request enrichment.
      mergedAt: pr.merged_at || null,
    };
  } catch {
    return null;
  }
}

export async function fetchCodeowners(scanRoot, remoteUrl, config) {
  if (!config || !config.token) return null;
  const or = ownerRepoFromRemote(remoteUrl);
  if (!or) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  for (const path of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
    try {
      const r = await fetch(`${base}/repos/${or.owner}/${or.repo}/contents/${path}`, {
        headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/vnd.github+json' },
        signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) continue;
      const body = await r.json();
      if (!body.content) continue;
      const text = Buffer.from(body.content, 'base64').toString('utf8');
      return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    } catch { continue; }
  }
  return null;
}

export { resolveProviderConfig };
