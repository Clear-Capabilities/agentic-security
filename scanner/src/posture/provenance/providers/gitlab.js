// GitLab provider enrichment (Finding Provenance PRD, M3 §3.4). Same
// contract as providers/github.js — strictly opt-in, zero network calls
// when unconfigured.
import { resolveProviderConfig } from './config.js';

const DEFAULT_API_BASE = 'https://gitlab.com/api/v4';

function projectPathFromRemote(remoteUrl) {
  const m = String(remoteUrl || '').match(/gitlab\.com[:/](.+?)(?:\.git)?$/);
  return m ? m[1] : null;
}

export async function fetchPRMetadata(scanRoot, commitSha, remoteUrl, config) {
  if (!config || !config.token) return null;
  const projectPath = projectPathFromRemote(remoteUrl);
  if (!projectPath) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  const encodedProject = encodeURIComponent(projectPath);
  try {
    const r = await fetch(`${base}/projects/${encodedProject}/repository/commits/${commitSha}/merge_requests`, {
      headers: { 'PRIVATE-TOKEN': config.token },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    const mrs = await r.json();
    if (!Array.isArray(mrs) || mrs.length === 0) return null;
    const mr = mrs[0];
    return {
      prNumber: mr.iid,
      reviewers: (mr.reviewers || []).map((u) => u.username),
      approvals: typeof mr.upvotes === 'number' ? mr.upvotes : null,
      mergedAt: mr.merged_at || null,
    };
  } catch {
    return null;
  }
}

export async function fetchCodeowners(scanRoot, remoteUrl, config) {
  if (!config || !config.token) return null;
  const projectPath = projectPathFromRemote(remoteUrl);
  if (!projectPath) return null;
  const base = config.baseUrl || DEFAULT_API_BASE;
  const encodedProject = encodeURIComponent(projectPath);
  try {
    const r = await fetch(`${base}/projects/${encodedProject}/repository/files/CODEOWNERS/raw?ref=HEAD`, {
      headers: { 'PRIVATE-TOKEN': config.token },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    const text = await r.text();
    return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  } catch {
    return null;
  }
}

export { resolveProviderConfig };
