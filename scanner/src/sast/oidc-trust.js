// OIDC trust policy evidence found in the repository itself (PRD FR 06).
//
// A repository can only show the cloud trust policy when that policy is kept in it (Terraform, CloudFormation, a JSON policy). Absence
// from the repository is not absence from the cloud account, so `absent` stays needs-review. Classification is of the `sub` (subject)
// condition for the GitHub OIDC issuer:
//   restrictive  every subject pins an exact repository and a ref or environment, with no wildcard beyond the ref part
//   permissive   a wildcard repository or owner, or a trust statement for the issuer with no subject condition at all
//   mismatched   no subject pins this repository (`ownRepository`, when it is known); a policy that trusts this repository and
//                others as well is not a mismatch, since one role is often shared by several repositories
//   absent       no policy for the GitHub issuer exists in the scanned files

import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';

const ISSUER = /token\.actions\.githubusercontent\.com/;
const SUB_RE = /token\.actions\.githubusercontent\.com(?::|"\s*:\s*\{?\s*")?\s*sub["']?\s*[:=]?\s*[\[\{]?\s*["']([^"'\]\}]+)["']/gi;
const SUB_LOOSE = /["']?(?:token\.actions\.githubusercontent\.com:)?sub["']?\s*[:=]\s*\[?\s*["'](repo:[^"']+)["']/gi;

export function classifyOidcTrust(files, { ownRepository = null } = {}) {
  const policies = [];
  for (const [file, text] of Object.entries(files || {})) {
    if (typeof text !== 'string' || !ISSUER.test(text)) continue;
    if (!/\.(?:tf|json|ya?ml|template|hcl)$/i.test(file)) continue;
    const subs = new Set();
    for (const re of [SUB_RE, SUB_LOOSE]) { re.lastIndex = 0; let m; while ((m = re.exec(text))) subs.add(m[1]); }
    policies.push({ file, subjects: [...subs] });
  }
  if (!policies.length) return { status: 'absent', policies: [], note: 'no trust policy for the GitHub OIDC issuer in the scanned files; the cloud account may still have one' };
  const subjects = policies.flatMap((p) => p.subjects.map((s) => ({ file: p.file, subject: s })));
  if (!subjects.length) return { status: 'permissive', policies, note: 'a trust statement names the GitHub OIDC issuer but no subject condition was found' };
  const bad = subjects.find(({ subject }) => /^\*$|^repo:\*|^repo:[^/:*]+\/\*(?::|$)|:\*$/.test(subject) && !/^repo:[^/:*]+\/[^/:*]+:(?:ref|environment|pull_request)/.test(subject));
  if (bad) return { status: 'permissive', policies, evidence: bad, note: `subject "${bad.subject}" admits more than one repository or any ref` };
  if (ownRepository) {
    const repoOf = (subject) => { const m = /^repo:([^/:*]+\/[^/:*]+)/.exec(subject); return m ? m[1].toLowerCase() : null; };
    const mine = subjects.some(({ subject }) => repoOf(subject) === ownRepository.toLowerCase());
    if (!mine) {
      const other = subjects.find(({ subject }) => repoOf(subject));
      return { status: 'mismatched', policies, evidence: other || subjects[0], note: `no subject pins ${ownRepository}; the policy in the repository is not the one this workflow's token is checked against` };
    }
  }
  return { status: 'restrictive', policies, note: 'every subject pins one repository and a ref or environment' };
}

/** Apply the classification to OIDC findings in place. Never closes a finding on repository evidence alone. */
export function applyOidcTrust(findings, files, opts = {}) {
  const c = classifyOidcTrust(files, opts);
  for (const f of findings || []) {
    if (!f || !/^Pipeline: OIDC id-token: write/.test(String(f.vuln || ''))) continue;
    f.oidcTrust = { status: c.status, note: c.note, ...(c.evidence ? { evidence: c.evidence } : {}), ownRepository: opts.ownRepository || null, ownRepositoryBasis: opts.ownRepositoryBasis || (opts.ownRepository ? 'supplied' : 'unknown: the mismatched check was not made') };
    if (c.status === 'permissive' || c.status === 'mismatched') { f.severity = 'high'; f.disposition = 'needs-review'; f.missingEvidence = ['confirm the deployed trust policy matches the one in the repository']; }
    else if (c.status === 'restrictive') { f.missingEvidence = ['confirm the deployed trust policy matches the one in the repository']; f.severity = 'low'; }
    // absent: unchanged, the cloud-side policy is simply not verifiable from here
  }
  return c;
}

/**
 * This repository's GitHub name (`owner/repo`), with the basis it came from: the `origin` remote of the scanned tree, else
 * `GITHUB_REPOSITORY` when the scan runs inside GitHub Actions on its own checkout. Null when neither names a GitHub repository;
 * the mismatched check is then not made, and the report says so.
 */
export function resolveOwnRepository(scanRoot, env = process.env) {
  if (scanRoot) {
    const r = spawnSync('git', hardenGitArgs(['config', '--get', 'remote.origin.url']), { cwd: scanRoot, env: hardenGitEnv({}), encoding: 'utf8' });
    const url = r.status === 0 ? String(r.stdout || '').trim() : '';
    const m = /^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(url);
    if (m) return { name: m[1], basis: 'git remote origin' };
  }
  if (env.GITHUB_ACTIONS === 'true' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY || '') && env.GITHUB_WORKSPACE && scanRoot && path.resolve(env.GITHUB_WORKSPACE) === path.resolve(scanRoot)) {
    return { name: env.GITHUB_REPOSITORY, basis: 'GITHUB_REPOSITORY (GitHub Actions)' };
  }
  return null;
}
