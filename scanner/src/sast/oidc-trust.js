// OIDC trust policy evidence found in the repository itself (PRD FR 06).
//
// A repository can only show the cloud trust policy when that policy is kept in it (Terraform, CloudFormation, a JSON policy). Absence
// from the repository is not absence from the cloud account, so `absent` stays needs-review. Classification is of the `sub` (subject)
// condition for the GitHub OIDC issuer:
//   restrictive  every subject pins an exact repository and a ref or environment, with no wildcard beyond the ref part
//   permissive   a wildcard repository or owner, or a trust statement for the issuer with no subject condition at all
//   mismatched   the policy pins a repository other than the one named by `ownRepository` (when it is known)
//   absent       no policy for the GitHub issuer exists in the scanned files

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
    const other = subjects.find(({ subject }) => { const m = /^repo:([^/:*]+\/[^/:*]+)/.exec(subject); return m && m[1].toLowerCase() !== ownRepository.toLowerCase(); });
    if (other) return { status: 'mismatched', policies, evidence: other, note: `subject "${other.subject}" pins a repository other than ${ownRepository}` };
  }
  return { status: 'restrictive', policies, note: 'every subject pins one repository and a ref or environment' };
}

/** Apply the classification to OIDC findings in place. Never closes a finding on repository evidence alone. */
export function applyOidcTrust(findings, files, opts = {}) {
  const c = classifyOidcTrust(files, opts);
  for (const f of findings || []) {
    if (!f || !/^Pipeline: OIDC id-token: write/.test(String(f.vuln || ''))) continue;
    f.oidcTrust = { status: c.status, note: c.note, ...(c.evidence ? { evidence: c.evidence } : {}) };
    if (c.status === 'permissive' || c.status === 'mismatched') { f.severity = 'high'; f.disposition = 'needs-review'; f.missingEvidence = ['confirm the deployed trust policy matches the one in the repository']; }
    else if (c.status === 'restrictive') { f.missingEvidence = ['confirm the deployed trust policy matches the one in the repository']; f.severity = 'low'; }
    // absent: unchanged, the cloud-side policy is simply not verifiable from here
  }
  return c;
}
