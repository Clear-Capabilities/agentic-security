// 0.7.0 Feat-9: Pipeline / GitHub Actions integrity detector with PBOM emitter.
//
// Catches the canonical CI/CD security mistakes:
//   - Floating action tags (uses: foo/bar@main)        — supply-chain hijack vector
//   - Third-party action without SHA pinning           — same threat
//   - Excessive permissions (write-all)                — token-blast-radius
//   - Secret echoed in run: step                       — leakage
//   - OIDC id-token: write without aud restriction     — token theft / re-use
//   - script-injection in github.event.<...>           — RCE in workflow
//
// Same finding shape as scanIaC; produced separately so the rule set is small and tunable.

const _GH_WORKFLOW_RE = /(?:^|\/)\.github\/workflows\/.*\.ya?ml$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|examples?|fixtures?)\//i;

const PIPELINE_PATTERNS = [
  {
    re: /\buses\s*:\s*[\w-]+\/[\w-]+@(?:main|master|latest)\b/g,
    vuln: 'Pipeline: GitHub Action pinned to floating tag',
    sev: 'medium', cwe: 'CWE-1357',
    fix: 'Pin third-party actions to a 40-char commit SHA. The tag can be re-pointed by the publisher (or an attacker who compromises them) without your knowledge.',
  },
  {
    re: /\buses\s*:\s*(?!actions\/)[\w-]+\/[\w-]+@v?\d+(?!\.\d+\.\d+)\b/g,
    vuln: 'Pipeline: Third-party action pinned to major-version tag (mutable)',
    sev: 'medium', cwe: 'CWE-1357',
    fix: 'Tag like @v3 is mutable. For first-party `actions/*` it is generally safe. For any third-party action, pin to a full SHA.',
  },
  {
    re: /\bpermissions\s*:\s*write-all\b/g,
    vuln: 'Pipeline: permissions set to write-all (excessive scope)',
    sev: 'high', cwe: 'CWE-272',
    fix: 'Replace `permissions: write-all` with the minimum required permissions block, e.g. `contents: read` + the specific scopes the workflow needs.',
  },
  {
    re: /run\s*:\s*[\s\S]*?echo\s+[^\n]*\$\{?\s*\{?\s*secrets\.[A-Z0-9_]+/g,
    vuln: 'Pipeline: secret echoed to logs',
    sev: 'high', cwe: 'CWE-532',
    fix: 'Never echo a `${{ secrets.* }}` value to step output. Use `::add-mask::` if you must reference it, and prefer reading the secret directly into a tool that doesn\'t print it.',
  },
  {
    re: /\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|head_commit\.message|inputs\.[A-Za-z_][\w]*)\s*\}\}/g,
    vuln: 'Pipeline: untrusted github.event input interpolated into shell context',
    sev: 'critical', cwe: 'CWE-78',
    fix: 'Pipe untrusted github.event values through an environment variable instead of interpolating into the shell, e.g. `env: TITLE: ${{ github.event.issue.title }}` then use `"$TITLE"` in the run script.',
    // Suppress the exact pattern this fix recommends: a pure YAML mapping
    // entry (`KEY: ${{ github.event.… }}`) assigns the value to an env var
    // at the workflow-engine level, not into a shell command string — the
    // shell later reads it as an ordinary env-var reference ("$KEY"), which
    // is safe. A match embedded inside a larger line (a run: script body)
    // does not have this shape and is still flagged.
    lineSafeRe: /^[\w.-]+\s*:\s*\$\{\{[^}]*\}\}\s*$/,
  },
  {
    re: /\bid-token\s*:\s*write\b/g,
    vuln: 'Pipeline: OIDC id-token: write without explicit aud restriction',
    sev: 'medium', cwe: 'CWE-1188',
    fix: 'When granting `id-token: write`, configure the cloud-side trust policy to require a specific `aud` claim and `sub` pattern. Otherwise any workflow on the repo can mint a token usable against this trust policy.',
    contextRe: /\b(?:aud|audience)\s*:/, contextNeg: true, // fire only if NO aud/audience configured
  },
];

export function scanPipeline(fp, raw) {
  if (!_GH_WORKFLOW_RE.test(fp.replace(/\\/g, '/'))) return [];
  if (_NONPROD_RE.test(fp.replace(/\\/g, '/'))) return [];
  if (!raw || raw.length > 200_000) return [];
  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();
  for (const p of PIPELINE_PATTERNS) {
    if (p.contextRe) {
      const present = p.contextRe.test(raw);
      if (p.contextNeg && present) continue; // suppress: required context exists
      if (!p.contextNeg && !present) continue;
    }
    const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
    let m;
    while ((m = re.exec(raw))) {
      const line = raw.substring(0, m.index).split('\n').length;
      if (p.lineSafeRe && p.lineSafeRe.test((lines[line - 1] || '').trim())) continue;
      const id = `pipeline:${fp}:${line}:${p.vuln.replace(/\s/g, '_').slice(0, 48)}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id, kind: 'iac', severity: p.sev, vuln: p.vuln,
        cwe: p.cwe, stride: 'Tampering',
        file: fp, line, snippet: (lines[line - 1] || '').trim(),
        fix: p.fix,
      });
    }
  }
  return findings;
}

// PBOM emitter: a Pipeline Bill of Materials. Lists every workflow file, every
// `uses:` step with its pin (SHA or tag), every secret reference, every
// permissions block. The PBOM is meant to be stored alongside the SBOM and
// produced from the same scan.
export function toPBOM(fileContents, meta = {}) {
  const workflows = [];
  for (const [fp, raw] of Object.entries(fileContents || {})) {
    if (!_GH_WORKFLOW_RE.test(fp.replace(/\\/g, '/'))) continue;
    const usesArr = [];
    const usesRe = /\buses\s*:\s*([\w-]+\/[\w-]+)@([^\s]+)/g;
    let m;
    while ((m = usesRe.exec(raw))) {
      usesArr.push({
        action: m[1],
        pin: m[2],
        pinned: /^[a-f0-9]{40}$/.test(m[2]),
      });
    }
    const secretRefs = Array.from(new Set([...(raw.match(/\bsecrets\.[A-Z0-9_]+/g) || [])]));
    const permsBlock = (raw.match(/\bpermissions\s*:[^\n]*(?:\n\s+[^\n]*)*/g) || []).map(s => s.trim());
    const idToken = /\bid-token\s*:\s*write\b/.test(raw);
    workflows.push({ file: fp, uses: usesArr, secretsReferenced: secretRefs, permissions: permsBlock, oidcEnabled: idToken });
  }
  return {
    pbomFormat: 'agentic-security PBOM',
    version: '1',
    generatedAt: meta.startedAt || new Date().toISOString(),
    workflows,
    summary: {
      totalWorkflows: workflows.length,
      totalActions: workflows.reduce((n, w) => n + w.uses.length, 0),
      pinnedActions: workflows.reduce((n, w) => n + w.uses.filter(u => u.pinned).length, 0),
      oidcWorkflows: workflows.filter(w => w.oidcEnabled).length,
    },
  };
}
