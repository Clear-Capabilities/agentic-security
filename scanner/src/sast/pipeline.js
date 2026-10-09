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


// Matches of the workflow-wide `env:` secret pattern, as { index, end }. See the entry in PIPELINE_PATTERNS.
// The header is `^env\s*:\s*\n`; its greedy `\s*` ends at the last newline of the whitespace run, and every earlier choice
// of newline only replays the same lines, so the lazy line loop starts at the line after that newline. Each following line
// is either the assignment (the tail, tried first, as the lazy loop does) or must itself start with a space or tab.
const _ENV_HEAD_RE = /^env\s*:\s*/gm;
const _ENV_TAIL_RE = /[ \t]+[A-Za-z0-9_]+\s*:\s*\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/y;
export function* scanEnvSecrets(raw, stats) {
  const head = new RegExp(_ENV_HEAD_RE.source, _ENV_HEAD_RE.flags);
  const tail = new RegExp(_ENV_TAIL_RE.source, _ENV_TAIL_RE.flags);
  let pos = 0;
  while (pos <= raw.length) {
    head.lastIndex = pos;
    const h = head.exec(raw);
    if (!h) return;
    const afterHead = h.index + h[0].length;
    const colon = raw.indexOf(':', h.index + 3);
    const lastNl = raw.lastIndexOf('\n', afterHead - 1);
    if (lastNl <= colon) { pos = h.index + 1; continue; }   // no newline after the colon: not a header
    let s = lastNl + 1;
    let end = -1;
    for (;;) {
      tail.lastIndex = s;
      if (stats) stats.tailAttempts += 1;
      const t = tail.exec(raw);
      if (t) { end = s + t[0].length; break; }
      const c = raw.charCodeAt(s);
      if (c !== 32 && c !== 9) break;                      // the line loop needs an indented line
      const nl = raw.indexOf('\n', s);
      if (nl < 0) break;
      s = nl + 1;
    }
    if (end < 0) { pos = h.index + 1; continue; }
    yield { index: h.index, end };
    pos = end > h.index ? end : h.index + 1;
  }
}

const PIPELINE_PATTERNS = [
  // ── build hooks common to Haskell (ghcup, Cabal, Stack, Hackage) and Nix pipelines ──
  {
    re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g,
    vuln: 'Pipeline: remote script piped into a shell (unverified installer)',
    sev: 'high', cwe: 'CWE-494',
    fix: 'Download the installer to a file, verify its published checksum or signature, then run it. Installers for ghcup, Nix and similar tools are a common supply-chain target when piped straight into `sh`.',
  },
  {
    re: /\bnix\s+(?:run|shell|develop|build|profile\s+install|eval)\b[^\n]*?\b(?:github|gitlab|sourcehut):[\w.-]+\/[\w.-]+(?!\/[0-9a-f]{40}\b)(?=[\s#?]|$)/g,
    vuln: 'Pipeline: Nix flake reference executed without a pinned revision',
    sev: 'high', cwe: 'CWE-829',
    fix: 'Pin the flake reference to a full commit (`github:owner/repo/<40-hex-rev>`) or run it from this repository\'s own locked flake, so CI cannot execute whatever the branch points to today.',
  },
  {
    re: /\bnix\b[^\n]*(?:--accept-flake-config|--option\s+sandbox\s+false|--option\s+substituters\s+http:|--extra-trusted-public-keys|--impure\b)/g,
    vuln: 'Pipeline: Nix evaluation or build trust relaxed in CI',
    sev: 'medium', cwe: 'CWE-693',
    fix: 'Do not accept a flake\'s own configuration, disable the sandbox, add unauthenticated substituters or evaluate impurely in CI. Put the trust decision in the repository\'s reviewed configuration instead.',
  },
  {
    // Equivalent to /^env\s*:\s*\n(?:[ \t]+[^\n]*\n)*?[ \t]+[A-Za-z0-9_]+\s*:\s*\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/gm,
    // which backtracked catastrophically on a comment-blanked workflow (blanking leaves runs of blank lines, and `\s*`, `\n` and
    // the lazy line loop can all claim them): a real repository's CI directory made a scan run for many minutes. The matcher
    // below returns the same match starts and ends, in one pass over each `env:` block. Pinned against the original expression
    // by test/pipeline-env-secret.test.js.
    scan: scanEnvSecrets,
    vuln: 'Pipeline: secret exposed at workflow-wide environment scope',
    sev: 'medium', cwe: 'CWE-522',
    fix: 'Set secrets such as a Hackage or Cachix token on the single step that needs them (`env:` under that step), not at the top of the workflow where every step and every third-party action can read them.',
  },
  {
    re: /\bref\s*:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}/g,
    vuln: 'Pipeline: pull_request_target checks out untrusted pull request code',
    sev: 'high', cwe: 'CWE-829',
    fix: 'A `pull_request_target` workflow runs with repository secrets. Never check out and build the pull request head in it (a Cabal custom Setup.hs, a Nix flake or a build hook would run attacker code with those secrets); use `pull_request`, or split the privileged step.',
    contextRe: /\bpull_request_target\b/,
  },
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
    let matches;
    if (p.scan) matches = p.scan(raw);
    else {
      const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
      matches = (function* () { let mm; while ((mm = re.exec(raw))) yield mm; })();
    }
    for (const m of matches) {
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
export function toPBOM(fileContents, meta = {}, extras = {}) {
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
    ...(extras.languageBuild && (extras.languageBuild.haskell || extras.languageBuild.nix) ? { languageBuild: extras.languageBuild } : {}),
    summary: {
      totalWorkflows: workflows.length,
      totalActions: workflows.reduce((n, w) => n + w.uses.length, 0),
      pinnedActions: workflows.reduce((n, w) => n + w.uses.filter(u => u.pinned).length, 0),
      oidcWorkflows: workflows.filter(w => w.oidcEnabled).length,
    },
  };
}
