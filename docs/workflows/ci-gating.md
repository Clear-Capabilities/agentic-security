# CI gating

<!-- seo: title="CI gating for AI-written code: a severity gate and an assurance gate" description="Gate pull requests on new findings and on whether the analysis itself finished, with baselines so the gate is adoptable on a repository that is not clean yet." -->

**Maturity:** GA

A pull request gate has two jobs, and Agentic Security keeps them separate:

1. **Severity gate.** Fail when a new finding at or above `--fail-on` appears.
2. **Assurance gate.** Fail (in `strict` mode) when the analysis did not complete, so an incomplete scan can never pass as green.

## Generate the job

```text
/agentic-security:setup --ci
```

It detects your provider (or take `--provider github|gitlab|circleci|buildkite|jenkins`), picks a threshold (`--fail-on critical|high|medium`), and is a dry run until you add `--apply`. The generated job runs a baseline-aware scan on the pull request, writes SARIF so findings appear in your provider's security UI, posts a findings comment, and sets the exit status from the scan.

On GitHub, the fastest path is the reusable workflow; copy [`security.yml.example`](../examples/security.yml.example). Full detail: [CI setup](../guides/ci-setup.md).

## The command underneath

```bash
agentic-security ci . --assurance strict
```

Captured output, with both gates in one run:

```text
[ci] full scan (no baseline ref detected)
[ci] 44 findings — 3 critical · 6 high · 7 medium · 16 low · 12 info
[ci] ⚠ scan-health=partial — EPSS exploit-probability data is stale (20745 day(s) old)
[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}
[ci] fail-on=critical  scan-exit=3
[ci] assurance gate FAILED (mode=strict): strict mode requires a fully complete scan; scanHealth.status is 'partial'
```

## Adopting it on a repository that is not clean

- **Baseline:** `scan . --set-baseline` snapshots existing findings; the CI gate diffs against the pull request's base so it fails only on *newly introduced* findings.
- **Assurance mode:** start with `standard` (reports scan health, never fails on it) and move to `strict` once your feeds and analyzers are reliably complete. See [assurance modes](../trust/assurance-modes.md).

## Beyond the pull request

- `setup --predeploy` blocks `vercel`, `fly` and `wrangler` deploys on critical findings.
- `setup --bodyguard` intercepts insecure AI-written edits before they reach disk.
- Exit codes and report formats: [Scanning](../guides/scanning.md#exit-codes).

## What a green gate means

A passing `strict` gate means no new actionable findings at your threshold *and* a complete scan. It does not mean the code is safe; see [trust and limitations](../trust/trust-and-limitations.md).
