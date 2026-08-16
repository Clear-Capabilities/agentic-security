# CI setup

**Goal:** gate every pull request so a new critical (or high) vulnerability
can't merge — and, optionally, block risky deploys from your own terminal.

**Prerequisites:** a git repository with a CI provider. Commands are shown as
Claude Code (`/agentic-security:setup …`); the generator also runs from the
bare CLI.

---

## Generate a CI gate

```text
/agentic-security:setup --ci
```

It auto-detects your provider (or set `--provider github|gitlab|circleci|buildkite|jenkins`),
picks a severity threshold (`--fail-on critical|high|medium`), and does a
**dry-run by default** — nothing is written until you add `--apply`.

- **GitHub Actions** is generated inline.
- **GitLab / CircleCI / Buildkite / Jenkins** come from `scripts/ci-templates/`.

The generated job runs a baseline-aware scan on the PR, writes SARIF (so
findings show in your provider's security UI), posts a findings comment, and
sets the job's exit status from the scan's exit code (`3` critical, `2` high,
… — see [scanning](scanning.md#exit-codes)).

---

## GitHub Actions — the shortcut

If you're on GitHub, the fastest path is the committed reusable workflow. Copy
[`docs/examples/security.yml.example`](../examples/security.yml.example) to
`.github/workflows/security.yml` in your repo:

```yaml
name: Security scan
on:
  pull_request: {}
  push:
    branches: [main]
jobs:
  security:
    permissions:
      contents: read          # checkout
      security-events: write  # upload SARIF to the Security tab
      pull-requests: write    # post the findings comment
    uses: Clear-Capabilities/agentic-security/.github/workflows/scan.yml@main
    with:
      fail-on: critical
      baseline: ${{ github.event.pull_request.base.sha || 'HEAD~1' }}
      output-sarif: 'true'
```

`baseline:` makes the gate diff against the PR's base, so it fails only on
*newly introduced* findings — which is what makes it adoptable on a repo that
isn't clean yet.

---

## The baseline-then-gate workflow for existing repos

A repo with pre-existing findings shouldn't fail its first CI run on all of
them. Snapshot them once, then gate only on regressions:

```bash
# once, committed to the repo:
npx @clear-capabilities/agentic-security-scanner scan . --set-baseline
```

With a baseline in place (or the `baseline:` input above), CI reports only what
each PR *adds*. Pay the existing debt down over time; don't let new debt in.

---

## Block risky deploys locally

CI catches things at merge time. The pre-deploy gate catches them at deploy
time, in your own terminal:

```text
/agentic-security:setup --predeploy
```

It intercepts `vercel` / `fly` / `wrangler` deploys and blocks them on open
critical or CISA-KEV findings. Sub-commands: `install` (default), `check`,
`status`, `off`.

---

## Recurring CVE checks

To catch CVEs disclosed *after* your code merged, schedule the CVE watcher.
`scripts/ci-templates/cve-watch.github-actions.yml` is a ready-made cron
workflow; `/agentic-security:supply --cve-alerts` will also help you wire it in.

---

## Related

- [Scanning](scanning.md) — modes and exit codes the gate relies on
- [SBOM & AI-BOM](sbom-and-ai-bom.md) · [Compliance](compliance.md)
- [Configuration & env vars](../reference/configuration.md)
