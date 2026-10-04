# Scanning

**Goal:** run a scan the right way for your situation, and understand what
comes back.

**Prerequisites:** Node.js ≥ 24. Commands are shown as bare CLI
(`npx @clear-capabilities/agentic-security-scanner …`); in Claude Code the
same thing is `/agentic-security:scan …`.

---

## The one command

```bash
npx @clear-capabilities/agentic-security-scanner scan .
```

That runs the full 12-pillar sweep — SAST, SCA, secrets, IaC, LLM safety,
MCP/agent-tool audit, auth/authZ, and more — over the current directory and
prints a verdict. To try it against a known-vulnerable target first, point it
at [`examples/demo-app`](../../examples/demo-app/).

---

## Scan modes

| I want to… | Command |
|---|---|
| Scan everything | `scan .` |
| Scan only what changed vs a git ref | `scan . --changed-since main` |
| Watch and re-scan on every save | `scan . --watch` |
| Snapshot current findings as a baseline | `scan . --set-baseline` |
| Show only findings new since the baseline | `scan . --since-baseline` |
| Scan one pillar only | `scan . --only sca` (also `sast`, `secrets`) |

`--watch` re-scans incrementally as files change and prints a running
risk-delta — useful while you're actively fixing. `--changed-since` limits the
scan to files git reports as modified, which is what CI uses on a pull request.

**Legacy or large codebases:** a first full scan can surface a lot. Snapshot it
as a baseline and then work only against what's new:

```bash
npx @clear-capabilities/agentic-security-scanner scan . --set-baseline
# fix new code over time; each scan shows only regressions:
npx @clear-capabilities/agentic-security-scanner scan . --since-baseline
```

---

## Reading the verdict

```text
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────
  • 1 critical · 6 high · 20 advisory

  Coverage: 6 files · flow=[js,py]
```

- **Verdict** — `❌ Not safe to deploy` when a critical or high finding is open;
  `✅ Safe to deploy` when none remains and the scan completed cleanly. If zero
  findings remain but the scan finished incompletely (e.g., file timeout or
  analyzer error), the verdict is `⚠️  Scan incomplete — cannot confirm safe to
  deploy`, which fires when `scanHealth.status !== 'complete'`.
- **Severity tiers** — `critical` and `high` first; `advisory` folds
  medium/low/info.
- **Coverage** — the files examined and the languages the flow engine ran, so
  you can confirm the whole surface was looked at.

Every finding is written in plain English — the stakes and the fix, not a CVE
number — and, where it applies, an estimated dollar cost if exploited.

### Exit codes

The process exit code is a machine-readable verdict, not an error signal:

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | highest severity is low or medium |
| `2` | at least one high |
| `3` | at least one critical |
| `4` | the scan itself errored (bad path, crash) |

So `scan . ; echo $?` printing `3` means "critical findings present," not "the
tool broke." CI gates key off these — see [CI setup](ci-setup.md).

---

## Output formats

```bash
npx @clear-capabilities/agentic-security-scanner scan . --format html --output report.html
```

| `--format` | Use it for |
|---|---|
| `cli` *(default)* | the terminal verdict |
| `html` | a self-contained, shareable report (charts + filterable table, no external resources) |
| `json` | scripting, or feeding another tool |
| `md` | pasting into a PR or doc |
| `sarif` | GitHub Code Scanning, IDE SARIF viewers (renders taint traces as code flows) |
| `csv` | spreadsheets |
| `cyclonedx` / `spdx` | SBOM — see [SBOM & AI-BOM](sbom-and-ai-bom.md) |
| `aibom` / `aibom-md` | AI-BOM — see [SBOM & AI-BOM](sbom-and-ai-bom.md) |

Every scan also writes machine-readable state to `.agentic-security/` (the
canonical `last-scan.json` that every other command reads), regardless of the
`--format` you chose.

---

## Suppressing a finding

When a finding is a genuine false positive on a specific line, annotate that
line:

```js
const q = `SELECT * FROM t WHERE id = ${id}`; // agentic-security-ignore: sql-injection
```

The pragma is **line-scoped** and matches the finding's rule id, vuln, CWE, or
family (`#` and `/* */` comment forms work too). A bare
`// agentic-security-ignore` with no rule id suppresses every finding on that
line. Every suppression is recorded — `scan . --include-suppressed` shows what
was hidden, so a suppression is never invisible.

Prefer fixing at the source over suppressing. A finding with no line number
(some structural detectors emit these) cannot be suppressed by pragma — fix it
instead.

---

## Haskell and Nix projects

| Topic | Behavior |
|---|---|
| Discovery | `.hs`, `.lhs`, `.hs-boot`, `.hsc`, `.nix`, `flake.lock`, and the Haskell manifests (`*.cabal`, `cabal.project`, `cabal.project.freeze`, `package.yaml`, `stack.yaml`, `stack.yaml.lock`). Found by file type, so no flag is needed. |
| Exclusions | `dist-newstyle/`, `.stack-work/`, `.cabal-sandbox/`, `.direnv/`, `result` and `nix/store/` are never walked. Two explicit exports are read by exact path: `dist-newstyle/cache/plan.json` / `.stack-work/dependencies.json` and `nix-export.json` / `.direnv/nix-export.json`. A source over the size cap is **not** analysed and is a scan-health condition. |
| Modes | `--format` (every report format), `--set-baseline` / `--since-baseline`, `--changed-since`, `--only` and `ci` all apply. (The editor and MCP surfaces that scan a single file add that file's imported modules as context and report only the file you asked about.) `--since-baseline` filters every bucket (code, secrets, supply chain), so a baselined dependency finding does not return as new when you edit another line. |
| Suppression | `-- agentic-security-ignore: <rule>` (Haskell, also `{- -}`) and `# agentic-security-ignore: <rule>` (Nix, also `/* */`). Line-scoped, matched by exact rule id, family or CWE (never a substring), and recognised only inside a comment. A malformed pragma suppresses nothing and is reported. Every suppression is logged. |
| Partial coverage | Template Haskell, CPP branches, foreign imports, dynamic Nix attributes, unreadable files and a stale resolved plan are stated as limitations or scan-health conditions. `scanHealth.status` is then `partial`. |
| Exit codes | the usual `0` / `1` / `2` / `3` / `4`; `ci --assurance strict` additionally fails on any incomplete analysis. |

Without an advisory snapshot the dependency half of a Haskell or Nix scan is not performed, and the verdict says so: see
[Haskell](haskell.md#dependencies-advisories-and-the-software-bill-of-materials) and [Nix and NixOS](nix-nixos.md).

## Related

- [Fixing vulnerabilities](fixing-vulnerabilities.md)
- [CI setup](ci-setup.md)
- [CLI reference](../reference/cli.md) · [Configuration & env vars](../reference/configuration.md)
