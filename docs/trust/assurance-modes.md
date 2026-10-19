# Assurance modes

<!-- seo: title="Assurance modes: gate CI on whether the analysis finished" description="advisory, standard and strict assurance modes on agentic-security ci: separate a severity gate failure from an incomplete-analysis failure." -->

**Maturity:** GA

CI can fail for two unrelated reasons, and Agentic Security keeps them apart:

- **The severity gate.** Real vulnerabilities were found at or above `--fail-on`. Fix the code.
- **The assurance gate.** The analysis itself did not finish cleanly, whatever it found. Investigate the scan.

`--assurance` exists on `ci` only. There is no `scan --assurance`.

## The three modes

| Mode | Behavior |
|---|---|
| `advisory` | Reports scan health. Never fails the build over it. |
| `standard` (default) | Mechanically identical to `advisory`. |
| `strict` | Fails when `scanHealth.status` is not `complete`. |

## Captured output

Real output from `agentic-security ci examples/demo-app --assurance strict` on a machine whose local exploit-probability cache is stale:

```text
$ agentic-security ci examples/demo-app --assurance strict
[ci] full scan (no baseline ref detected)
[ci] 44 findings — 3 critical · 6 high · 7 medium · 16 low · 12 info
[ci] ⚠ scan-health=partial — EPSS exploit-probability data is stale (20745 day(s) old)
[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}
[ci] fail-on=critical  scan-exit=3
[ci] assurance gate FAILED (mode=strict): strict mode requires a fully complete scan; scanHealth.status is 'partial'
```

Two failure classes in one run:

- `fail-on=critical  scan-exit=3` is the severity gate.
- `assurance gate FAILED (mode=strict)` is the assurance gate.

On a run whose status is `complete`, the last line reads `[ci] assurance gate PASSED (mode=strict)`.

## Choosing a mode

- Use `strict` where a clean result is used as a release signal. It makes "the scan did not finish" a failure instead of a footnote.
- Use `standard` or `advisory` while you are adopting, or where a flaky feed must not block merges. The condition is still printed.

## Go deeper

- [Walkthrough: assurance modes](../walkthroughs/assurance-modes.md)
- [CI setup](../guides/ci-setup.md)
- [Scan health](scan-health.md)
