# The 5-minute demo

<!-- seo: title="5-minute demo: scan a deliberately vulnerable app and see the assurance gate" description="Run one command against the bundled demo app and see both a severity gate and an assurance gate, with real captured output." -->

The repository ships a small, deliberately vulnerable [demo app](../../examples/demo-app/) so a first run always finds something. Clone this repository, or point the scanner at your own project once you have tried it.

## 1. Run it

```bash
npx @clear-capabilities/agentic-security-scanner ci examples/demo-app --assurance strict
```

`ci` is the CI-shaped entry point, the same command a pipeline runs. `--assurance strict` makes it gate on whether the scan *itself* finished cleanly, not just on what it found. (`--assurance` exists only on `ci`.)

## 2. Read what came back

Real captured output (the `npx` form prints the identical output):

```text
$ agentic-security ci examples/demo-app --assurance strict
[ci] full scan (no baseline ref detected)
[ci] 44 findings — 3 critical · 6 high · 7 medium · 16 low · 12 info
[ci] ⚠ scan-health=partial — EPSS exploit-probability data is stale (20745 day(s) old)
[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}
[ci] fail-on=critical  scan-exit=3
[ci] assurance gate FAILED (mode=strict): strict mode requires a fully complete scan; scanHealth.status is 'partial'
```

Two different failures in one run:

| Line | Gate | What it says | What to do |
|---|---|---|---|
| `fail-on=critical  scan-exit=3` | Severity | Real vulnerabilities at or above your threshold | Triage and fix. See [Fixing vulnerabilities](../guides/fixing-vulnerabilities.md) |
| `assurance gate FAILED (mode=strict)` | Assurance | The analysis did not finish cleanly (here, stale exploit-probability data) | Investigate the scan, not the findings. See [Scan health](../trust/scan-health.md) |

That is the first idea worth taking away: **"0 findings" and "the scan completed" are different claims**, and the tool keeps them apart.

## 3. Look at one finding

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/demo-app --format json --output report.json
```

Open `report.json` and find `struct:server.js:11:SQL_Injection_(Template_Literal)`. It carries a severity, a confidence, a corroboration list, a falsification verdict and `unreachable: false`, each a separate fact. [One finding's journey](../workflows/one-findings-journey.md) walks that exact finding through all ten lifecycle stages.

## Where next

- [15-minute quickstart](15-minute-quickstart.md): install, fix a finding, export a report, run it on your own project
- [How it works](../how-it-works/assurance-lifecycle.md)
- [The evidence model](../how-it-works/evidence-model.md)
