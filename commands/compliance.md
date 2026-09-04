---
description: Compliance + auditor flows. Framework attestation, walkthrough, buyer-facing badge, stack audits, PR augmentation.
argument-hint: "[--report <fw>|--walkthrough <fw>|--attestation|--audit <target>|--pr]"
---

# /compliance

Compliance + auditor flows dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--report <framework>` | Generate automated technical-control evidence for a framework. Frameworks: `nist-ai-600-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act` |
| `--walkthrough <framework>` | Step-by-step auditor narrative with evidence mapping per control. Frameworks: `nist-csf-2`, `nist-ai-600-1`, `nist-privacy-1-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act`, `gdpr`, `hipaa-security-rule`, `ccpa` (or BYO at `.agentic-security/compliance/<id>/controls.json`) |
| `--attestation` | Render buyer-facing security posture artifact. `--format badge|onepager|page` |
| `--audit <target>` | Filters `last-scan.json`'s findings by keyword per target: `db`, `auth`, `rate-limit`, `webhook`, `env`, `csp-cors`, `llm-cost`, `prompt`. `deploy` and `launch` instead run `/secure`'s real readiness check for that intent, not a findings filter. |
| `--pr` | Generate a PR-description block: findings delta vs a persisted baseline + MITRE ATT&CK techniques on new findings + suggested reviewers by family + links to posture artifacts |
| `--gap` | Show only the failing controls, each with its observations — a worklist of what isn't clearing (see the `--gap` section below) |
| `--privacy` | NIST Privacy Framework 1.1 assessment with remediation per gap. Artifacts: `.agentic-security/privacy-framework.{json,md}` |

Bare `/compliance` (no flag) prints this mode menu. `--report` accepts `--format cli|json|oscal`; `--gap` accepts `--format cli|json`.

## `--gap` (close the deltas)

`--gap` with no framework argument filters the **NIST Privacy Framework 1.1** assessment (`--privacy`'s bucket model) to the `gap` bucket — this is the real `agentic-security compliance --gap` CLI subcommand, documented below. `--gap <framework>` filters that named framework's generic evaluation (`auditor-walkthrough.js#evaluateFramework`) to controls whose status is not `present` (i.e. `partial` or `manual` — no code-checked evidence clears them), each with its observations. It is a worklist of what isn't clearing, not a mapping to a specific closing command per control — that per-control command mapping described in earlier drafts of this doc does not exist in the code and has been removed rather than left aspirational.

## `--privacy` (NIST Privacy Framework 1.1)

Runs on every scan and writes `.agentic-security/privacy-framework.{json,md}`.
All 104 PF 1.1 controls are carried, and each lands in exactly one bucket:

| Bucket | Meaning |
|---|---|
| **gap** | Mapped to an engine signal, and that signal is failing — **this is the only bucket that emits a finding** |
| **not assessed** | NIST rates the control code-testable, but this engine has no signal for it. Disclosed by name. **Not a pass.** |
| **manual** | NIST rates the control not code-testable — governance, policy, process. Outside any scanner's reach. |
| **satisfied** | Mapped, and the signal is clean |

The split matters: of the 104 controls NIST rates **23 yes, 33 partial and 48 no**
for code-testability. A tool that reports the 48 governance controls as "passed"
because no rule fired against them is manufacturing assurance, so they are never
counted as satisfied — and neither are controls this engine simply does not check.

**Remediation.** Each gap carries an actionable remediation and is emitted as a
normal finding (`family: privacy-compliance`, `CWE-359`), so it flows through
triage and `/fix` like any other. Findings are **opt-in** via
`AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1`: a compliance opinion should not silently
become a build failure for a project that never asked for one. The assessment
artifact is written either way.

A scan that examined **no files** reports every control as *not assessed* rather
than satisfied — a clean signal from a run that read nothing is not evidence.

Backed by a real subcommand — `/compliance --privacy` runs it, and you can call
it directly:

```bash
agentic-security compliance                        # assessment + per-gap remediation
agentic-security compliance --gap                  # only the failing controls
agentic-security compliance --format json          # machine-readable
agentic-security compliance --fail-on gap          # exit 1 when a control fails (CI)
agentic-security compliance --list                 # bundled + BYO frameworks
agentic-security compliance --walkthrough <id>     # auditor narrative, any framework
AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1 agentic-security scan .   # gaps as fixable findings
```

It reads `.agentic-security/last-scan.json` rather than re-scanning: a compliance
answer is a statement about a scan that happened. With no scan to read it exits
**2** and says so, rather than assessing an empty project — which would report
every control as unassessed and sits one careless flag away from looking clean.

Exit codes: **0** report produced · **1** only with `--fail-on gap` and a failing
control · **2** nothing to assess, or an unknown framework.

## `--format json` (machine-readable export)

`--report <fw> --format json` emits the framework evaluation as structured JSON — one `{control, status, observations}` entry per control, `status` ∈ `present` (all mapped signals clear) / `partial` (some signal present but not all clear, or an unverifiable `rule:` mapping) / `manual` (no automated mapping at all). `--format cli` (default) renders the same evaluation as `--walkthrough`'s auditor narrative.

## `--format oscal` (NIST OSCAL assessment-results)

`--report <fw> --format oscal` emits an OSCAL 1.1.2 `assessment-results` document (`scanner/src/report/oscal.js`). The same flag works on the real CLI: `agentic-security compliance --report <fw> --format oscal`, and on the default NIST Privacy Framework assessment with no framework argument.

The one thing to know before consuming it: **a control the engine could not decide carries no OSCAL finding.** An OSCAL finding requires a binary `satisfied` / `not-satisfied` state, so a `manual` control — and, on the privacy path, an `engine-gap` control, meaning this scanner has no check for something NIST rates code-testable — appears as an observation with method `EXAMINE`, never as a finding. Counting findings and calling the rest passing would invert exactly the distinction this command exists to preserve. `--format json` above is the lossless view; OSCAL is the interoperable one. Full mapping table, including how `absent` and `partial` land: [docs/OSCAL.md](../docs/OSCAL.md).

## Examples

```bash
/compliance --report nist-ai-600-1              # NIST AI 600-1 attestation
/compliance --walkthrough owasp-asvs-5          # OWASP ASVS auditor walkthrough
/compliance --attestation --format onepager     # buyer-facing one-pager
/compliance --audit db                          # database posture audit
/compliance --pr                                # PR-description block
```

## Implementation

Every mode below runs a real, verified command. `--privacy`/`--walkthrough`(no `--format json`)/`--gap` (no framework) pass straight through to the real `agentic-security compliance` CLI subcommand already documented above; the rest call the backing posture modules directly, since no CLI flag exposes them.

```bash
FLAG="${1:-}"

case "$FLAG" in
  --report)
    FW="$2"
    FMT="cli"
    if [ "$3" = "--format" ] && [ -n "$4" ]; then FMT="$4"; fi
    node -e "
      const fs = require('fs');
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/auditor-walkthrough.js').then(aw => {
        let scan = null;
        try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
        if (!scan) { console.error('No .agentic-security/last-scan.json — run a scan first.'); process.exit(2); }
        const fwId = process.argv[1];
        const fw = aw.loadFramework('.', fwId);
        if (!fw) { console.error('Unknown framework \"' + fwId + '\". Try /compliance --walkthrough with --list, or a bundled id: nist-ai-600-1, owasp-asvs-5, owasp-llm-top-10, eu-ai-act, nist-csf-2, nist-privacy-1-1, gdpr, hipaa-security-rule, ccpa.'); process.exit(2); }
        const evaluation = aw.evaluateFramework('.', fw, scan);
        const format = process.argv[2];
        if (format === 'oscal') {
          import('${CLAUDE_PLUGIN_ROOT}/scanner/src/report/oscal.js').then(o => {
            console.log(JSON.stringify(o.toOSCALCompliance(fw, o.complianceRowsFromEvaluation(evaluation), { startedAt: scan._scanMeta && scan._scanMeta.startedAt }), null, 2));
          });
        } else if (format === 'json') {
          console.log(JSON.stringify({ framework: { id: fw.id, name: fw.name }, evaluation }, null, 2));
        } else {
          console.log(aw.renderWalkthrough(fw, evaluation, {}));
        }
      });
    " "$FW" "$FMT" ;;
  --walkthrough)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs compliance --walkthrough "$2" ;;
  --attestation)
    FMT="badge"
    if [ "$2" = "--format" ] && [ -n "$3" ]; then FMT="$3"; fi
    case "$FMT" in
      badge)    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs badge ;;
      onepager) python3 ${CLAUDE_PLUGIN_ROOT}/scripts/security-onepager.py --print ;;
      page)     python3 ${CLAUDE_PLUGIN_ROOT}/scripts/trust-page.py --contact security@example.com ;;
      *)        echo "Unknown --format \"$FMT\" for --attestation. Valid: badge, onepager, page." ;;
    esac ;;
  --audit)
    TARGET="$2"
    case "$TARGET" in
      deploy) node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs secure . --deploy --json ;;
      launch) node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs secure . --launch --json ;;
      *)
        node -e "
          const fs = require('fs');
          const KEYWORDS = {
            db: /\bsql\s*injection|\bdatabase\b|stored\s*xss.*db/i,
            auth: /\bauth(?:entication|orization)?\b|\bidor\b|broken-auth/i,
            'rate-limit': /rate[-\s]?limit/i,
            webhook: /webhook/i,
            env: /hardcoded[-\s]?secret|environment\s*variable|\.env\b/i,
            'csp-cors': /\bcsp\b|\bcors\b|clickjack|x-frame|content-security-policy|header-hardening/i,
            'llm-cost': /cost\s*advisory/i,
            prompt: /prompt\s*injection|\bLLM01\b/i,
          };
          const target = process.argv[1];
          const re = KEYWORDS[target];
          if (!re) { console.log(JSON.stringify({ message: 'Unknown --audit target \"' + target + '\". Valid: ' + Object.keys(KEYWORDS).join(', ') + ', deploy, launch.' })); process.exit(0); }
          let scan = null;
          try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
          if (!scan) { console.log(JSON.stringify({ message: 'No prior scan found. Run /scan --all first.' })); process.exit(0); }
          const hay = f => [f.vuln, f.family, f.owaspLlm].filter(Boolean).join(' ');
          const matched = (scan.findings || []).filter(f => re.test(hay(f)));
          console.log(JSON.stringify({
            target, matchedCount: matched.length,
            findings: matched.map(f => ({ id: f.id, vuln: f.vuln, severity: f.severity, file: f.file, line: f.line })),
          }, null, 2));
        " "$TARGET" ;;
    esac ;;
  --pr)
    REF="main"
    if [ "$2" = "--persist-baseline" ] && [ -n "$3" ]; then
      node -e "
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/pr-augment.js').then(pa => {
          const fs = require('fs');
          let scan = null;
          try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
          if (!scan) { console.error('No .agentic-security/last-scan.json — run a scan first.'); process.exit(2); }
          const fp = pa.persistBaseline('.', process.argv[1], scan);
          console.log(JSON.stringify({ persisted: fp }, null, 2));
        });
      " "$3"
    else
      if [ "$2" = "--baseline" ] && [ -n "$3" ]; then REF="$3"; fi
      node -e "
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/pr-augment.js').then(pa => {
          const r = pa.augmentPrBody('.', { baselineRef: process.argv[1] });
          if (!r.ok) { console.error(r.error); process.exit(2); }
          console.log(r.body);
        });
      " "$REF"
    fi ;;
  --gap)
    if [ -n "$2" ] && [ "$2" != "--format" ]; then
      FW="$2"
      node -e "
        const fs = require('fs');
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/auditor-walkthrough.js').then(aw => {
          let scan = null;
          try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
          if (!scan) { console.error('No .agentic-security/last-scan.json — run a scan first.'); process.exit(2); }
          const fwId = process.argv[1];
          const fw = aw.loadFramework('.', fwId);
          if (!fw) { console.error('Unknown framework \"' + fwId + '\".'); process.exit(2); }
          const evaluation = aw.evaluateFramework('.', fw, scan);
          const gaps = evaluation.filter(e => e.status !== 'present');
          console.log(JSON.stringify({ framework: fw.id, gapCount: gaps.length, gaps: gaps.map(g => ({ id: g.control.id, summary: g.control.summary, status: g.status, observations: g.observations })) }, null, 2));
        });
      " "$FW"
    else
      node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs compliance --gap "$@"
    fi ;;
  --privacy|"")
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs compliance ;;
  *)
    echo "Modes: --report --walkthrough --attestation --audit --pr --gap --privacy" ;;
esac
```

`--report <framework>` and `--gap <framework>` both call `auditor-walkthrough.js#loadFramework`/`evaluateFramework` directly — the same functions the real `compliance --walkthrough` CLI path uses internally, exposed here for raw JSON. There is no alias mechanism: `loadFramework()` does a plain `fw.id === id` match, so the framework argument must be a bundled id exactly (`nist-ai-600-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act`, …) or a BYO id under `.agentic-security/compliance/<id>/controls.json`. `--report`'s default (non-JSON) rendering calls the same `renderWalkthrough` narrative as `--walkthrough` — there is no separate "attestation" renderer in the code, so the two converge outside `--format json`.

`--walkthrough <framework>` and `--privacy`/bare `--gap` pass straight through to the real `agentic-security compliance` CLI subcommand (unchanged from the `--privacy` section above).

`--attestation --format badge|onepager|page` calls three independently real backends: the CLI's `badge` subcommand (`src/badge.js`, SVG), `scripts/security-onepager.py --print` (Markdown one-pager), and `scripts/trust-page.py --contact ...` (Markdown trust page). None of the three previously had any invocation path from this command.

`--audit <target>` is a keyword filter over `last-scan.json`'s findings (`vuln`/`family`/`owaspLlm` text) — not a dedicated per-target detector, disclosed as such. `deploy` and `launch` are different in kind: they run `agentic-security secure --deploy`/`--launch`, the real readiness-decision command (`posture/router.js#decide`), rather than filtering findings.

`--pr [--baseline <ref>]` calls `posture/pr-augment.js#augmentPrBody` directly — a fully real, unit-tested module (`test/pr-augment.test.js`) with zero prior CLI wiring anywhere in the codebase. It needs a persisted baseline to diff against; `--pr --persist-baseline <ref>` calls `persistBaseline` to snapshot the current scan under that ref (run this on the base branch first). With no baseline, `augmentPrBody` still returns a body — showing the whole current scan as "added" — rather than failing.
