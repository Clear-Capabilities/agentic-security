---
description: Experimental + AI-driven. Self-audit, model rescan, rule synth, cross-repo, risk/time quantification.
argument-hint: "[--claude-audit|--model-rescan|--synthesize-rule|--cross-repo|--risk-dollars|--time-to-fix|--llm]"
---

# /labs

Experimental + AI-driven analyses dispatcher. Modes that don't fit cleanly under scan / fix / triage / posture / compliance / supply / setup land here.

## Modes

| Flag | Behaviour |
|---|---|
| `--claude-audit` | Analyze patterns in Claude-introduced findings + draft CLAUDE.md stanzas to pre-empt them |
| `--model-rescan` | Re-validate the current scan with a different LLM and show the delta |
| `--synthesize-rule` | LLM-assisted detector-spec extraction from sample vulnerable files for a given CWE — writes a JSON spec for human review, never auto-incorporated |
| `--cross-repo` | Look up sibling-repo fixes + triage decisions for the same family from this developer's cross-repo history |
| `--risk-dollars` | Expected-value-of-exploitation in USD per finding (EV = EPSS × Impact × Reachability) |
| `--time-to-fix` | Estimate engineering hours per finding from family base + patch shape + reachability |
| `--llm` | LLM-specific risk surface: prompt injection, model loading, MCP audit, AI-BOM |

Bare `/labs` (no flag) prints this mode menu.

## Graduation status

Labs modes are experimental by intent. Maturity today:

| Mode | Status |
|---|---|
| `--llm` | **Stable** — candidate to promote to a first-class `/scan --llm` surface. |
| `--risk-dollars`, `--time-to-fix` | **Stable** — candidates to surface under `/posture`. |
| `--claude-audit`, `--cross-repo` | **Beta** — output shape may change. |
| `--model-rescan` | **Beta** — real producer as of the Stage 6 correctness audit (see below); still gated on an LLM endpoint being configured. |
| `--synthesize-rule` | **Experimental** — gated on env vars; not yet load-bearing. |

"Stable" modes keep working from `/labs` even after they're promoted; promotion adds a primary path, it doesn't remove the labs one.

## Examples

```bash
/labs --claude-audit                             # AI self-reflection report
/labs --model-rescan --model claude-opus-5       # re-validate with newer model
/labs --synthesize-rule --cwe CWE-79 --lang java --files Bad1.java Bad2.java --out spec.json
/labs --cross-repo <finding-id>                  # sibling-repo lookup
/labs --risk-dollars --top 10                    # money-priority view
/labs --time-to-fix --summary                    # eng-hour rollup
/labs --llm                                      # LLM/MCP risk surface
```

## Implementation

All seven modes below run a real, verified command. `--model-rescan` was the one exception until the Stage 6 correctness audit: `posture/model-rescan.js`'s `diffValidatorRuns()` expects a `{model, results: {findingId: {verdict, reason}}}` run file, but nothing in the codebase — including `llm-validator/index.js`, the module that actually calls an LLM — ever wrote a file in that shape. Fixed by adding the missing producer, `model-rescan.js#runModelRescan(scanRoot, {toModel})`: it re-validates the last scan's findings twice through `llm-validator/index.js#validateMany` — once under whatever model the environment currently resolves to ("from"), once under `toModel` via the existing per-role override `AGENTIC_SECURITY_LLM_MODEL_VALIDATE` (`llm-validator/providers.js` already supports this; no new plumbing needed) — then feeds both runs into the already-built `diffValidatorRuns`/`persistRescanReport`/`summarizeDelta`. Requires an LLM endpoint configured (`AGENTIC_SECURITY_LLM_ENDPOINT`); with none configured, `validateMany` degrades every finding to `unvalidated` with no network call, same as everywhere else in this codebase.

```bash
FLAG="${1:-}"
case "$FLAG" in
  --claude-audit)
    node -e "
      const fs = require('fs');
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/claude-authorship.js').then(ca => {
        let scan = null;
        try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
        if (!scan) { console.log(JSON.stringify({ message: 'No prior scan found. Run /scan --all first.' })); process.exit(0); }
        const findings = scan.findings || [];
        const analysis = ca.analyzeAuthorshipPatterns(findings);
        console.log(JSON.stringify({
          analysis,
          suggestions: ca.suggestClaudeMdEvolution(analysis),
          promptClusters: ca.extractOriginatingPromptCluster(findings),
        }, null, 2));
      });
    " ;;
  --cross-repo)
    node -e "
      const fs = require('fs');
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/cross-repo-memory.js').then(cr => {
        const id = process.argv[1] || '';
        let scan = null;
        try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
        if (!scan) { console.log(JSON.stringify({ message: 'No prior scan found. Run /scan --all first.' })); process.exit(0); }
        const finding = (scan.findings || []).find(f => f.id === id);
        if (!finding) { console.log(JSON.stringify({ message: id ? 'No finding with that id in the last scan.' : 'Usage: /labs --cross-repo <finding-id>' })); process.exit(0); }
        const signals = cr.findSiblingSignals('.', finding);
        console.log(JSON.stringify({
          finding: { id: finding.id, family: finding.family, vuln: finding.vuln },
          signals, note: cr.renderSiblingNote(signals),
        }, null, 2));
      });
    " "$2" ;;
  --risk-dollars)
    TOP=10
    if [ "$2" = "--top" ] && [ -n "$3" ]; then TOP="$3"; fi
    node -e "
      const fs = require('fs');
      const top = Number(process.argv[1]) || 10;
      let scan = null;
      try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
      if (!scan) { console.log(JSON.stringify({ message: 'No prior scan found. Run /scan --all first.' })); process.exit(0); }
      const findings = (scan.findings || []).filter(f => f.riskDollars);
      const sumEv = findings.reduce((s, f) => s + f.riskDollars.ev, 0);
      const ranked = [...findings].sort((a, b) => b.riskDollars.ev - a.riskDollars.ev).slice(0, top);
      console.log(JSON.stringify({
        total: findings.length, sumEvUsd: sumEv,
        top: ranked.map(f => ({ id: f.id, vuln: f.vuln, severity: f.severity, evUsd: f.riskDollars.ev })),
      }, null, 2));
    " "$TOP" ;;
  --time-to-fix)
    node -e "
      const fs = require('fs');
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/time-to-fix.js').then(ttf => {
        let scan = null;
        try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
        if (!scan) { console.log(JSON.stringify({ message: 'No prior scan found. Run /scan --all first.' })); process.exit(0); }
        const findings = (scan.findings || []).filter(f => typeof f.estimatedFixHours === 'number');
        const perFamily = {};
        let totalHours = 0;
        for (const f of findings) {
          totalHours += f.estimatedFixHours;
          const fam = f.family || 'unknown';
          perFamily[fam] = (perFamily[fam] || 0) + f.estimatedFixHours;
        }
        const roll = { perFinding: findings.length, totalHours: Number(totalHours.toFixed(1)), perFamily };
        console.log(JSON.stringify({ ...roll, summary: ttf.renderTimeSummary(roll) }, null, 2));
      });
    " ;;
  --synthesize-rule)
    shift
    node ${CLAUDE_PLUGIN_ROOT}/scripts/synthesize-detector.mjs "$@" ;;
  --llm)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format aibom-md --no-network
    node -e "
      const fs = require('fs');
      let scan = null;
      try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
      const findings = (scan && scan.findings) || [];
      const llmFindings = findings.filter(f => f.owaspLlm);
      console.log(JSON.stringify({
        owaspLlmFindingCount: llmFindings.length,
        owaspLlmFindings: llmFindings.map(f => ({ id: f.id, owaspLlm: f.owaspLlm, vuln: f.vuln, severity: f.severity, file: f.file, line: f.line })),
      }, null, 2));
    " ;;
  --model-rescan)
    MODEL=""
    if [ "$2" = "--model" ] && [ -n "$3" ]; then MODEL="$3"; fi
    node -e "
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/model-rescan.js').then(async (mr) => {
        const toModel = process.argv[1];
        if (!toModel) { console.log(JSON.stringify({ ok: false, reason: 'Usage: /labs --model-rescan --model <model-id>' })); process.exit(0); }
        const r = await mr.runModelRescan('.', { toModel });
        console.log(JSON.stringify(r, null, 2));
      });
    " "$MODEL" ;;
  *)
    echo "Modes: --claude-audit --model-rescan --synthesize-rule --cross-repo --risk-dollars --time-to-fix --llm" ;;
esac
```

`--claude-audit` calls `claude-authorship.js`'s three pure functions over `last-scan.json`'s findings: `analyzeAuthorshipPatterns` (per-family AI-vs-human lift), `suggestClaudeMdEvolution` (draft stanzas for patterns with lift ≥ 1.2 and ≥ 2 AI-authored instances), `extractOriginatingPromptCluster` (Jaccard-clustered originating prompts). All three depend on `f.aiAuthored`/`f.originatingPrompt`, which `posture/git-history.js#annotateGitHistory` stamps on every finding in every scan of a git repo (wired in `engine.js`) — but until this fix, neither field (nor `introducedBy`/`introducedIn`/`introducedAt`/`introducedInMessage`) survived `toJSON()`'s per-finding allowlist, so `--claude-audit` would have silently seen zero AI-authored findings on every real repo, the same class of bug as the `licenseGraph`/`sbomDiff`/`entrypointInventory` gaps fixed earlier (see `test/annotator-errors.test.js`).

`--cross-repo <finding-id>` looks the finding up in `last-scan.json` by id, then calls `cross-repo-memory.js#findSiblingSignals` against the developer's local `~/.claude/agentic-security/cross-repo/` store (populated over time by `recordFix`/`recordTriage`, not run here). An id from a repo with no prior cross-repo history returns empty arrays honestly rather than fabricating a match.

`--risk-dollars [--top N]` and `--time-to-fix` both read `f.riskDollars`/`f.estimatedFixHours` directly off `last-scan.json`'s findings — same allowlist-fix as above; `posture/risk-dollars.js#annotateRiskDollars` and `posture/time-to-fix.js#annotateTimeToFix` are already wired into every scan (`engine.js`), so no re-annotation is needed at report time, only reading what the engine already computed.

`--synthesize-rule` passes its arguments straight through to the real `scripts/synthesize-detector.mjs` CLI (`--cwe`, `--lang`, `--files`, `--out`). That script already refuses to run without `AGENTIC_SECURITY_LLM_VALIDATE=1` and `AGENTIC_SECURITY_LLM_ENDPOINT`, prints its own usage, and never writes into `scanner/src` — the synthesized spec is always a human-reviewed proposal.

`--llm` runs a real scan with `--format aibom-md` (which also writes `last-scan.json` as a side effect of any scan, regardless of output format), prints the AI-BOM, then filters that same scan's findings for `f.owaspLlm` — the field `sast/llm-owasp.js` stamps on OWASP-LLM-Top-10-mapped findings (prompt injection, insecure output handling, excessive agency, etc.) and which `toJSON()` already carried through before this fix.
