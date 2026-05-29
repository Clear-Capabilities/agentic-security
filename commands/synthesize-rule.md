---
description: Draft a custom SAST detector from a natural-language description. Runs in shadow mode before promotion.
argument-hint: "<natural-language description> [--from-cve <id>] [--language js|py|java|...] [--promote]"
---

# /synthesize-rule

Draft a custom SAST detector for this project from a natural-language description. Wraps `scripts/synthesize-detector.mjs` as a conversational command.

## When to use

- A new internal API is deprecated and you want to flag any use → "flag any call to `legacyDb.*`"
- A CVE just dropped and you want to detect its shape in your repo → "match the manifest of CVE-2024-XYZ in our codebase"
- A pattern you saw in a postmortem → "flag `req.body.something + req.params.somethingElse` being passed to `child_process.exec`"

## What it does

1. Prompts the LLM to draft a detector spec: regex(es), AST shape, family, severity, fix template
2. Runs the candidate detector in **shadow mode** against the current repo via `.agentic-security/shadow-findings.json` — does not affect CI gate
3. Reports hits with context (file:line + snippet)
4. If `--promote` is passed AND the user confirms, promotes the rule into `.agentic-security/rules.yml`
5. Auto-generates a vulnerable + clean fixture pair at `.agentic-security/synth-rules/<name>/{vulnerable,clean}/`

## Implementation

The command shells into the existing developer helper:

```bash
node scripts/synthesize-detector.mjs \
  --description "$DESCRIPTION" \
  --out .agentic-security/synth-rules/<name>/spec.json \
  ${CVE:+--from-cve "$CVE"} \
  ${LANG:+--language "$LANG"}
```

That script:
- Calls an LLM (uses `AGENTIC_SECURITY_LLM_MODEL`, default `gpt-4o-mini`)
- Returns a structured detector spec
- Writes the spec to `--out`

Then the command runs:

```bash
node bin/agentic-security.js scan --shadow-rule .agentic-security/synth-rules/<name>/spec.json
```

…which loads the rule, runs it against the project, and writes hits to `.agentic-security/shadow-findings.json` without affecting `last-scan.json`.

## Usage

```bash
# Draft a rule from a description
/synthesize-rule "flag any use of legacyDb.* — it's been deprecated since v0.78"

# Draft from a CVE
/synthesize-rule --from-cve CVE-2024-12345 "match this in our codebase"

# Promote after review
/synthesize-rule "flag any inline aws-sdk client construction" --promote
```

## Safety

The synth script outputs the detector spec for **review before any promotion**. The promote step requires explicit `--promote` AND a user confirm. Shadow findings are excluded from CI gates by design.
