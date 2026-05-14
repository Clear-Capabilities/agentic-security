---
description: For a finding the scanner produced from THIS working directory, build a PoC (proof-of-concept) input + a regression test, OPTIONALLY EXECUTE THE TEST to prove the finding is real, and surface a full risk-context bundle. Refuses to operate on findings whose `file` resolves outside the current scan root. Emits PROBABLE_FP when no PoC can be constructed from the local code shape, INDETERMINATE_BY_CLASS for vuln classes the validator cannot reliably prove. Supports batch validation (`--all`), JUnit XML output (`--junit`), and a verdict cache. Intended for pre-remediation validation under authorized security review of code the user owns.
argument-hint: "<finding-id> | --all [--severity critical|high] [--junit <path>] [--no-execute] [--no-cache]"
---

Build a proof-of-concept (or refusal / FP verdict) for finding `${1}` against code in the **current working directory only**.

## High-level flow

```
1. Parse args                         (--all, --severity, --junit, --no-execute, --no-cache)
2. Verify last-scan.json exists       (else stop)
3. For each target finding:
   a. Scope guard                     (refuse out-of-tree)
   b. Class refusal check             (timing, ReDoS, etc. → INDETERMINATE_BY_CLASS)
   c. Cache lookup                    (return cached verdict if hash matches)
   d. Risk context render             (severity, reach, data classes, compliance)
   e. User consent                    (single finding) / batch consent (--all)
   f. Detect project test framework   (jest / pytest / go test / cargo test / …)
   g. Invoke security-poc-generator   (with finding + risk context + framework)
   h. Execute the test                (unless --no-execute) → upgrade verdict
   i. Write test file                 (offer if TP_PROVEN / TP_CONFIRMED)
   j. Offer auto-fix bundle           (from FIXES template) if TP_PROVEN
   k. Apply suppression               (offer if PROBABLE_FP / PROBABLE_FP_VERIFIED)
   l. Append to history.json          (for confidence calibration)
   m. Cache the verdict
4. Emit JUnit XML                     (if --junit was set)
5. Print confidence calibration       (after the run, from history.js summary)
```

## Verdicts

| Verdict | Meaning | Severity action |
|---|---|---|
| **TP_PROVEN** | PoC test was written AND executed AND failed (asserted vuln behaviour fires on unfixed code). | Recommend `/fix --one <id>` immediately. |
| **TP_CONFIRMED** | PoC test was written but not executed (`--no-execute` or no test framework). Static evidence is strong. | Recommend `/fix --one <id>`. |
| **PROBABLE_FP_VERIFIED** | PoC test was written AND executed AND passed (vulnerable assertion did not fire — data flow is blocked). | Offer suppression entry. |
| **PROBABLE_FP** | A blocker (sanitizer / guard) was identified statically. No test executed. | Offer suppression entry. |
| **INDETERMINATE_BY_CLASS** | The vuln class (timing oracle, ReDoS, weak RNG) cannot be reliably proved by a regression test. | Leave finding as-is. |
| **REFUSED** | Finding targets a file outside the working directory. | Print refusal. |
| **INDETERMINATE_TEST_INVALID** | Test was generated but errored out (compile failure, missing dep). | Manual review. |
| **INDETERMINATE** | Ambiguous static evidence; no blocker, no confirmable PoC. | Manual review. |

## Step-by-step instructions

### Step 1 — Parse args

If `${1}` is `--all`, switch to batch mode. Parse `--severity critical|high|medium|low`, `--junit <path>`, `--no-execute`, `--no-cache` from the argument string.

In single-finding mode, `${1}` is the finding ID.

### Step 2 — Verify scan state

```bash
if [ ! -f .agentic-security/last-scan.json ]; then
  echo "No scan results — run /scan --all first."
  exit 1
fi
```

### Step 3a — Scope guard

```bash
FINDING_FILE=$(jq -r --arg id "${FINDING_ID}" '.findings[]? // .logicVulns[]? | select(.id == $id) | .file // .sink.file' .agentic-security/last-scan.json | head -1)
if [ -z "$FINDING_FILE" ]; then
  echo "Finding not in last-scan.json."
  exit 1
fi
ABS=$(python3 -c "import os,sys; print(os.path.abspath(sys.argv[1]))" "$FINDING_FILE")
CWD=$(pwd)
case "$ABS" in
  "$CWD"/*) ;;
  *)
    echo "REFUSED: $ABS is outside the current scan root ($CWD)."
    exit 1 ;;
esac
```

### Step 3b — Class refusal check

```bash
CWE=$(jq -r --arg id "${FINDING_ID}" '.findings[]? // .logicVulns[]? | select(.id == $id) | .cwe // ""' .agentic-security/last-scan.json | head -1)
VULN=$(jq -r --arg id "${FINDING_ID}" '.findings[]? // .logicVulns[]? | select(.id == $id) | .vuln // ""' .agentic-security/last-scan.json | head -1)
REASON=$(node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/refusal-classes.mjs check "$CWE" "$VULN" 2>&1)
RC=$?
if [ "$RC" = "11" ]; then
  echo "INDETERMINATE_BY_CLASS: $REASON"
  # Append to history & junit, skip this finding.
fi
```

### Step 3c — Cache lookup

Unless `--no-cache` is passed:

```bash
CACHED=$(node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/cache.mjs read "${FINDING_ID}")
if [ "$CACHED" != "MISS" ]; then
  echo "$CACHED"
  # still emit to junit and history; skip the LLM call.
fi
```

### Step 3d — Render risk context

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/risk-context.mjs "${FINDING_ID}"
```

Output (example):

```
Risk context
  Severity:        HIGH     Triage: 88/100 (High Confidence)   Toxicity: 78/100 (High)
  Reachability:   yes (called from route)
  Route:          POST /api/users/:id
  Data classes:   PII, PCI
  CWE:            CWE-89    STRIDE: Tampering
  Compliance:     OWASP ASVS V5.3.4, PCI 6.2.4, NIST AC-3
  KEV:            n/a    EPSS: n/a
```

### Step 3e — Consent prompt

Show the user the finding summary, the risk-context block, and ask for explicit consent:

```
PoC scope confirmation

Finding:           <finding.vuln> (severity: <finding.severity>)
Target file:       <file>:<line>   (resolved: <absolute-path>)
Working directory: <pwd>

<risk-context block>

This will produce a proof-of-concept input + a regression test for the
flagged code in your working directory. If a test framework is detected
AND --no-execute is NOT set, the test will be executed against your local
code to upgrade the verdict from TP_CONFIRMED → TP_PROVEN. The PoC is for
pre-remediation validation under authorized security review. By proceeding
you confirm you own this code or have permission from the system owner to
validate findings in it.

Proceed? (yes / no)
```

In batch mode (`--all`), ask once at the start: "About to validate N findings of severity ≥ X. Proceed? [yes / no]"

### Step 3f — Detect project test framework

```bash
FW_JSON=$(node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/detect-framework.mjs)
echo "$FW_JSON"
# {"framework":"jest","runner":"npx jest","ext":"test.js","lang":"js"}
```

Pass this to the agent so it can generate idiomatic tests.

### Step 3g — Invoke `security-poc-generator` subagent

Provide:
- The finding object (JSON)
- The framework detection result
- The risk context block
- ±60 lines of file context around the finding

The agent must return (per the agent definition):
- `TP_CONFIRMED` + **PAYLOAD** + **TEST** + **DATA_FLOW** + **ADVERSARIAL_VARIANTS** (3-5)
- `PROBABLE_FP` + **BLOCKER** + **SUPPRESSION**
- `INDETERMINATE` + reason

### Step 3h — Execute the test (unless --no-execute)

```bash
TEST_PATH=".agentic-security/poc/${FINDING_ID}/poc.${EXT}"
mkdir -p "$(dirname "$TEST_PATH")"
# Write the **TEST** block from the agent verbatim to TEST_PATH.

if [ "$NO_EXECUTE" != "true" ] && [ "$FRAMEWORK" != "none" ]; then
  RESULT=$(node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/run-test.mjs "$TEST_PATH")
  EXEC_VERDICT=$(echo "$RESULT" | jq -r '.verdict')
  case "$EXEC_VERDICT" in
    TEST_FAILED_AS_EXPECTED)  VERDICT="TP_PROVEN" ;;
    TEST_PASSED_UNEXPECTEDLY) VERDICT="PROBABLE_FP_VERIFIED" ;;
    TEST_ERRORED)             VERDICT="INDETERMINATE_TEST_INVALID" ;;
  esac
fi
```

Show the test output (stdout/stderr truncated to 40 lines) so the user can see why a test failed/passed.

### Step 3i — Offer to write the regression test

If verdict is TP_PROVEN or TP_CONFIRMED, offer to copy the test from `.agentic-security/poc/<id>/poc.<ext>` to `tests/security/<finding-id>.<ext>`. Ask before writing.

### Step 3j — Offer auto-fix bundle

If verdict is TP_PROVEN, look up the FIX template for this vuln in `.agentic-security/last-scan.json` (each finding carries a `fix` and `code` field set by the engine). Offer:

```
TP_PROVEN — fix available.

Apply both (a) the regression test in tests/security/<id>.<ext>
and (b) the canonical fix patch shown below?

<diff preview from FIXES.code, adapted to the actual file location>

Apply? [yes / fix-only / test-only / no]
```

### Step 3k — Apply suppression

If PROBABLE_FP or PROBABLE_FP_VERIFIED: append the SUPPRESSION YAML to `.agentic-security/rules.yml`. Ask before writing.

### Step 3l — Append to validator history

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/history.mjs append "$(cat <<EOF
{"id":"${FINDING_ID}","vuln":"${VULN}","cwe":"${CWE}","family":"${FAMILY}","verdict":"${VERDICT}","proven":${PROVEN},"durationMs":${DURATION_MS}}
EOF
)"
```

### Step 3m — Cache the verdict

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/cache.mjs write "${FINDING_ID}" "$VERDICT_JSON"
```

### Step 4 — Emit JUnit XML

If `--junit <path>` was set, collect all verdicts into `verdicts.json` and:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/junit.mjs verdicts.json > "$JUNIT_PATH"
```

### Step 5 — Print confidence calibration

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/validator/history.mjs summary
```

Per-family decisive-verdict rate, so users see where the validator is trustworthy.

## Why this exists

A finding the team can't reproduce is a finding the team won't fix. By forcing a concrete PoC for every flagged issue AND optionally executing it as a regression test, this command:

- Raises **precision**: findings whose data flow can't actually be triggered are flipped to PROBABLE_FP_VERIFIED and suppressed at source.
- Raises **recall on real bugs over time**: the regression test lives in CI and re-fires if the bug is reintroduced by a future commit.
- Produces **proof**, not just an assertion: TP_PROVEN means a test demonstrated the bug; TP_CONFIRMED means the agent believes it can.

Together with `/fix --one`, this closes the loop: **find → prove → fix → test**.

## Automating PoC execution

After `/validate-findings` has generated test files, use `scripts/run-poc-tests.py` to batch-execute them outside of Claude — in CI, in a pre-commit hook, or from the terminal.

```bash
# Run all PoCs for the current project
python3 scripts/run-poc-tests.py

# Only critical and high findings
python3 scripts/run-poc-tests.py --severity high

# Single finding by ID
python3 scripts/run-poc-tests.py --id <finding-id>

# List which findings have generated PoCs (without running)
python3 scripts/run-poc-tests.py --list

# CI gate — exits 1 if any TP_PROVEN findings, writes JUnit XML
python3 scripts/run-poc-tests.py --severity high --junit poc-results.xml

# Re-run even if a cached verdict exists
python3 scripts/run-poc-tests.py --no-cache

# Machine-readable output
python3 scripts/run-poc-tests.py --json
```

The script reads `.agentic-security/last-scan.json` for findings, discovers test files under `.agentic-security/poc/<id>/poc.*`, checks the same verdict cache that `/validate-findings` writes, and auto-detects the project test framework (jest / vitest / pytest / go test / cargo test / etc.).

**Exit codes:** `0` = no proven vulnerabilities · `1` = at least one `TP_PROVEN` finding

**Verdicts emitted:**

| Verdict | Meaning |
|---|---|
| `TP_PROVEN` | Test ran and failed — vulnerable behaviour confirmed |
| `PROBABLE_FP_VERIFIED` | Test ran and passed — data flow is blocked |
| `INDETERMINATE_TEST_INVALID` | Test errored (missing dep, compile failure, timeout) |
| `CACHED` | Returned from verdict cache — no test executed |
| `NO_POC` | No test generated yet — run `/validate-findings` first |

**Typical workflow:**

```
/scan --all
/validate-findings --all --severity high
python3 scripts/run-poc-tests.py --severity high --junit poc-results.xml
/fix --all --high
```

## Scope (compliance note)

This skill operates only on findings whose `file` resolves inside the current working directory. It is intended for pre-remediation validation of code the user owns, under authorized security review. It does not accept remote targets, does not probe external systems, and refuses findings whose path resolves outside the scan root. Generated tests target `localhost` / `127.0.0.1` / the in-process test runner only — never a remote host.

🛡  agentic-security · created by Clear Capabilities
