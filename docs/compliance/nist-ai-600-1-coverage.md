# NIST AI 600-1 scanner coverage map

**Framework version:** NIST AI 600-1 (2024) — Artificial Intelligence Risk Management Framework: Generative AI

This repository ships **two independent, real NIST AI 600-1 tools** with different scope. A
static markdown table trying to summarize both had drifted out of sync with each of them
(confirmed during the Stage 6 correctness audit: it matched neither the 212-control spreadsheet
catalog nor the 6-control engine mapping, and nothing gated it against drifting further) and had
no generator that could keep it current — so this page now points at the live sources of truth
instead of re-stating a snapshot that goes stale the moment either one changes.

## 1. The engine-native mapping (6 hand-curated controls)

`scanner/src/posture/compliance-frameworks/nist-ai-600-1.json` maps a small, hand-curated set of
NIST AI 600-1 controls directly to scanner families/modules — this is what `/compliance` and the
MCP surface actually evaluate against a scan. Get the current, correct answer with:

```bash
/compliance --walkthrough nist-ai-600-1     # narrative, per-control evidence
/compliance --report nist                   # same evaluation, auditor-attestation framing
/compliance --report nist --format json      # structured {control, status, observations}[]
```

Each control's `status` is `present` (every mapped signal is clean), `partial` (some signal
present but not all clear, or an unverifiable `rule:` mapping), `absent` (mapped, but nothing
passed), or `manual` (no automated mapping — requires human attestation). Requires a prior scan
(`/scan --all`) — the report is a statement about a scan that happened, not a live re-scan, so a
stale scan produces a stale (but honestly dated) answer rather than a silently wrong one.

## 2. The full spreadsheet catalog (212 controls, code-testable ones only)

`scripts/nist-compliance/` is a standalone scanner (not part of the main engine) generated
directly from the source NIST spreadsheet (`docs/standards/NIST AI 600-1.xlsx` via
`build-catalog.py`) — 212 controls at the spreadsheet's own granularity, of which the subset
NIST itself rates `code_testable: Yes` or `Partial` (122 today) get evidence-rule checks. Run it
directly against any repository:

```bash
python3 scripts/nist-compliance/scan.py <path-to-repo>          # markdown attestation sheet
python3 scripts/nist-compliance/scan.py <path-to-repo> --json-out out.json
python3 scripts/nist-compliance/build-catalog.py --check         # confirms controls.json still
                                                                   # matches the source spreadsheet
                                                                   # (wired into the release gate)
```

Its own output states, per control, whether it needs external attestation on top of what it
found in code/config — see the printed summary line and `write_md`'s per-control table for the
current, accurate counts. Do not hand-transcribe them into this file; that is exactly how the
previous version of this page went stale.

## Which one should I use?

- Evaluating **this specific engine's** compliance posture as part of a normal scan/triage
  workflow → tool 1 (`/compliance --walkthrough` / `--report`).
- An **independent, spreadsheet-faithful** control-by-control attestation sheet, including
  controls the main engine doesn't map at all → tool 2 (`scripts/nist-compliance/scan.py`).

Both are real, both run today, and neither requires trusting a hand-maintained snapshot in this
file.
