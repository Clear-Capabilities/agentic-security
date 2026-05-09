---
description: Scan the working tree for NIST AI 600-1 compliance evidence and produce an auditor-ready attestation sheet (122 testable controls).
argument-hint: "[path]"
---

Run the NIST AI 600-1 compliance scanner against `${1:-.}` and produce an attestation sheet for auditors.

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/nist-compliance/scan.py ${1:-.}
```

Three files are written to the current directory:

- `nist-ai-600-1-attestation.md` — per-control evidence + status, suitable to email to auditors or attach to a vendor risk questionnaire
- `nist-ai-600-1-attestation.csv` — one row per control for spreadsheet review
- `nist-ai-600-1-attestation.json` — machine-readable for CI gating

The scanner only opines on the **122 code-testable controls** (55 "Yes" + 67 "Partial" in column F of `NIST AI 600-1.xlsx`). The remaining 90 controls are inherently organizational and need external attestation (signed policies, training records, vendor agreements). Those are listed in the source xlsx as `Code Testable = No` and are not part of this scan.

After the scan you can:

- Open the markdown report and walk through `Not Compliant` controls — most have a 1-line evidence rule you can satisfy with a small code/doc addition (e.g., dropping a `MODEL_CARD.md`, adding a content-filter call, wiring a fairness benchmark into CI).
- Edit `scripts/nist-compliance/evidence-rules.json` to teach the scanner about your project's vocabulary (e.g., your team uses `block_prompt()` instead of `content_filter()`).
- Re-run after changes — scans are deterministic and complete in seconds.
