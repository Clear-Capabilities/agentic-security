# Output schema reference

`agentic-security scan . --format json` (and `ci`, which builds the same
object) return one JSON document. This page is a map of its real top-level
keys, built directly from `toJSON()` in `scanner/src/report/index.js` — not
every field is documented elsewhere, and this page corrects one thing every
other doc assumes wrong.

---

## There is no top-level `schemaVersion`

The output object itself is not versioned. The **only** `schemaVersion`
field in the whole document lives nested inside `scanHealth`:

```json
{ "scanHealth": { "schemaVersion": 1, "status": "partial", "…": "…" } }
```

If you're looking for "what version of the output shape is this," that's
the field — `scanHealth.schemaVersion`, not `.schemaVersion` at the root.

---

## `privacyInventory` and `policyDecision` do not exist

Neither key appears anywhere in `scanner/src/report/` or the rest of
`scanner/src/`. If you've seen either name in a draft doc or an older
spec, it does not describe real output — omit it. The real privacy-related
top-level keys are `privacyFramework` (NIST Privacy Framework 1.1 gap
findings, see [compliance](../guides/compliance.md)), `privacyIrBacked`
(boolean — whether privacy classification was backed by the IR/taint layer
for this scan, not a string status), and `privacyTaxonomyVersion` (which
data-classification taxonomy version ran). None of the three is an
"inventory" object; there is no top-level policy-decision object either —
the closest real analogue is the egress layer's own per-call decision
object, documented in [egress allow/deny/local-only](glossary.md#egress-allowdenylocal-only),
which is not part of scan output at all.

---

## Real top-level keys

| Key | What it is |
|---|---|
| `scanId`, `startedAt`, `durationMs` | Run identity and timing. |
| `scanned` | `{files, lines}` — how much was scanned. |
| `findings[]` | The SAST/secrets/SCA/logic finding array. See [Finding evidence](../walkthroughs/finding-evidence.md) for a full field-by-field read. |
| `bundles` | Root-cause bundles grouping findings that share a helper/root cause. |
| `routes` | Discovered HTTP routes (used for reachability). |
| `components[]` | SCA dependency inventory: `{ecosystem, name, version, reachable, hasVulns, isDeprecated, latestVersion, license}`. |
| `suppressedCount` | Count of custom-rule suppressions applied. |
| `blastRadiusSignals` | Blast-radius summary, or `null`. |
| `annotatorErrors[]` | Posture annotators that threw and were skipped (empty when clean). |
| `detectorErrors[]` | Per-file SAST/logic/secrets detector errors, `{file, analyzer, err}` (empty when clean). |
| `attestation` | Run attestation digest, or `null` when not computed — see [Signed, portable evidence](../../CLAUDE.md#signed-portable-evidence-prd-d2). |
| `suppressedRules` | `.agentic-security/rules.yml` `disable:` entries in effect, or `null`. |
| `legacyFieldNotice` | Non-null only when a finding used a deprecated field alias. |
| `licenseGraph`, `sbomDiff`, `entrypointInventory` | Per-component license map, SBOM drift, and entry-point inventory. |
| `rootCauseSweep`, `attackTaxonomy`, `privacyFramework` | Scan-level structured summaries (root-cause sweep always runs; the other two are default-on unless their own opt-out env var is set). |
| `privacyIrBacked`, `privacyTaxonomyVersion` | See above. |
| `scanHealth` | Whether the analysis itself completed — see below and [Scan health](../walkthroughs/scan-health.md). |
| `suppressed` | Only present with `--include-suppressed`. |

Fields prefixed `_` (`_v3`, `_scanMeta`) are internal/engine-detail and not
part of the documented contract.

---

## `scanHealth` (small real excerpt)

The real captured example from [Scan health](../walkthroughs/scan-health.md)
— a scan where every analyzer completed, but the local EPSS cache was
stale:

```json
"scanHealth": {
  "schemaVersion": 1,
  "status": "partial",
  "analyzers": { "expected": 120, "completed": 120, "failed": 0, "timedOut": 0, "skippedByPolicy": 0 },
  "freshness": {
    "epss": { "source": "cache/live", "ageDays": 20699, "stale": true, "cvesChecked": 8 }
  },
  "conditions": ["EPSS exploit-probability data is stale (20699 day(s) old)"]
}
```

`status` is binary — `complete` or `partial`. See the [glossary](glossary.md#completepartialfailed)
for how this differs from the coverage ledger's own, separate status
vocabulary.

---

## `findings[]` (small real excerpt)

One entry from the real SQLi finding in `report.py`, from
[Finding evidence](../walkthroughs/finding-evidence.md) — trimmed to a few
identity/evidence fields; the full object (confidence, proof, falsification,
verification, exploitability, riskDollars, provenance, poc, …) is documented
there field by field, not repeated here:

```json
{
  "id": "ir-taint:report.py:16:py-cursor-execute",
  "stableId": "d5bd1991a0e5abb8",
  "severity": "high", "vuln": "SQL Injection (cursor.execute)", "cwe": "CWE-89",
  "file": "report.py", "line": 16,
  "chain": [{ "file": "report.py", "line": 13, "label": "request.args/form/values/headers/cookies/json/data.get() (Flask/Django)", "provenance": "url-param" }]
}
```

---

## Go deeper

- [Finding evidence](../walkthroughs/finding-evidence.md) — every field on
  a finding, explained.
- [Scan health](../walkthroughs/scan-health.md) — the full `scanHealth`
  shape and what each sub-object means.
- [Glossary](glossary.md) — short definitions of the vocabulary used across
  these fields.
- [Scan health troubleshooting](../troubleshooting/scan-health.md) — what
  to do when `scanHealth.status` isn't `complete`.
