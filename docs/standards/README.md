# Standards source material

Upstream, third-party standards documents kept **only when something in this repository reads
them**. A primary source that no generator consumes is not kept here — the derived JSON is
authoritative in that case, and the standard is cited by URL instead. Nothing in this folder is
loaded at runtime.

| File | Publisher | License | Read by | Derived artefacts |
|---|---|---|---|---|
| `NIST AI 600-1.xlsx` | NIST | public domain (US Federal publication) | [`scripts/nist-compliance/build-catalog.py`](../../scripts/nist-compliance/build-catalog.py) | [`scripts/nist-compliance/controls.json`](../../scripts/nist-compliance/controls.json) (212 controls, generated) · [`scanner/src/posture/compliance-frameworks/nist-ai-600-1.json`](../../scanner/src/posture/compliance-frameworks/nist-ai-600-1.json) → [`docs/compliance/nist-ai-600-1-coverage.md`](../compliance/nist-ai-600-1-coverage.md) |

The **Read by** column is the admission test. NIST Privacy Framework 1.1 has no row because its
workbook has no reader: its controls were transcribed once into
[`nist-privacy-1-1.json`](../../scanner/src/posture/compliance-frameworks/nist-privacy-1-1.json),
which is the source of truth for that framework and is cited from
<https://www.nist.gov/privacy-framework>.

## The chain, and which link is authoritative

```
[docs/standards/<standard>.xlsx]      ← optional; present only when a generator reads it
  └─ compliance-frameworks/<id>.json  ← machine-readable controls + engine mappings (authoritative for the engine)
       └─ docs/compliance/<id>-coverage.md  ← human-readable coverage map (derived from the JSON)
```

The first link is optional and the second is not. Most frameworks are transcribed straight into
their JSON, which then stands as the source of truth on its own.

Edit the JSON, not the coverage map. The coverage maps state control counts and coverage
percentages; if they are hand-edited they will disagree with what the engine actually assesses,
which is exactly the failure mode the whole chain exists to prevent.

**That second link was aspirational, not automated, and had actually drifted (found and fixed,
Stage 6 correctness audit).** No generator ever produced `docs/compliance/*.md` from the JSON —
the files were transcribed by hand once and then drifted silently (`nist-ai-600-1-coverage.md`'s
control counts matched neither `controls.json` nor the engine mapping; `owasp-asvs-coverage.md`
even had the framework VERSION wrong — 4.0.3 in prose vs. 5.0 in the JSON it claimed to
summarize). Rather than hand-authoring a corrected snapshot (the same drift problem, one commit
later), both pages were rewritten to point at the live evaluators
(`/compliance --walkthrough <id>` / `--report <alias>`) instead of re-stating counts in prose —
so there is nothing left to go stale in those two files. `owasp-llm-top10-coverage.md` and
`nist-privacy-1-1-coverage.md` still carry static counts that currently happen to match their
JSON; that is luck, not enforcement, and the same pointer-based fix applies if either one is
found to have drifted. The `build-catalog.py --check` half of this (confirming `controls.json`
itself still matches the source spreadsheet) is now wired into `scripts/release-check.mjs` as
the `nist-catalog-freshness` gate, matching the precedent `scorecard-freshness` already set for
`docs/SCORECARD.md`.

The Python attestation scanners under `scripts/` follow the same rule — none of them opens a
workbook. `scripts/nist-compliance/` is the one catalog with a generator, because its controls
come from a spreadsheet rather than being authored by hand:

```
docs/standards/NIST AI 600-1.xlsx
  └─ build-catalog.py ──> scripts/nist-compliance/controls.json   ← the standard's own text
                          scripts/nist-compliance/evidence-rules.json  ← how WE detect it (hand-authored)
                            └─ scan.py joins the two by control id
```

Regenerate after any workbook change, and verify with the drift gate — it fails when the
committed catalog no longer matches the workbook:

```bash
python3 scripts/nist-compliance/build-catalog.py          # regenerate
python3 scripts/nist-compliance/build-catalog.py --check  # exit 1 if stale
```

Keeping upstream control text (`controls.json`) apart from our detection logic
(`evidence-rules.json`) is deliberate: the first is a quotation from a standard and must stay
verbatim, the second is our claim about the code and changes whenever detectors do. Merging them
would make it impossible to tell which of the two a diff had altered.

## Adding a standard

1. Commit the primary source here **only if a generator will read it** — as `build-catalog.py`
   reads the AI 600-1 workbook. If you are transcribing the controls by hand into JSON, cite the
   standard by URL from that JSON and do not commit the document; an unread binary is weight
   without a reader.
2. If you did commit it, add a row to the table above naming what reads it and what it feeds.
3. Build `scanner/src/posture/compliance-frameworks/<id>.json`. Every control needs `id`,
   `function`, `category`, `summary`, and a `codeTestable` rating taken from the source — plus
   `mapsTo` **only** where this engine produces a real signal. An unmapped-but-testable control is
   reported as an engine gap; never add a speculative `mapsTo` to make coverage look better.
4. Write `docs/compliance/<id>-coverage.md` and link it from the compliance table in the root
   `README.md`.

Only redistributable sources belong here. Public-domain US Federal publications and openly
licensed standards (OWASP) are fine; a paywalled or license-restricted standard (e.g. ISO) is
not — reference it by clause number instead of committing the document.
