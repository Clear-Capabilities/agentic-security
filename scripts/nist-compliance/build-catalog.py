#!/usr/bin/env python3
"""Build controls.json from the NIST AI 600-1 workbook.

This is the ONLY place in the repository that reads the .xlsx. `scan.py` reads
the generated `controls.json`, so an ordinary compliance scan needs no openpyxl
and no binary parsing — same reason every sibling scanner
(`owasp-asvs/`, `owasp-llm-top10/`, `eu-ai-act/`) carries its controls as JSON.

Run it when the upstream workbook changes:

    python3 scripts/nist-compliance/build-catalog.py            # regenerate
    python3 scripts/nist-compliance/build-catalog.py --check    # drift gate

`--check` exits 1 if regenerating would change the committed file, so a stale
catalog is caught rather than silently scanned against. It exits 2 when the
workbook or openpyxl is unavailable — an unverifiable check is a failure, not a
skip.

The workbook column order (id, family, description, text, risks, code_testable)
and the one upstream typo fix (`GV-4.3--001`) are preserved verbatim from the
original loader so the generated catalog is byte-equivalent to what scan.py used
to parse at runtime.
"""

from __future__ import annotations

import argparse
import json
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DEFAULT_XLSX = REPO_ROOT / "docs" / "standards" / "NIST AI 600-1.xlsx"
DEFAULT_OUT = HERE / "controls.json"

# The upstream sheet ships one malformed control id. Correcting it here keeps the
# join against evidence-rules.json intact.
ID_FIXUPS = {"GV-4.3--001": "GV-4.3-001"}


def load_from_xlsx(xlsx_path: Path) -> list[dict]:
    try:
        import openpyxl
    except ImportError:
        sys.stderr.write(
            "ERROR: openpyxl is required to REBUILD the catalog "
            "(scanning does not need it). Install with: pip3 install openpyxl\n"
        )
        sys.exit(2)

    if not xlsx_path.exists():
        sys.stderr.write(f"ERROR: workbook not found: {xlsx_path}\n")
        sys.exit(2)

    wb = openpyxl.load_workbook(str(xlsx_path), read_only=True)
    ws = wb["Sheet1"]
    controls = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        padded = list(row) + [None] * (6 - len(row))
        cid, family, desc, text, risks, ct = padded[:6]
        if not cid:
            continue
        cid = cid.strip() if isinstance(cid, str) else cid
        cid = ID_FIXUPS.get(cid, cid)
        controls.append({
            "id": cid,
            "family": family,
            "description": desc,
            "text": text,
            "risks": risks,
            "code_testable": ct,
        })
    return controls


def build(xlsx_path: Path) -> dict:
    controls = load_from_xlsx(xlsx_path)
    testable = [c for c in controls if c["code_testable"] in ("Yes", "Partial")]
    digest = hashlib.sha256(xlsx_path.read_bytes()).hexdigest()
    return {
        "_doc": (
            "NIST AI 600-1 control catalog — GENERATED, do not hand-edit. "
            "Source of truth is the workbook named in `source`; regenerate with "
            "`python3 scripts/nist-compliance/build-catalog.py`. This file carries "
            "the standard's own text and its `code_testable` rating only — how this "
            "engine detects each control lives separately in evidence-rules.json, so "
            "upstream text and our detection logic can never be confused for one another."
        ),
        "framework": "NIST AI 600-1",
        "publisher": "NIST",
        "license": "public-domain (US Federal publication)",
        "source": "docs/standards/NIST AI 600-1.xlsx",
        "sourceSha256": digest,
        "generator": "scripts/nist-compliance/build-catalog.py",
        "controlCount": len(controls),
        "testableCount": len(testable),
        "controls": controls,
    }


def serialize(catalog: dict) -> str:
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xlsx", default=str(DEFAULT_XLSX), help="Path to the source workbook")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="Path to controls.json")
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if the committed catalog is stale; write nothing")
    args = ap.parse_args()

    out_path = Path(args.out)
    body = serialize(build(Path(args.xlsx)))

    if args.check:
        if not out_path.exists():
            sys.stderr.write(f"FAIL: {out_path} does not exist — run build-catalog.py\n")
            return 1
        current = out_path.read_text(encoding="utf-8")
        if current != body:
            sys.stderr.write(
                f"FAIL: {out_path} is stale relative to {args.xlsx}.\n"
                f"      Run: python3 scripts/nist-compliance/build-catalog.py\n"
            )
            return 1
        print(f"OK: {out_path.name} matches {Path(args.xlsx).name}")
        return 0

    out_path.write_text(body, encoding="utf-8")
    catalog = json.loads(body)
    print(f"Wrote {out_path} — {catalog['controlCount']} controls "
          f"({catalog['testableCount']} code-testable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
