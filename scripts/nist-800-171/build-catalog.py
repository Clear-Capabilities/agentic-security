#!/usr/bin/env python3
"""Build controls.json from the NIST SP 800-171 Rev. 3 control export.

This is the ONLY place in the repository that reads the 800-171 CSV. `scan.py`
reads the generated `controls.json`, so an ordinary compliance scan parses no
source export at all — the same split `scripts/nist-compliance/` uses for the
AI 600-1 workbook.

Run it when the upstream export changes:

    python3 scripts/nist-800-171/build-catalog.py            # regenerate
    python3 scripts/nist-800-171/build-catalog.py --check    # drift gate

`--check` exits 1 if regenerating would change the committed file, so a stale
catalog is caught rather than silently scanned against. It exits 2 when the
source export or the testability ratings are unavailable — an unverifiable
check is a failure, not a skip.

DIFFERENCE FROM THE AI 600-1 CATALOG, and why this file exists separately:

  1. The source is CSV, not XLSX, so this reads it with the standard library.
     `scripts/nist-compliance/build-catalog.py` exits 2 when openpyxl is
     missing; this gate can never be unrunnable for a missing dependency.

  2. The AI 600-1 workbook ships NIST's own `code_testable` column. The
     800-171 export does NOT rate testability — it has four columns and none
     of them is a testability judgment. The rating is therefore ours, and it
     lives in `code-testability.json`, joined here by control id. Keeping it
     out of the CSV and out of the hand-maintained mapping file means the
     three inputs stay individually reviewable:

        the CSV               — the standard's own text (quotation, verbatim)
        code-testability.json — our claim about what is observable in code
        evidence-rules.json   — how we actually detect it

     A diff to any one of them says unambiguously which kind of claim changed.

A rating is REQUIRED for every control. A control present in the CSV but
missing from code-testability.json is a hard failure rather than a silent
default: defaulting would either invent coverage ("Yes") or silently suppress
a control ("No"), and both are the failure mode this whole chain exists to
prevent.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DEFAULT_CSV = REPO_ROOT / "docs" / "standards" / "NIST_SP_800_171r3_Controls.csv"
DEFAULT_RATINGS = HERE / "code-testability.json"
DEFAULT_OUT = HERE / "controls.json"

VALID_RATINGS = ("Yes", "Partial", "No")

# The export carries multi-KB DISCUSSION text in the fourth column, well over
# the 128 KB default field limit on some platforms.
csv.field_size_limit(10 ** 9)


def load_ratings(path: Path) -> dict:
    if not path.exists():
        sys.stderr.write(f"ERROR: testability ratings not found: {path}\n")
        sys.exit(2)
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"ERROR: {path} is not valid JSON: {exc}\n")
        sys.exit(2)
    ratings = blob.get("ratings")
    if not isinstance(ratings, dict) or not ratings:
        sys.stderr.write(f"ERROR: {path} has no `ratings` object\n")
        sys.exit(2)
    return ratings


def load_from_csv(csv_path: Path, ratings: dict) -> list[dict]:
    if not csv_path.exists():
        sys.stderr.write(f"ERROR: source export not found: {csv_path}\n")
        sys.exit(2)

    controls = []
    seen = set()
    # utf-8-sig is defensive: the file as supplied has no BOM, but it is an
    # Excel export and a re-export can introduce one, which would corrupt the
    # first control id and silently break every join by id downstream.
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        try:
            next(reader)  # header
        except StopIteration:
            sys.stderr.write(f"ERROR: {csv_path} is empty\n")
            sys.exit(2)
        for row in reader:
            padded = list(row) + [None] * (4 - len(row))
            cid, family, description, text = padded[:4]
            cid = cid.strip() if isinstance(cid, str) else cid
            if not cid:
                continue
            if cid in seen:
                sys.stderr.write(f"ERROR: duplicate control id in source: {cid}\n")
                sys.exit(2)
            seen.add(cid)

            rating = ratings.get(cid)
            if rating is None:
                sys.stderr.write(
                    f"ERROR: control {cid} has no entry in code-testability.json.\n"
                    f"       Every control needs an explicit rating — defaulting would\n"
                    f"       either invent coverage or silently suppress the control.\n"
                )
                sys.exit(2)
            value = rating.get("code_testable") if isinstance(rating, dict) else None
            if value not in VALID_RATINGS:
                sys.stderr.write(
                    f"ERROR: control {cid} has invalid code_testable {value!r} "
                    f"(expected one of {', '.join(VALID_RATINGS)})\n"
                )
                sys.exit(2)

            description = (description or "").strip()
            # The first line of the requirement text is the control's title.
            title = description.split("\n")[0].strip()

            controls.append({
                "id": cid,
                "family": (family or "").strip(),
                "title": title,
                "description": description,
                "text": (text or "").strip(),
                "code_testable": value,
                "code_testable_rationale": (rating.get("rationale") or "").strip(),
            })

    if not controls:
        sys.stderr.write(f"ERROR: no controls parsed from {csv_path}\n")
        sys.exit(2)

    orphans = sorted(set(ratings) - seen)
    if orphans:
        sys.stderr.write(
            "ERROR: code-testability.json rates controls that are not in the source: "
            + ", ".join(orphans) + "\n"
        )
        sys.exit(2)

    return controls


def build(csv_path: Path, ratings_path: Path) -> dict:
    ratings = load_ratings(ratings_path)
    controls = load_from_csv(csv_path, ratings)
    testable = [c for c in controls if c["code_testable"] in ("Yes", "Partial")]
    return {
        "_doc": (
            "NIST SP 800-171 Rev. 3 control catalog. GENERATED, do not hand-edit. "
            "Source of truth for control text is the export named in `source`; "
            "source of truth for `code_testable` is `code-testability.json`, which is "
            "OUR judgment and not NIST's: the 800-171 export rates no control for "
            "testability. Regenerate with `python3 scripts/nist-800-171/build-catalog.py`. "
            "How this engine detects each control lives separately in evidence-rules.json."
        ),
        "framework": "NIST SP 800-171 Rev. 3",
        # Read by scan.py to name its output files and label its attestation.
        # Set explicitly because deriving it from the name would produce
        # "nist-sp-800-171-rev-3" rather than the id the rest of the codebase
        # uses for this framework.
        "slug": "nist-800-171-r3",
        "publisher": "NIST",
        "license": "public-domain (US Federal publication)",
        "source": "docs/standards/NIST_SP_800_171r3_Controls.csv",
        "sourceSha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "testabilitySource": "scripts/nist-800-171/code-testability.json",
        "testabilitySha256": hashlib.sha256(ratings_path.read_bytes()).hexdigest(),
        "testabilityAuthoredBy": "engine team (not NIST; the source export carries no testability rating)",
        "generator": "scripts/nist-800-171/build-catalog.py",
        "controlCount": len(controls),
        "testableCount": len(testable),
        "controls": controls,
    }


def serialize(catalog: dict) -> str:
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default=str(DEFAULT_CSV), help="Path to the source CSV export")
    ap.add_argument("--ratings", default=str(DEFAULT_RATINGS), help="Path to code-testability.json")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="Path to controls.json")
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if the committed catalog is stale; write nothing")
    args = ap.parse_args()

    out_path = Path(args.out)
    body = serialize(build(Path(args.csv), Path(args.ratings)))

    if args.check:
        if not out_path.exists():
            sys.stderr.write(f"FAIL: {out_path} does not exist — run build-catalog.py\n")
            return 1
        if out_path.read_text(encoding="utf-8") != body:
            sys.stderr.write(
                f"FAIL: {out_path} is stale relative to {args.csv} / {args.ratings}.\n"
                f"      Run: python3 scripts/nist-800-171/build-catalog.py\n"
            )
            return 1
        print(f"OK: {out_path.name} matches {Path(args.csv).name}")
        return 0

    out_path.write_text(body, encoding="utf-8")
    catalog = json.loads(body)
    counts = {r: sum(1 for c in catalog["controls"] if c["code_testable"] == r) for r in VALID_RATINGS}
    print(f"Wrote {out_path} — {catalog['controlCount']} controls "
          f"({catalog['testableCount']} code-testable: "
          f"{counts['Yes']} Yes, {counts['Partial']} Partial, {counts['No']} No)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
