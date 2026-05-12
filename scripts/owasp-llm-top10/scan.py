#!/usr/bin/env python3
"""OWASP LLM Top 10 (2025) compliance scanner.

Reuses scripts/_compliance_lib.py for the multi-signal evidence evaluation.
Extends the standard emit with a per-control remediation section so
engineers know exactly what to implement for each Not Compliant / Partial control.
"""
import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _compliance_lib import evaluate

FRAMEWORK = "OWASP LLM Top 10 (2025)"
RULES_PATH = os.path.join(HERE, "evidence-rules.json")


def emit(results, controls, fmt, out_path):
    rows = []
    for ctrl in controls:
        r = results[ctrl["id"]]
        rows.append({
            "id": r["id"],
            "title": r["title"],
            "status": r["status"],
            "weight": r["weight"],
            "signals": "+".join(r["signals"]),
            "evidence_count": len(r["evidence"]),
            "remediation": ctrl.get("remediation", []),
        })

    if fmt == "json":
        body = json.dumps(
            {
                "framework": FRAMEWORK,
                "controls": [
                    {**r, "remediation": ctrl.get("remediation", [])}
                    for r, ctrl in zip(results.values(), controls)
                ],
            },
            indent=2,
        )
    elif fmt == "csv":
        from io import StringIO
        s = StringIO()
        fieldnames = ["id", "title", "status", "weight", "signals", "evidence_count", "remediation"]
        w = csv.DictWriter(s, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({**r, "remediation": "; ".join(r["remediation"])})
        body = s.getvalue()
    else:
        total = len(rows)
        compliant = sum(1 for r in rows if r["status"] == "Compliant")
        partial = sum(1 for r in rows if r["status"] == "Partial")
        non_compliant = total - compliant - partial

        lines = [
            f"# {FRAMEWORK} Compliance Attestation",
            "",
            f"**Total controls:** {total}    "
            f"**Compliant:** {compliant}    "
            f"**Partial:** {partial}    "
            f"**Not Compliant:** {non_compliant}",
            "",
            "| ID | Title | Status | Weight | Signals |",
            "|---|---|---|---:|---|",
        ]
        for r in rows:
            icon = "✅" if r["status"] == "Compliant" else "🟡" if r["status"] == "Partial" else "❌"
            lines.append(
                f"| `{r['id']}` | {r['title']} | {icon} {r['status']} | {r['weight']} | {r['signals']} |"
            )

        # Remediation section — only for controls that need work
        needs_work = [r for r in rows if r["status"] != "Compliant" and r["remediation"]]
        if needs_work:
            lines += ["", "---", "", "## Remediation Required", ""]
            for r in needs_work:
                icon = "🟡" if r["status"] == "Partial" else "❌"
                lines += [
                    f"### {icon} `{r['id']}` — {r['title']}",
                    "",
                    f"**Status:** {r['status']}    **Evidence weight:** {r['weight']}",
                    "",
                    "**Required mitigations:**",
                    "",
                ]
                for step in r["remediation"]:
                    lines.append(f"- {step}")
                lines.append("")

        body = "\n".join(lines)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"Wrote {out_path}")
    else:
        sys.stdout.write(body)


def main():
    ap = argparse.ArgumentParser(
        description=f"{FRAMEWORK} compliance scanner"
    )
    ap.add_argument("path", nargs="?", default=".", help="Project root to scan")
    ap.add_argument("--format", choices=["md", "csv", "json"], default="md")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    with open(RULES_PATH, "r", encoding="utf-8") as fh:
        rules = json.load(fh)
    controls = [c for c in rules.get("controls", []) if not c.get("id", "").startswith("_")]

    results = evaluate(os.path.abspath(args.path), controls)
    emit(results, controls, args.format, args.output)


if __name__ == "__main__":
    main()
