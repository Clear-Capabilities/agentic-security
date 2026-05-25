#!/usr/bin/env python3
"""Compliance-fix planner.

Re-runs the chosen compliance scanner with --format json, then routes every
Not-Compliant / Partial control to the agentic-security command sequence that
addresses it. Prints a deduped, ordered plan; flags process-only controls
that no tool can close.

Usage:
    plan.py {nist|asvs|llm|eu-ai-act} [PATH] [--dry-run]

PATH defaults to '.'. With --dry-run the script prints the plan and stops.
Without --dry-run the script just prints the plan with a one-liner telling
the user to execute the listed commands themselves — this keeps the script
side-effect-free; the slash command is what actually invokes the chain.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)

FRAMEWORKS = {
    "llm":      ("owasp-llm-top10",   "routing-llm.json"),
    "asvs":     ("owasp-asvs",        "routing-asvs.json"),
    "nist":     ("nist-compliance",    "routing-nist.json"),
    "eu-ai-act":("eu-ai-act",        "routing-eu-ai-act.json"),
}

# ANSI for the action lines — falls back to plain if NO_COLOR or non-TTY.
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
FROG  = "\x1b[38;2;255;107;44m" if _USE_COLOR else ""
DEEP  = "\x1b[38;2;201;52;20m"  if _USE_COLOR else ""
DIM   = "\x1b[2m"               if _USE_COLOR else ""
BOLD  = "\x1b[1m"               if _USE_COLOR else ""
RESET = "\x1b[0m"               if _USE_COLOR else ""


def run_scan(framework_key, path):
    """Re-run the underlying compliance scanner with JSON output and return the parsed report."""
    scanner_dir, _ = FRAMEWORKS[framework_key]
    scan_py = os.path.join(SCRIPTS, scanner_dir, "scan.py")
    if not os.path.exists(scan_py):
        sys.stderr.write(f"compliance-fix: scanner not found at {scan_py}\n")
        sys.exit(2)
    out = tempfile.NamedTemporaryFile(prefix="compfix-", suffix=".json", delete=False).name
    try:
        # NIST scan.py uses --json-out (and writes all three formats unconditionally).
        # asvs / llm scan.py use --format json --output.
        if framework_key == "nist":
            cmd = ["python3", scan_py, path, "--json-out", out, "--quiet",
                   "--md-out", os.devnull, "--csv-out", os.devnull]
        else:
            cmd = ["python3", scan_py, path, "--format", "json", "--output", out]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr or proc.stdout or "compliance-fix: scanner failed\n")
            sys.exit(proc.returncode or 2)
        with open(out, "r", encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        try: os.unlink(out)
        except OSError: pass


def load_routing(framework_key):
    _, fn = FRAMEWORKS[framework_key]
    with open(os.path.join(HERE, fn), "r", encoding="utf-8") as fh:
        return json.load(fh)


def gaps_from_report(report):
    """Return [(id, title, status, summary)] for Not-Compliant + Partial controls.

    Tolerates schema differences across the three scanners. NIST's JSON uses
    `control_text` and `looking_for` instead of `title`/`summary`; the LLM and
    ASVS scanners emit `title` and (for ASVS) a `summary`.
    """
    out = []
    for c in report.get("controls", []):
        status = c.get("status", "")
        if status not in ("Not Compliant", "Partial", "Partial (limited evidence)"):
            continue
        cid = c.get("id", "")
        title = c.get("title") or c.get("control_text") or c.get("looking_for") or cid
        summary = c.get("looking_for") or c.get("summary") or c.get("control_text") or title
        # Normalize "Partial (limited evidence)" → "Partial" downstream.
        if status.startswith("Partial"):
            status = "Partial"
        out.append((cid, title, status, summary))
    return out


def route_exact_id(gaps, routing):
    routed, process_only, unmapped = [], [], []
    routes = routing.get("routes", {})
    for cid, title, status, _summary in gaps:
        spec = routes.get(cid)
        if spec is None:
            unmapped.append((cid, title, status))
        elif spec.get("process_only"):
            process_only.append((cid, title, status, spec.get("note", "")))
        else:
            routed.append((cid, title, status, spec))
    return routed, process_only, unmapped


def route_id_prefix(gaps, routing):
    routed, process_only, unmapped = [], [], []
    # Sort prefixes by length desc so longer prefixes win.
    routes = sorted(routing.get("routes", {}).items(), key=lambda kv: -len(kv[0]))
    for cid, title, status, _summary in gaps:
        spec = None
        for prefix, candidate in routes:
            if cid.startswith(prefix):
                spec = candidate
                break
        if spec is None:
            unmapped.append((cid, title, status))
        elif spec.get("process_only"):
            process_only.append((cid, title, status, spec.get("note", "")))
        else:
            routed.append((cid, title, status, spec))
    return routed, process_only, unmapped


def route_keyword(gaps, routing):
    routed, process_only, unmapped = [], [], []
    keyword_routes = routing.get("keyword_routes", [])
    for cid, title, status, summary in gaps:
        haystack = f"{title} {summary}".lower()
        hit = None
        for r in keyword_routes:
            if any(kw.lower() in haystack for kw in r.get("keywords", [])):
                hit = r
                break
        if hit is None:
            process_only.append((cid, title, status, "No code-fix path; governance/process control."))
        elif hit.get("process_only"):
            process_only.append((cid, title, status, hit.get("note", "")))
        else:
            routed.append((cid, title, status, hit))
    return routed, process_only, unmapped


def build_plan(framework_key, report):
    routing = load_routing(framework_key)
    gaps = gaps_from_report(report)
    strategy = routing.get("match_strategy", "exact_id")
    if strategy == "exact_id":
        routed, process_only, unmapped = route_exact_id(gaps, routing)
    elif strategy == "id_prefix":
        routed, process_only, unmapped = route_id_prefix(gaps, routing)
    elif strategy == "keyword":
        routed, process_only, unmapped = route_keyword(gaps, routing)
    else:
        sys.stderr.write(f"compliance-fix: unknown match_strategy {strategy}\n")
        sys.exit(2)

    # Dedupe commands while preserving order across all routed controls.
    seen = set()
    ordered_commands = []
    for cid, title, status, spec in routed:
        for entry in spec.get("commands", []):
            key = entry["cmd"]
            if key in seen:
                continue
            seen.add(key)
            ordered_commands.append({
                "cmd": key,
                "desc": entry.get("desc", ""),
                "for": [(cid, title)],
            })
        # Attach control to whatever was already added.
        for entry in spec.get("commands", []):
            for oc in ordered_commands:
                if oc["cmd"] == entry["cmd"] and (cid, title) not in oc["for"]:
                    oc["for"].append((cid, title))

    return {
        "framework": routing.get("framework", framework_key),
        "total_gaps": len(gaps),
        "routed": routed,
        "process_only": process_only,
        "unmapped": unmapped,
        "ordered_commands": ordered_commands,
    }


def print_plan(plan):
    fw = plan["framework"]
    print(f"\n{BOLD}🛡  agentic-security · compliance-fix · {fw}{RESET}\n")
    if plan["total_gaps"] == 0:
        print(f"{FROG}{BOLD}✓ No gaps.{RESET} All controls report Compliant. Nothing to fix.\n")
        return 0

    print(f"{BOLD}Gaps:{RESET} {plan['total_gaps']} "
          f"({len([c for c in plan['routed']])} routable, "
          f"{len(plan['process_only'])} process-only, "
          f"{len(plan['unmapped'])} unmapped)\n")

    if plan["ordered_commands"]:
        print(f"{BOLD}Execution plan ({len(plan['ordered_commands'])} step{'s' if len(plan['ordered_commands']) != 1 else ''}):{RESET}\n")
        for i, step in enumerate(plan["ordered_commands"], 1):
            print(f"  {i:>2}. {FROG}{BOLD}{step['cmd']}{RESET}")
            if step.get("desc"):
                print(f"      {DIM}{step['desc']}{RESET}")
            ids = ", ".join(cid for cid, _ in step["for"][:6])
            if len(step["for"]) > 6:
                ids += f", +{len(step['for']) - 6} more"
            print(f"      {DIM}closes: {ids}{RESET}")
            print()

    if plan["process_only"]:
        print(f"{BOLD}{DEEP}Not patchable by tooling{RESET} ({len(plan['process_only'])} control{'s' if len(plan['process_only']) != 1 else ''}):\n")
        for cid, title, status, note in plan["process_only"][:20]:
            print(f"  · {cid} — {title} {DIM}[{status}]{RESET}")
            if note:
                print(f"      {DIM}{note}{RESET}")
        if len(plan["process_only"]) > 20:
            print(f"  {DIM}+ {len(plan['process_only']) - 20} more (governance / process work){RESET}")
        print()

    if plan["unmapped"]:
        print(f"{DIM}Unmapped (no routing entry yet): "
              f"{', '.join(cid for cid, _, _ in plan['unmapped'][:10])}"
              f"{'...' if len(plan['unmapped']) > 10 else ''}{RESET}\n")

    print(f"{DIM}Run each step above in order. Most chain into /agentic-security:fix --all "
          f"to apply patches; review the previews before --apply.{RESET}\n")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Plan compliance fixes from a fresh scan.")
    ap.add_argument("framework", choices=list(FRAMEWORKS.keys()))
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--dry-run", action="store_true",
                    help="(reserved; current behavior is always plan-only — execution is the slash command's job)")
    ap.add_argument("--json", action="store_true", help="Emit the plan as JSON instead of human-readable.")
    args = ap.parse_args()

    report = run_scan(args.framework, args.path)
    plan = build_plan(args.framework, report)
    if args.json:
        # Routed/process_only contain tuples — JSON-serialize as objects.
        out = {
            "framework": plan["framework"],
            "total_gaps": plan["total_gaps"],
            "ordered_commands": plan["ordered_commands"],
            "process_only": [
                {"id": cid, "title": title, "status": status, "note": note}
                for cid, title, status, note in plan["process_only"]
            ],
            "unmapped": [
                {"id": cid, "title": title, "status": status}
                for cid, title, status in plan["unmapped"]
            ],
        }
        print(json.dumps(out, indent=2))
        return 0
    return print_plan(plan)


if __name__ == "__main__":
    sys.exit(main())
