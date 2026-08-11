#!/usr/bin/env python3
"""Regression tests for scripts/_compliance_lib.py (CMP-8, Stage-0 audit, 2026).

Two independent defects, reproduced live before this fix:

1. WEAK-SIGNAL-ONLY "Compliant". evaluate() declared a control "Compliant" on
   `weight >= 8 or len(signals) >= 3` — the second branch has no weight floor
   at all. Three distinct WEAK-tier signal kinds (doc_term=1.0,
   config_term=1.5, comment=0.5 — a word mentioned once in a README, once in
   a YAML config, and once in a code comment) satisfy `len(signals) >= 3`
   with a combined weight of only 3.0, nowhere near the 8.0 the weight-based
   branch requires. That is three throwaway word mentions producing a real
   Compliant checkmark in a document titled "<framework> compliance
   attestation" — sibling scripts/nist-compliance/scan.py already closed
   this exact hole with a `weak_only` guard; this module had drifted from it.

2. NO DISCLAIMER / METHODOLOGY / SKIP DISCLOSURE. The markdown output had no
   disclaimer that automated signal-matching is not a compliance
   certification, no explanation of the weight/threshold scheme a reader
   would need to judge the numbers, and files over 500KB were silently
   skipped in list_files() with no count surfaced anywhere.

Run directly: python3 scripts/test__compliance_lib.py
"""
from __future__ import annotations
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "_compliance_lib", REPO_ROOT / "scripts" / "_compliance_lib.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _mkproject(files):
    tmpdir = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = tmpdir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmpdir


def test_three_weak_signal_kinds_alone_cannot_reach_compliant(mod):
    # Each TERM only counts once (evaluate() breaks after the first matching
    # file per term) — three distinct terms, one per low-weight file kind, is
    # what actually produces three distinct signal KINDS from three
    # throwaway word mentions, which is the real shape of the bug: a doc_term
    # (1.0) + config_term (1.5) + code_term (2.0) totals 4.5 — nowhere near a
    # substantive evidence bar — but satisfied the old `len(signals) >= 3`
    # branch regardless of how low the combined weight was.
    tmpdir = _mkproject({
        "README.md": "We support encryption for data at rest.",
        "config.yaml": "logging: enabled",
        "app.py": "audited_flag = True\n",
    })
    try:
        ctrl = {"id": "C1", "title": "Encryption", "terms": ["encryption", "logging", "audited_flag"]}
        results = mod.evaluate(str(tmpdir), [ctrl])
        r = results["C1"]
        _assert(len(set(r["signals"])) >= 3, f"expected 3 distinct signal kinds, got {r['signals']}")
        _assert(r["weight"] < 8.0, f"expected weight under 8, got {r['weight']}")
        _assert(r["status"] != "Compliant",
            f"three throwaway low-weight signal kinds (weight={r['weight']}) must not reach Compliant; got {r['status']}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_a_real_manifest_dependency_can_still_reach_compliant(mod):
    tmpdir = _mkproject({
        "package.json": '{"dependencies": {"helmet": "^7.0.0"}}',
        "app.js": "const helmet = require('helmet');\nconst x = 1;\n",
        "README.md": "We use helmet for security headers.",
    })
    try:
        ctrl = {"id": "C2", "title": "Security headers", "manifest_deps": ["helmet"], "imports": ["helmet"], "terms": ["helmet"]}
        results = mod.evaluate(str(tmpdir), [ctrl])
        r = results["C2"]
        _assert(r["status"] == "Compliant",
            f"real manifest+import+doc evidence (strong signals present) must still reach Compliant; got {r['status']} weight={r['weight']} signals={r['signals']}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_markdown_output_carries_a_disclaimer_and_methodology(mod):
    tmpdir = _mkproject({"README.md": "hello"})
    try:
        ctrl = {"id": "C1", "title": "Encryption", "terms": ["encryption"]}
        results = mod.evaluate(str(tmpdir), [ctrl])
        out = tmpdir / "out.md"
        mod.emit(results, [ctrl], "Test Framework", "md", str(out))
        body = out.read_text()
        lower = body.lower()
        _assert("does not certify" in lower or "not a certification" in lower or "not certify compliance" in lower,
            f"markdown output must carry a non-certification disclaimer, got:\n{body[:600]}")
        _assert("weight" in lower and ("signal" in lower or "methodology" in lower),
            "markdown output must explain the weight/signal methodology, not just print a bare table")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_skipped_oversized_files_are_disclosed(mod):
    tmpdir = _mkproject({"README.md": "hello"})
    try:
        big = tmpdir / "big.txt"
        big.write_bytes(b"x" * 600_000)
        files, skipped = mod.list_files(str(tmpdir))
        _assert(str(big) not in files, "an oversized file must still be excluded from the scanned set")
        _assert(len(skipped) == 1, f"the oversized file must be reported in the skip list, got {skipped}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    mod = _load_module()
    tests = [
        test_three_weak_signal_kinds_alone_cannot_reach_compliant,
        test_a_real_manifest_dependency_can_still_reach_compliant,
        test_markdown_output_carries_a_disclaimer_and_methodology,
        test_skipped_oversized_files_are_disclosed,
    ]
    failures = []
    for t in tests:
        try:
            t(mod)
            print(f"  OK: {t.__name__}")
        except AssertionError as e:
            failures.append(f"{t.__name__}: {e}")
            print(f"  FAIL: {t.__name__}: {e}")
    if failures:
        print(f"\n{len(failures)}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    main()
