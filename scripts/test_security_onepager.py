#!/usr/bin/env python3
"""Regression tests for scripts/security-onepager.py (CMP-9, Stage-0 audit, 2026).

Two independent defects, reproduced live before this fix:

1. FABRICATED CLAIMS. data_handling_block() hardcoded specific infrastructure
   facts ("TLS 1.2+ for all inbound and outbound traffic", "All databases are
   encrypted with provider-managed keys (AES-256)", "No engineer has direct
   production database access") as an unconditional template — never derived
   from the scan, the stack, or anything about the actual project. The
   document's own preamble promised "generated from our actual security
   tooling, not a marketing template — if something here is wrong, our
   scanner will flag it." That promise was false for this block: nothing
   about it could ever be wrong in the scanner's eyes, because nothing
   checked it.

2. FILE CLOBBERING. main() called `out.write_text(md)` unconditionally on the
   default output path SECURITY.md — a filename GitHub itself recognises as a
   project's real vulnerability-disclosure policy. A repo with a hand-authored
   SECURITY.md would have it silently destroyed on first run.

Run directly: python3 scripts/test_security_onepager.py
"""
from __future__ import annotations
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "security_onepager", REPO_ROOT / "scripts" / "security-onepager.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_data_handling_block_is_not_presented_as_verified_fact(mod):
    block = mod.data_handling_block()
    # The specific, unverifiable infrastructure claims must not appear as
    # unconditional assertions of fact anymore.
    _assert("TLS 1.2+ for all inbound and outbound traffic" not in block,
        "a specific TLS-version claim must not be asserted unconditionally — "
        "nothing in this tool checks it")
    _assert("No engineer has direct production database access" not in block,
        "an access-control claim about the reader's own infrastructure must "
        "not be asserted unconditionally")
    # It must instead be honest that this section needs operator review.
    lower = block.lower()
    _assert("review" in lower or "verify" in lower or "edit" in lower or "fill in" in lower,
        f"data_handling_block must flag itself as needing operator review, got:\n{block}")
    print("  OK: data_handling_block no longer asserts unverified facts")


def test_preamble_does_not_overclaim_full_tool_verification(mod):
    md = mod.render("Acme", "security@acme.test", None, [], {}, REPO_ROOT)
    _assert("not a marketing template" not in md or "operator-attested" in md.lower() or "review" in md.lower(),
        "the preamble must not claim every section is tool-verified when the "
        "data-handling section is operator-filled")
    print("  OK: preamble does not overclaim full tool verification")


def test_main_refuses_to_clobber_an_existing_output_file(mod):
    tmpdir = Path(tempfile.mkdtemp())
    try:
        existing = tmpdir / "SECURITY.md"
        existing.write_text("# Our real, hand-authored vulnerability disclosure policy\n")
        original = existing.read_text()

        old_argv = sys.argv
        sys.argv = ["security-onepager.py", "--cwd", str(tmpdir)]
        try:
            try:
                mod.main()
                refused = False
            except SystemExit as e:
                refused = (e.code not in (0, None))
        finally:
            sys.argv = old_argv

        _assert(existing.read_text() == original,
            "an existing SECURITY.md must not be overwritten without --force")
        _assert(refused, "main() must exit non-zero when refusing to overwrite")
        print("  OK: existing SECURITY.md was not clobbered, exit was non-zero")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_main_writes_with_explicit_force(mod):
    tmpdir = Path(tempfile.mkdtemp())
    try:
        existing = tmpdir / "SECURITY.md"
        existing.write_text("old content\n")

        old_argv = sys.argv
        sys.argv = ["security-onepager.py", "--cwd", str(tmpdir), "--force"]
        try:
            mod.main()
        finally:
            sys.argv = old_argv

        _assert(existing.read_text() != "old content\n",
            "--force must allow the overwrite (guard against over-tightening)")
        print("  OK: --force allows the overwrite")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_main_writes_cleanly_when_no_file_exists(mod):
    tmpdir = Path(tempfile.mkdtemp())
    try:
        old_argv = sys.argv
        sys.argv = ["security-onepager.py", "--cwd", str(tmpdir)]
        try:
            mod.main()
        finally:
            sys.argv = old_argv
        _assert((tmpdir / "SECURITY.md").exists(),
            "with no pre-existing file, the write must succeed with no flag needed")
        print("  OK: writes cleanly when nothing would be clobbered")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    mod = _load_module()
    tests = [
        test_data_handling_block_is_not_presented_as_verified_fact,
        test_preamble_does_not_overclaim_full_tool_verification,
        test_main_refuses_to_clobber_an_existing_output_file,
        test_main_writes_with_explicit_force,
        test_main_writes_cleanly_when_no_file_exists,
    ]
    failures = []
    for t in tests:
        try:
            t(mod)
        except AssertionError as e:
            failures.append(f"{t.__name__}: {e}")
            print(f"  FAIL: {t.__name__}: {e}")
    if failures:
        print(f"\n{len(failures)}/{len(tests)} FAILED")
        sys.exit(1)
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    main()
