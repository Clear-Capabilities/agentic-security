#!/usr/bin/env python3
"""NIST SP 800-171 Rev. 3 deep-attestation scanner.

A THIN WRAPPER. All of the matching and scoring lives in
`scripts/nist-compliance/scan.py`, which is framework-agnostic: it takes
`--catalog` and `--rules`, and reads the framework's name, slug and source from
the catalog itself. This file only supplies the 800-171 defaults.

Why a wrapper and not a copy: that engine is ~1200 lines and includes
ReDoS-hardened regex handling with its own guard test
(`scripts/nist-compliance/test_regex_redos.py`). Two copies would mean a fix to
one silently missing the other — a security-relevant divergence, not a cosmetic
one. A wrapper keeps exactly one copy of that logic.

Why not an extracted shared module: parameterising the existing engine was a
~20-line change against a working, release-gated tool, where extraction was a
1200-line restructure. The AI 600-1 scanner's output was pinned before and after
that change and is byte-identical.

    python3 scripts/nist-800-171/scan.py <path>       # attestation for <path>
    python3 scripts/nist-800-171/scan.py . --quiet

Writes `nist-800-171-r3-attestation.{md,csv,json}` by default — the slug comes
from the catalog, so this cannot collide with the AI 600-1 attestation.

SCOPE, and what this must not be read as: it reports evidence detectable from
source, manifests, configuration, documentation and CI in one repository. 43 of
800-171's 97 requirements are organisational, physical or personnel controls
that no code scanner can evidence; they have no rules here and are absent from
this attestation by design. This is not a CMMC assessment and produces no SPRS
score. See docs/compliance/nist-800-171-r3-coverage.md.

SCORING, and what it inherits: the weights and status thresholds below are
`scripts/nist-compliance/scan.py`'s, shared with AI 600-1, not independently
recalibrated for this evidence-rules.json's shape — see "The deep-attestation
scanner" in docs/compliance/nist-800-171-r3-coverage.md for the measured
difference (800-171's rules lean on term/path signals over named libraries far
more than AI 600-1's do) and why a rushed recalibration was deliberately not
done.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "nist-compliance" / "scan.py"

DEFAULT_CATALOG = HERE / "controls.json"
DEFAULT_RULES = HERE / "evidence-rules.json"


def main() -> int:
    if not ENGINE.exists():
        sys.stderr.write(f"ERROR: scanning engine not found at {ENGINE}\n")
        return 2
    for required, what in ((DEFAULT_CATALOG, "control catalog"), (DEFAULT_RULES, "evidence rules")):
        if not required.exists():
            sys.stderr.write(
                f"ERROR: {what} not found at {required}\n"
                f"       Run: python3 scripts/nist-800-171/build-catalog.py\n"
            )
            return 2

    argv = sys.argv[1:]
    # Caller-supplied flags win; these are only defaults.
    if not any(a == "--catalog" or a.startswith("--catalog=") for a in argv):
        argv += ["--catalog", str(DEFAULT_CATALOG)]
    if not any(a == "--rules" or a.startswith("--rules=") for a in argv):
        argv += ["--rules", str(DEFAULT_RULES)]

    sys.argv = [str(ENGINE), *argv]
    runpy.run_path(str(ENGINE), run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
