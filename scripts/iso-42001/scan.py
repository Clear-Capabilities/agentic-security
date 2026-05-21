#!/usr/bin/env python3
"""ISO/IEC 42001:2023 AI Management System compliance scanner.

Uses scripts/_compliance_lib.py for the multi-signal evidence evaluation.
This is a v0 mapping — code-detectable signals only. The full AIMS control
mapping is owned by Compliance / GRC and lives in evidence-rules.json.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _compliance_lib import run

if __name__ == "__main__":
    run(framework="ISO/IEC 42001:2023 AIMS (v0)", rules_path=os.path.join(HERE, "evidence-rules.json"))
