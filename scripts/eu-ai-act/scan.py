#!/usr/bin/env python3
"""EU AI Act compliance scanner — Articles 9 through 15 (high-risk AI obligations).

Uses scripts/_compliance_lib.py for the multi-signal evidence evaluation.
This is a v0 mapping — code-detectable signals only. The legal mapping and
applicability determination (is this AI "high-risk"?) are owned by Legal / GRC.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _compliance_lib import run

if __name__ == "__main__":
    run(framework="EU AI Act Articles 9–15 (v0)", rules_path=os.path.join(HERE, "evidence-rules.json"))
