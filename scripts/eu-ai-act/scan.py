#!/usr/bin/env python3
"""EU AI Act compliance scanner.

Uses scripts/_compliance_lib.py for the multi-signal evidence evaluation.
72 controls covering Art. 5 (prohibited), Art. 9-15 (high-risk), Art. 17 (QMS),
Art. 43/49 (conformity/registration), Art. 51-55 (GPAI), Art. 72-73 (post-market).
Applicability determination (Annex III) is owned by Legal / GRC.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _compliance_lib import run

if __name__ == "__main__":
    run(framework="EU AI Act", rules_path=os.path.join(HERE, "evidence-rules.json"))
