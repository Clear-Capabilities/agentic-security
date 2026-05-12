#!/usr/bin/env python3
"""Benchmark the OWASP LLM Top 10 scanner against a reference corpus.

Ground truth for the OWASP agent_security_initiative corpus:
  - LLM01  NOT_COMPLIANT  promptinjection.py is the attack demo; no guardrails library present
  - LLM02  NOT_COMPLIANT  faker is test-data generation, not PII protection; no Presidio/scrubadub
  - LLM03  PARTIAL        poetry.lock sha256 hashes = genuine dep-integrity; no SBOM tooling
  - LLM04  NOT_COMPLIANT  sandbox/DVC appear only in problem-description docs; no prevention tooling
  - LLM05  NOT_COMPLIANT  no output-sanitization library anywhere
  - LLM06  NOT_COMPLIANT  HITL reference is the "overwhelming HITL" attack doc; no rate-limiting
  - LLM07  NOT_COMPLIANT  guardrails referenced in README screenshots, never installed/imported
  - LLM08  NOT_COMPLIANT  chromadb used without access controls; no audit logging
  - LLM09  PARTIAL        autogen refund demo has a real llama-index RAG knowledgebase
  - LLM10  NOT_COMPLIANT  timeout/quota appear only in lockfile metadata and problem docs

F1 treats "Compliant" and "Partial" as positive (mitigation evidence found).
"Not Compliant" is negative (no evidence).

Usage:
  python3 benchmark.py <corpus_path>
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

GROUND_TRUTH = {
    "LLM01": "Not Compliant",
    "LLM02": "Not Compliant",
    "LLM03": "Partial",
    "LLM04": "Not Compliant",
    "LLM05": "Not Compliant",
    "LLM06": "Not Compliant",
    "LLM07": "Not Compliant",
    "LLM08": "Not Compliant",
    "LLM09": "Partial",
    "LLM10": "Not Compliant",
}

def is_positive(status):
    return status in ("Compliant", "Partial")

def run_scanner(corpus_path):
    result = subprocess.run(
        [sys.executable, os.path.join(HERE, "scan.py"), corpus_path, "--format", "json"],
        capture_output=True, text=True
    )
    if result.returncode != 0 and not result.stdout.strip():
        print("Scanner error:", result.stderr, file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)

def f1(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    score     = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, score

def run_benchmark(corpus_path):
    scan = run_scanner(corpus_path)
    controls = {c["id"]: c for c in scan["controls"]}

    tp = fp = fn = tn = 0
    rows = []
    for ctrl_id, gt_status in GROUND_TRUTH.items():
        ctrl = controls.get(ctrl_id, {})
        pred_status = ctrl.get("status", "Not Compliant")
        gt_pos  = is_positive(gt_status)
        pred_pos = is_positive(pred_status)

        if gt_pos and pred_pos:
            outcome, tp = "TP", tp + 1
        elif not gt_pos and not pred_pos:
            outcome, tn = "TN", tn + 1
        elif not gt_pos and pred_pos:
            outcome, fp = "FP — false alarm", fp + 1
        else:
            outcome, fn = "FN — missed", fn + 1

        rows.append((ctrl_id, gt_status, pred_status, outcome))

    precision, recall, f1_score = f1(tp, fp, fn)

    # Print per-control table
    print()
    print(f"{'Control':<8} {'Ground Truth':<18} {'Scanner':<18} {'Verdict'}")
    print("-" * 70)
    for ctrl_id, gt, pred, outcome in rows:
        marker = "" if outcome in ("TP", "TN") else " ←"
        print(f"{ctrl_id:<8} {gt:<18} {pred:<18} {outcome}{marker}")

    print()
    print(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"Precision : {precision:.3f}")
    print(f"Recall    : {recall:.3f}")
    print(f"F1 Score  : {f1_score:.3f}")

    if f1_score >= 1.0 and fp == 0 and fn == 0:
        print("\n✅  100% F1 — all controls correctly classified")
    else:
        print(f"\n❌  F1 = {f1_score:.3f} — tuning required")
    print()
    return f1_score

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", nargs="?",
        default="/tmp/owasp-llm-bench/initiatives/agent_security_initiative",
        help="Path to the benchmark corpus")
    args = ap.parse_args()
    score = run_benchmark(args.corpus)
    sys.exit(0 if score >= 1.0 else 1)
