---
description: Route every Not-Compliant control from /compliance-report to the agentic-security command that closes it, in a deduped/ordered plan. Flags controls that are not patchable by tooling.
argument-hint: "[nist|asvs|llm] [path] [--json]"
---

Re-runs the chosen compliance scanner, then prints an execution plan: each Not-Compliant or Partial control routed to the `/agentic-security:*` command that addresses it, deduplicated and ordered, with process-only controls listed separately.

```bash
FRAMEWORK="${1:-}"
PATH_ARG="${2:-.}"
EXTRA_ARGS="${@:3}"

case "$FRAMEWORK" in
  nist|asvs|llm)
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/compliance-fix/plan.py "$FRAMEWORK" "$PATH_ARG" $EXTRA_ARGS
    ;;
  *)
    echo "Usage: /compliance-fix [nist|asvs|llm] [path] [--json]"
    echo ""
    echo "  nist   — route NIST AI 600-1 gaps (122 controls; most are governance/process)"
    echo "  asvs   — route OWASP ASVS Level 1+2 gaps"
    echo "  llm    — route OWASP LLM Top 10 (2025) gaps"
    echo ""
    echo "  --json   emit the plan as machine-readable JSON instead of human-readable text"
    exit 1
    ;;
esac
```

## How it works

1. Re-runs the underlying scanner (same engine as `/compliance-report`) with JSON output.
2. For every control whose status is `Not Compliant` or `Partial`, looks up the routing entry in `scripts/compliance-fix/routing-<framework>.json`.
3. Deduplicates commands across controls (e.g., `/agentic-security:fix --all` is referenced by many LLM controls but appears once in the plan).
4. Prints each command with the control IDs it closes plus a one-line description of what it does.
5. Lists controls that have no tooling fix (`process_only: true` in routing, or no keyword match for NIST) in a separate section with a note explaining what they require.

## After the plan

You can execute the listed commands in order; most chain into `/agentic-security:fix --all` to apply patches. Review each `--preview` before running `--apply`.

Re-run `/compliance-report <framework>` afterwards to confirm the gap count dropped.
