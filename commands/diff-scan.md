---
description: Differential scanner (FR-SDLC-10) — run two versions of the agentic-security scanner side-by-side and report the delta. Catches regressions in the scanner itself and lets you safely preview a scanner upgrade.
argument-hint: "--baseline <bin-path> --candidate <bin-path> [--root <dir>] [--format cli|json]"
---

Run baseline and candidate scanner binaries against the same target; emit a structured delta of added / removed / changed findings.

```bash
BASELINE=""
CANDIDATE=""
ROOT="."
FORMAT="cli"
NEXT=""
for arg in "$@"; do
  case "$NEXT" in
    baseline) BASELINE="$arg"; NEXT="" ; continue ;;
    candidate) CANDIDATE="$arg"; NEXT="" ; continue ;;
    root) ROOT="$arg"; NEXT="" ; continue ;;
    format) FORMAT="$arg"; NEXT="" ; continue ;;
  esac
  case "$arg" in
    --baseline) NEXT="baseline" ;;
    --candidate) NEXT="candidate" ;;
    --root) NEXT="root" ;;
    --format) NEXT="format" ;;
  esac
done

if [ -z "$BASELINE" ] || [ -z "$CANDIDATE" ]; then
  echo "Usage: /diff-scan --baseline <path-to-prev-scanner.mjs> --candidate <path-to-new-scanner.mjs> [--root .]"
  echo ""
  echo "Example:"
  echo "  /diff-scan --baseline /tmp/agentic-security-v0.51.mjs \\"
  echo "             --candidate \${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs"
  exit 1
fi

node ${CLAUDE_PLUGIN_ROOT}/scanner/bin/agentic-security-diff.js \
  --baseline "$BASELINE" \
  --candidate "$CANDIDATE" \
  --root "$ROOT" \
  --format "$FORMAT"
ec=$?
# Exit 1 means "delta detected" — not an error.
[ $ec -le 1 ] && exit 0 || exit $ec
```

## What the report shows

| Section | Meaning |
|---|---|
| **Added** | The candidate version finds something the baseline missed (new detector or improved rule). |
| **Removed** | The candidate version no longer finds something the baseline did (rule removed, FP suppression, or **regression** if it should still fire). |
| **Changed** | Same finding (matched by `stableId` or `(file, line, family)`) with different severity or wording. |

## Use cases

- **CI regression gate**: run on every release of the scanner; fail the build if the delta is non-trivial.
- **Pre-bump preview**: before upgrading a customer's pinned scanner version, show them exactly what changes.
- **Bug-bounty / pentest**: confirm that a "missing" finding in v0.53 was intentional in the changelog, not an accidental regression.

🛡  agentic-security · created by ClearCapabilities.Com
