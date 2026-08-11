#!/usr/bin/env bash
# predeploy-gate.sh — block production deploys when critical findings exist.
#
# Source this in your shell profile, then deploy commands check the local
# .agentic-security/last-scan.json before running:
#
#   source <plugin>/scripts/predeploy-gate.sh
#   vercel deploy --prod        # ← intercepted, scans, blocks on critical
#
# Or, invoke directly to check the current state without intercepting:
#
#   bash predeploy-gate.sh check
#
# Configuration via .agentic-security/predeploy-gate.json:
#   {
#     "block_on": ["critical"],            # severities that block
#     "block_on_kev": true,                # also block on known-exploited deps
#     "require_recent_scan_hours": 24,     # fail if last scan older than this
#     "wrapped_commands": [
#       "vercel deploy --prod", "vercel --prod",
#       "fly deploy", "wrangler deploy", "wrangler publish",
#       "netlify deploy --prod", "railway up --service",
#       "flyctl deploy"
#     ]
#   }

set -uo pipefail

PREDEPLOY_GATE_VERSION="0.34.0"
GATE_CFG=".agentic-security/predeploy-gate.json"
SCAN_FILE=".agentic-security/last-scan.json"

# ─────────────────────────────────────────────────────────────────────────────
# Core check — returns 0 if safe to deploy, 1 otherwise. Prints reasoning.
# ─────────────────────────────────────────────────────────────────────────────
predeploy_gate_check() {
  local cwd="${1:-$PWD}"
  cd "$cwd" || return 1

  echo ""
  echo "🚦  agentic-security pre-deploy gate"

  # Read config (or defaults)
  local block_on='["critical"]'
  local require_hours=24
  local block_kev=true
  if [ -f "$GATE_CFG" ]; then
    block_on=$(python3 -c "import json,sys; print(json.dumps(json.load(open('$GATE_CFG')).get('block_on', ['critical'])))" 2>/dev/null || echo '["critical"]')
    require_hours=$(python3 -c "import json,sys; print(json.load(open('$GATE_CFG')).get('require_recent_scan_hours', 24))" 2>/dev/null || echo 24)
    block_kev=$(python3 -c "import json,sys; print(str(json.load(open('$GATE_CFG')).get('block_on_kev', True)).lower())" 2>/dev/null || echo true)
  fi

  # Check the scan exists
  if [ ! -f "$SCAN_FILE" ]; then
    echo "    ❌  No scan results found at $SCAN_FILE"
    echo "    Run a scan first:   /scan --all"
    return 1
  fi

  # Check scan freshness
  if [ "$require_hours" -gt 0 ]; then
    local now=$(date +%s)
    local scan_mtime
    if [[ "$OSTYPE" == "darwin"* ]]; then
      scan_mtime=$(stat -f %m "$SCAN_FILE" 2>/dev/null || echo 0)
    else
      scan_mtime=$(stat -c %Y "$SCAN_FILE" 2>/dev/null || echo 0)
    fi
    local age_hours=$(( (now - scan_mtime) / 3600 ))
    if [ "$age_hours" -gt "$require_hours" ]; then
      echo "    ❌  Last scan is ${age_hours}h old (max allowed: ${require_hours}h)"
      echo "    Run a fresh scan:   /scan --all"
      return 1
    fi
  fi

  # Count findings by severity AND KEV exposure in one pass. A failure here
  # (python3 missing, or the JSON unreadable/malformed) MUST fail closed:
  # this used to leave crit/high/med empty via a bare, fallback-less command
  # substitution, which made `[ "$crit" -gt 0 ]` error ("integer expression
  # expected") rather than compare — an error whose non-zero status made the
  # surrounding `&&` chain evaluate false, so `blocking` silently stayed 0
  # and the gate printed "Safe to deploy" for a scan it never actually read.
  # KEV: an earlier version read a top-level `kev`/`kevExposure` array that
  # last-scan.json never has — KEV status is a per-finding boolean
  # (`f.kev === true`; see scanner/src/report/index.js), so that branch was
  # permanently dead regardless of what the scan found. `declare` and assign
  # are kept on separate lines on purpose: `local x=$(cmd)` masks a failing
  # command substitution's exit status behind `local`'s own (always-0) one.
  local counts
  counts=$(python3 -c "
import json, sys
try:
    data = json.load(open('$SCAN_FILE'))
except Exception:
    sys.exit(1)
findings = []
for k in ('findings', 'logicVulns', 'supplyChain'):
    findings.extend(data.get(k, []) or [])
sev_counts = {'critical': 0, 'high': 0, 'medium': 0}
kev = 0
for f in findings:
    s = (f.get('severity') or '').lower()
    if s in sev_counts: sev_counts[s] += 1
    if f.get('kev') is True: kev += 1
print(sev_counts['critical'], sev_counts['high'], sev_counts['medium'], kev)
")
  if [ $? -ne 0 ] || [ -z "$counts" ]; then
    echo ""
    echo "    ❌  Could not read/parse $SCAN_FILE — refusing to guess whether it is safe to deploy."
    echo "    Run a fresh scan:   /scan --all"
    return 1
  fi
  local crit high med kev_count
  read -r crit high med kev_count <<< "$counts"

  echo "    Last scan:  $(date -r "$scan_mtime" 2>/dev/null || date -d "@$scan_mtime" 2>/dev/null || echo unknown)"
  echo "    Findings:   ${crit} critical · ${high} high · ${med} medium"

  # Decide based on block_on config
  local blocking=0
  local blocking_reasons=""
  if echo "$block_on" | grep -q '"critical"' && [ "$crit" -gt 0 ]; then
    blocking=1
    blocking_reasons+="${crit} critical finding(s). "
  fi
  if echo "$block_on" | grep -q '"high"' && [ "$high" -gt 0 ]; then
    blocking=1
    blocking_reasons+="${high} high finding(s). "
  fi

  # KEV check
  if [ "$block_kev" = "true" ] && [ "$kev_count" -gt 0 ]; then
    blocking=1
    blocking_reasons+="${kev_count} KEV-listed (known-exploited) package(s). "
  fi

  if [ "$blocking" = "1" ]; then
    echo ""
    echo "    🛑  BLOCKED: ${blocking_reasons}"
    echo ""
    echo "    Options:"
    echo "      1. Fix the issues:           /find-and-fix-everything"
    echo "      2. Triage one critical:      /show-findings --severity critical"
    echo "      3. Override this once:       AS_GATE_OVERRIDE=1 <your-deploy-command>"
    echo "      4. Loosen the gate:          edit $GATE_CFG"
    return 1
  fi

  echo ""
  echo "    ✅  Safe to deploy. Proceeding..."
  return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Wrapper helpers — define functions that replace deploy commands. The user
# sources this file once; the originals are still callable via `command vercel`.
# ─────────────────────────────────────────────────────────────────────────────
predeploy_gate_wrap() {
  if [ -n "${AS_GATE_OVERRIDE:-}" ]; then
    echo "    (AS_GATE_OVERRIDE set — gate bypassed)"
    return 0
  fi
  predeploy_gate_check "$PWD"
}

vercel() {
  case "$*" in
    *"deploy --prod"*|*"--prod"*|*" prod"*)
      predeploy_gate_wrap || return 1 ;;
  esac
  command vercel "$@"
}

fly() {
  case "$*" in
    "deploy"|"deploy "*)
      predeploy_gate_wrap || return 1 ;;
  esac
  command fly "$@"
}

flyctl() {
  case "$*" in
    "deploy"|"deploy "*)
      predeploy_gate_wrap || return 1 ;;
  esac
  command flyctl "$@"
}

wrangler() {
  case "$*" in
    "deploy"|"deploy "*|"publish"|"publish "*)
      predeploy_gate_wrap || return 1 ;;
  esac
  command wrangler "$@"
}

netlify() {
  case "$*" in
    *"deploy --prod"*|*"deploy "*"--prod"*)
      predeploy_gate_wrap || return 1 ;;
  esac
  command netlify "$@"
}

railway() {
  case "$*" in
    "up"|"up "*)
      predeploy_gate_wrap || return 1 ;;
  esac
  command railway "$@"
}

# Standalone invocation: bash predeploy-gate.sh check
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  if [ "${1:-check}" = "check" ]; then
    predeploy_gate_check "$PWD"
    exit $?
  fi
fi
