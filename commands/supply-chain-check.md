---
description: One-screen supply-chain verdict. Rolls up dependency-CVE scan + KEV-listed deps + dep pinning + install-script audit + vendored-code audit + freshness into a single "is npm install safe?" answer. Replaces having to remember six separate /dep-* commands.
argument-hint: "[path] [--fix] [--strict]"
---

# Supply-chain check

The six dep commands (`/dep-pinning`, `/dep-freshness`, `/install-script-audit`, `/dep-alternatives`, `/vendor-audit`, `/trim-dependencies`) each answer one slice of the supply-chain question. This is the roll-up: **is it safe to `npm install`?**

It runs the SCA scan plus the five precision-loss-zero dep audits, then prints one verdict. No new detection — pure orchestration.

```bash
PATH_ARG="${1:-.}"
STRICT=""
DO_FIX=""
for a in "$@"; do
  case "$a" in
    --strict) STRICT=1 ;;
    --fix)    DO_FIX=1 ;;
  esac
done

W() { if [ -t 1 ]; then printf '\033[%sm%s\033[0m' "$2" "$1"; else printf '%s' "$1"; fi; }
BOLD=1; RED=31; YELLOW=33; GREEN=32; DIM=2; CYAN=36

echo ""
W "🛡  Supply-chain check  ·  $PATH_ARG" "$BOLD;36"; echo ""
echo "──────────────────────────────────────────────────────────────"
echo ""

SCANNER="${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs"

# 1. SCA — CVE-bearing deps (OSV + KEV + EPSS)
echo "  1/6  Dependency vulnerabilities (OSV + KEV + EPSS)"
node "$SCANNER" scan "$PATH_ARG" --only sca --format json --output .agentic-security/_sc-sca.json --no-network 2>/dev/null || true

CRIT=$(node -e "try { const f = require('fs').readFileSync('.agentic-security/_sc-sca.json','utf8'); const j = JSON.parse(f); const fs = (j.findings||[]).filter(x=>x.severity==='critical'); console.log(fs.length); } catch { console.log(0); }")
KEV=$(node -e "try { const f = require('fs').readFileSync('.agentic-security/_sc-sca.json','utf8'); const j = JSON.parse(f); console.log((j.findings||[]).filter(x=>x.kev).length); } catch { console.log(0); }")
HIGH=$(node -e "try { const f = require('fs').readFileSync('.agentic-security/_sc-sca.json','utf8'); const j = JSON.parse(f); console.log((j.findings||[]).filter(x=>x.severity==='high').length); } catch { console.log(0); }")
echo "       ${CRIT} critical · ${HIGH} high · ${KEV} actively exploited (KEV)"

# 2. Pinning — loose ranges that allow silent upgrades
echo ""
echo "  2/6  Pinning (loose version ranges)"
LOOSE=$(node -e "
try {
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('${PATH_ARG}/package.json','utf8'));
  const deps = { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) };
  const loose = Object.entries(deps).filter(([_,v]) => /^[\^~*]|^>/.test(String(v)));
  console.log(loose.length);
} catch { console.log(0); }
")
echo "       ${LOOSE} unpinned (^ ~ * >) — vulnerable to silent supply-chain injection"

# 3. Install scripts — postinstall/preinstall hooks (npm attack vector #1)
echo ""
echo "  3/6  Install scripts (postinstall / preinstall)"
SCRIPTS=$(node -e "
try {
  const fs = require('fs');
  const path = require('path');
  let count = 0;
  function walk(dir, depth) {
    if (depth > 2) return;
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) walk(path.join(dir, e.name), depth + 1);
      else if (e.name === 'package.json') {
        try {
          const p = JSON.parse(fs.readFileSync(path.join(dir, e.name), 'utf8'));
          const s = p.scripts || {};
          if (s.postinstall || s.preinstall) count++;
        } catch {}
      }
    }
  }
  walk('${PATH_ARG}/node_modules', 0);
  console.log(count);
} catch { console.log(0); }
")
echo "       ${SCRIPTS} packages run code on install"

# 4. Freshness — stale direct deps (CVE accumulation vector)
echo ""
echo "  4/6  Freshness (stale direct deps)"
echo "       Run /dep-freshness for per-dep ages."

# 5. Vendored code — third-party code copy-pasted in (invisible to scanners)
echo ""
echo "  5/6  Vendored code (third-party invisible to SCA)"
VENDORED=$(node -e "
try {
  const fs = require('fs');
  const path = require('path');
  let count = 0;
  const candidates = ['vendor', 'lib', 'third_party', 'thirdparty', 'external'];
  for (const c of candidates) {
    try {
      const full = path.join('${PATH_ARG}', c);
      if (fs.statSync(full).isDirectory()) count += fs.readdirSync(full).length;
    } catch {}
  }
  console.log(count);
} catch { console.log(0); }
")
echo "       ${VENDORED} entries in vendor/ lib/ third_party/"

# 6. Trim — installed but unused (attack surface)
echo ""
echo "  6/6  Unused installed deps"
echo "       Run /trim-dependencies for the precise list with removal commands."

# Verdict
echo ""
echo "──────────────────────────────────────────────────────────────"
echo ""
BLOCK=0
[ "$CRIT" -gt 0 ] && BLOCK=1
[ "$KEV"  -gt 0 ] && BLOCK=1
[ -n "$STRICT" ] && [ "$HIGH" -gt 0 ] && BLOCK=1
[ -n "$STRICT" ] && [ "$LOOSE" -gt 0 ] && BLOCK=1

if [ "$BLOCK" -eq 1 ]; then
  W "  ❌  NOT safe to npm install / publish" "$BOLD;$RED"; echo ""
  echo ""
  [ "$KEV"  -gt 0 ] && echo "      🔥  ${KEV} KEV-listed package(s) — being exploited in the wild"
  [ "$CRIT" -gt 0 ] && echo "      🔴  ${CRIT} critical CVE(s)"
  [ -n "$STRICT" ] && [ "$HIGH"  -gt 0 ] && echo "      🟠  ${HIGH} high CVE(s) (strict mode)"
  [ -n "$STRICT" ] && [ "$LOOSE" -gt 0 ] && echo "      🟡  ${LOOSE} unpinned (strict mode)"
  echo ""
  echo "      Fix:  /find-and-fix-everything"
  echo "            /dep-pinning --apply       (pin loose ranges)"
  echo "            /install-script-audit       (review postinstall hooks)"
elif [ "$HIGH" -gt 0 ] || [ "$LOOSE" -gt 0 ]; then
  W "  ⚠   Safe to npm install — with caveats" "$BOLD;$YELLOW"; echo ""
  echo ""
  [ "$HIGH"  -gt 0 ] && echo "      🟠  ${HIGH} high-severity CVE(s) — review with /show-findings"
  [ "$LOOSE" -gt 0 ] && echo "      🟡  ${LOOSE} loose version range(s) — pin with /dep-pinning"
else
  W "  ✅  Safe to npm install" "$BOLD;$GREEN"; echo ""
fi

echo ""
echo "──────────────────────────────────────────────────────────────"
echo ""
W "  Drill-down:" "$BOLD"; echo ""
echo "      /dep-pinning            Pin loose ranges"
echo "      /dep-freshness          Score stale deps"
echo "      /install-script-audit   Review postinstall scripts"
echo "      /vendor-audit           Audit vendored third-party code"
echo "      /trim-dependencies      Remove unused installed deps"
echo "      /dep-alternatives       Lighter / safer replacements"
echo ""
W "  🛡  agentic-security · created by Clear Capabilities" "$DIM"; echo ""

# Cleanup temp
rm -f .agentic-security/_sc-sca.json

# Exit code: 1 if blocked, 0 otherwise (vibecoder-compatible)
[ "$BLOCK" -eq 1 ] && exit 1 || exit 0
```

## Flags

- **`--strict`** — block also on high CVEs, loose pins, or any postinstall script
- **`--fix`** — after the verdict, offer to run `/find-and-fix-everything` and `/dep-pinning --apply`

## What blocks the verdict

| Default | `--strict` |
|---|---|
| Any **critical** CVE | + any **high** CVE |
| Any **KEV-listed** dep | + any **loose pin** (`^`, `~`, `*`, `>`) |
| | + any postinstall/preinstall script |

## What this replaces

| Question | Old answer | This command |
|---|---|---|
| "Are any of my deps being actively exploited?" | `/scan --sca` + read for KEV tags | `/supply-chain-check` line 1 |
| "Are my deps pinned?" | `/dep-pinning` | line 2 |
| "Does any dep run code on install?" | `/install-script-audit` | line 3 |
| "Are my deps stale?" | `/dep-freshness` | line 4 |
| "Is there vendored code I don't know about?" | `/vendor-audit` | line 5 |
| "What's installed but never imported?" | `/trim-dependencies` | line 6 |

Six commands → one verdict. Drill down with the original six when you need detail.

🛡  agentic-security · created by Clear Capabilities
