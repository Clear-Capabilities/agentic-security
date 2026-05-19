---
description: Auto-derived STRIDE threat model from the last scan — assets, trust boundaries, per-category finding counts, and top findings per attacker objective. Pairs with /personas for attacker-persona ranking.
argument-hint: "[--full] [--rebuild]"
---

Render the v3 auto-derived threat model. Reads `.agentic-security/last-scan.json`. Pass `--rebuild` to re-run `/scan` first.

```bash
REBUILD=""
FULL=""
for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD="1" ;;
    --full) FULL="1" ;;
  esac
done

if [ "$REBUILD" = "1" ] || [ ! -f .agentic-security/last-scan.json ]; then
  node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format json --output .agentic-security/last-scan.json >/dev/null 2>&1 || true
fi

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const tm = scan._v3 && scan._v3.threatModel;
const full = process.env.FULL === '1';
if (!tm) { console.log('No threat model on last scan. Re-run /scan with v0.53+.'); process.exit(0); }

const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
const BOLD='1', DIM='2';

console.log('');
console.log(W('STRIDE Threat Model — auto-derived', BOLD));
console.log(W('  ' + tm.summary.assetCount + ' assets · ' + tm.summary.boundaryCount + ' trust boundaries', DIM));
console.log('');
console.log('| Category               | Findings |');
console.log('|------------------------|----------|');
for (const [cat, count] of Object.entries(tm.summary.strideCounts)) {
  const pretty = cat.replace(/([A-Z])/g, ' \$1').trim();
  console.log('| ' + pretty.padEnd(22) + ' | ' + String(count).padEnd(8) + ' |');
}
console.log('');

if (full) {
  console.log(W('Per-category top findings:', BOLD));
  for (const [cat, items] of Object.entries(tm.stride)) {
    if (!items.length) continue;
    console.log('\n  ' + W(cat, BOLD) + ' (' + items.length + ')');
    for (const f of items.slice(0, 5)) {
      console.log('    [' + (f.severity||'').toUpperCase() + '] ' + (f.vuln || '').slice(0, 60) + '  ' + f.file + ':' + f.line);
    }
  }
  console.log('');
  console.log(W('Asset inventory:', BOLD));
  for (const a of tm.assets.slice(0, 15)) {
    console.log('  ' + a.category.padEnd(18) + ' ' + (a.name || '').slice(0, 30).padEnd(30) + ' ' + a.file + ':' + a.line);
  }
  console.log('');
  console.log(W('Trust boundaries:', BOLD));
  for (const b of tm.trustBoundaries.slice(0, 15)) {
    console.log('  ' + b.type.padEnd(20) + ' ' + (b.label || '').slice(0, 30).padEnd(30) + ' ' + b.file + ':' + b.line);
  }
}
console.log('');
console.log(W('Tip: /personas for attacker-persona ranking; /trust-boundary for the Mermaid diagram.', DIM));
"
```

## Modes

- **`/threat-model`** — Compact STRIDE table.
- **`/threat-model --full`** — STRIDE table + top findings per category + asset inventory + trust-boundary list.
- **`/threat-model --rebuild`** — Re-run `/scan` first, then render.

🛡  agentic-security · created by ClearCapabilities.Com
