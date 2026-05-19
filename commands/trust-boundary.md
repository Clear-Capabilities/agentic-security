---
description: Auto-generated Mermaid diagram of your architecture's trust boundaries — HTTP routes, queue producers/consumers, gRPC endpoints, DB edges, IaC-exposed assets — with findings rendered ON the diagram.
argument-hint: "[--output <file.svg|file.md>] [--inline]"
---

Render the v3 trust-boundary diagram. Default: write Markdown with embedded Mermaid to `reports/trust-boundary-<timestamp>.md` and open it. Pass `--inline` to dump the Mermaid source to stdout.

```bash
INLINE=""
OUT=""
for arg in "$@"; do
  case "$arg" in
    --inline) INLINE="1" ;;
    --output) OUT="next" ;;
    *) [ "$OUT" = "next" ] && OUT="$arg" ;;
  esac
done

node -e "
const fs = require('fs');
const path = require('path');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const d = scan._v3 && scan._v3.trustBoundaryDiagram;
if (!d) { console.log('No trust-boundary diagram on last scan. Re-run /scan with v0.52+.'); process.exit(0); }

const inline = process.env.INLINE === '1';
const explicitOut = process.env.OUT && process.env.OUT !== 'next' ? process.env.OUT : '';

if (inline) {
  process.stdout.write(d.mermaid + '\n');
  process.exit(0);
}

const ts = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
const out = explicitOut || ('reports/trust-boundary-' + ts + '.md');
fs.mkdirSync(path.dirname(out), { recursive: true });

const decorations = (d.decorations || []).slice(0, 25);
const body = [
  '# Trust Boundaries',
  '',
  '> Auto-generated from the last scan. Updated each time you run /scan.',
  '> Severity-styled nodes carry findings; uncolored nodes are clean.',
  '',
  '```mermaid',
  d.mermaid,
  '```',
  '',
  '## Decorations (' + (d.decorations || []).length + ' findings rendered on the diagram)',
  '',
];
for (const dec of decorations) {
  body.push('- **[' + (dec.severity || '').toUpperCase() + ']** ' + dec.vuln + '  →  ' + dec.file + ':' + dec.line);
}
if ((d.decorations || []).length > decorations.length) body.push('- ... and ' + ((d.decorations || []).length - decorations.length) + ' more');

fs.writeFileSync(out, body.join('\n'));
console.log('Trust-boundary diagram written: ' + out);
console.log('');
console.log('Open in any Markdown viewer with Mermaid support (VS Code, GitHub, Obsidian).');
console.log('Or pipe the inline source: /trust-boundary --inline');
" INLINE="$INLINE" OUT="$OUT"

# Try to open it for the user.
if [ -z "$INLINE" ] && [ -f reports/trust-boundary-*.md ]; then
  LATEST=$(ls -t reports/trust-boundary-*.md 2>/dev/null | head -1)
  [ -n "$LATEST" ] && (open "$LATEST" 2>/dev/null || xdg-open "$LATEST" 2>/dev/null || true)
fi
```

## What's on the diagram

| Node shape | Kind |
|---|---|
| `((Internet))` | external attacker source |
| `[Application]` | central application node |
| `[route@…]` | HTTP routes (Express / Next.js / FastAPI / Flask / Spring) |
| `[producer/consumer]` | message queue boundary (Kafka / SQS / RabbitMQ / Redis / PubSub) |
| `[grpc@…]` | gRPC server endpoint |
| `[(db@…)]` | database edge |
| `[/asset/]` | crown-jewel assets (Stripe / Auth0 / S3 / LLM / sessions) |

Findings on a node color the node by severity (red = critical, orange = high, yellow = medium, blue = low). The diagram is regenerated on every `/scan` so it reflects the codebase, not a stale diagram.

🛡  agentic-security · created by ClearCapabilities.Com
