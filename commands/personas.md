---
description: Per-attacker-persona prioritization of findings — what each adversary class (script kiddie / opportunistic / APT / supply-chain / insider) would target first in your codebase.
argument-hint: "[--persona <name>] [--top <N>]"
---

Show findings ranked per attacker persona. Each finding carries a 5-persona severity matrix; this command pivots the view so you see "what would a $PERSONA target?" instead of CVSS-flat severity.

```bash
PERSONA=""
TOP="5"
for arg in "$@"; do
  case "$arg" in
    --persona) PERSONA="next" ;;
    --top) TOP="next" ;;
    *)
      [ "$PERSONA" = "next" ] && PERSONA="$arg" && continue
      [ "$TOP" = "next" ] && TOP="$arg" && continue
      ;;
  esac
done

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const PERSONAS = ['script-kiddie','opportunistic-criminal','apt-nation-state','supply-chain-attacker','malicious-insider'];
const findings = (scan.findings || []).filter(f => f.personaScores);
if (!findings.length) { console.log('No persona-scored findings. Re-run /scan with v0.52+.'); process.exit(0); }

const target = process.env.PERSONA || '';
const top = parseInt(process.env.TOP || '5', 10);
const W = (s, c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', YELLOW='33', RED='31';

const personasToShow = target ? [target] : PERSONAS;
console.log('');
for (const p of personasToShow) {
  const items = findings.filter(f => f.personaScores[p]).slice().sort((a,b) =>
    (b.personaScores[p].score || 0) - (a.personaScores[p].score || 0)
  );
  console.log(W(p, BOLD) + W('  (' + items.length + ' relevant findings)', DIM));
  if (!items.length) { console.log('  ' + W('— this persona has no high-priority findings in your codebase', DIM)); console.log(''); continue; }
  for (const f of items.slice(0, top)) {
    const ps = f.personaScores[p];
    const tier = ps.tier;
    const color = tier === 'critical' ? RED : tier === 'high' ? YELLOW : DIM;
    console.log('  [' + W((ps.score).toFixed(2), color) + ' ' + tier.padEnd(8) + '] ' +
                (f.vuln || '').slice(0, 60).padEnd(60) + '  ' + f.file + ':' + f.line);
  }
  console.log('');
}
console.log(W('Tip: /personas --persona apt-nation-state to focus on one adversary class.', DIM));
" PERSONA="$PERSONA" TOP="$TOP"
```

## Modes

- **`/personas`** — All 5 personas, top-5 each.
- **`/personas --persona apt-nation-state`** — Filter to one persona.
- **`/personas --top 10`** — Show 10 per persona.

## What the personas mean

| Persona | Cares about |
|---|---|
| `script-kiddie` | Drive-by exploits, no creds, exposed-in-prod surface |
| `opportunistic-criminal` | High-bounty / high-value targets, KEV-listed bugs |
| `apt-nation-state` | Persistence, lateral movement, crown-jewel proximity |
| `supply-chain-attacker` | Install-script vectors, typosquats, AI-generated patterns |
| `malicious-insider` | AuthZ bypass, IDOR, mass-assignment (bypasses edge controls) |

🛡  agentic-security · created by ClearCapabilities.Com
