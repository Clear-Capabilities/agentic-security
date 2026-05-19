---
description: Show pre-built attack playbooks for high+ findings — copy-paste curl one-liners, Nuclei YAML templates, multi-step exploit probes. Every playbook includes an authorized-use ethics header.
argument-hint: "[--finding <id>] [--cwe <cwe>] [--all]"
---

Print attack playbooks the customer can run themselves against staging. Reads `.agentic-security/last-scan.json`.

```bash
MODE="--all"
ARG=""
for arg in "$@"; do
  case "$arg" in
    --finding) MODE="--finding" ;;
    --cwe) MODE="--cwe" ;;
    *) ARG="$arg" ;;
  esac
done

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }

const findings = (scan.findings || []).filter(f => f.attackPlaybook);
let target = findings;
const mode = process.env.MODE;
const arg = process.env.ARG;
if (mode === '--finding') target = findings.filter(f => f.id === arg || f.stableId === arg);
else if (mode === '--cwe')  target = findings.filter(f => (f.cwe || '').toUpperCase() === arg.toUpperCase());

const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
const BOLD='1', DIM='2';

if (!target.length) {
  console.log('No matching findings carry an attack playbook.');
  console.log(W('(Playbooks are only attached to high+/critical findings.)', DIM));
  process.exit(0);
}

console.log('');
console.log(W('Attack playbooks for ' + target.length + ' finding(s):', BOLD));
console.log('');

for (const f of target.slice(0, 20)) {
  const pb = f.attackPlaybook;
  console.log(W('━'.repeat(72), DIM));
  console.log(W(pb.cwe + ' — ' + pb.title, BOLD));
  console.log(W('Finding: ' + (f.vuln || '') + '  ' + f.file + ':' + f.line, DIM));
  console.log(W('Run kind: ' + pb.kind + '   How to confirm: ' + pb.instruction, DIM));
  console.log('');
  console.log(pb.script);
  console.log('');
}
console.log(W('━'.repeat(72), DIM));
console.log('');
console.log(W('Every playbook header includes an AUTHORIZED USE ONLY statement —', DIM));
console.log(W('run ONLY against systems you own or have explicit permission to test.', DIM));
" MODE="$MODE" ARG="$ARG"
```

## Modes

- **`/playbook`** — All playbooks attached to high+/critical findings from the last scan.
- **`/playbook --finding <id>`** — Just one finding's playbook.
- **`/playbook --cwe CWE-89`** — All playbooks for a specific CWE.

Coverage: SQLi (CWE-89), command injection (CWE-78), code injection (CWE-94), path traversal (CWE-22), SSRF (CWE-918), XSS (CWE-79), IDOR (CWE-639), CSRF (CWE-352), mass assignment (CWE-915), broken auth/JWT (CWE-287), webhook signature missing (CWE-345), unsafe deserialization (CWE-502), prototype pollution (CWE-1321), hardcoded creds (CWE-798), open redirect (CWE-601), XXE (CWE-611), missing authz (CWE-862), unrestricted upload (CWE-434), prompt injection (LLM01), unbounded LLM consumption (LLM10).

🛡  agentic-security · created by ClearCapabilities.Com
