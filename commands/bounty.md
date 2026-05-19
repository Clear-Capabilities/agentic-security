---
description: Predicted bug-bounty USD payouts per finding — what HackerOne / Bugcrowd / Immunefi would likely pay. Sourced from public disclosure data; scaled down for findings already mitigated in production.
argument-hint: "[--top <N>] [--web3]"
---

Show predicted bounty payouts per finding from the last scan. Useful for prioritizing pentest engagement scope or external validation of finding severity.

```bash
TOP="20"
WEB3=""
for arg in "$@"; do
  case "$arg" in
    --top) TOP="next" ;;
    --web3) WEB3="1" ;;
    *) [ "$TOP" = "next" ] && TOP="$arg" ;;
  esac
done

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const wantWeb3 = process.env.WEB3 === '1';
const top = parseInt(process.env.TOP || '20', 10);
let findings = (scan.findings || []).filter(f => f.predictedBountyUsd);
if (wantWeb3) findings = findings.filter(f => f.predictedBountyUsd.program === 'web3');
findings.sort((a,b) => (b.predictedBountyUsd.likely||0) - (a.predictedBountyUsd.likely||0));
const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', GREEN='32';

if (!findings.length) {
  console.log('No bounty-predicted findings.' + (wantWeb3 ? ' (no Solidity findings detected)' : ''));
  console.log(W('Re-run /scan with v0.53+.', DIM));
  process.exit(0);
}

console.log('');
console.log(W('Predicted bug-bounty payouts (' + findings.length + ' findings)', BOLD));
console.log(W('Sourced from public HackerOne / Bugcrowd / Immunefi 2023–2025 disclosures.', DIM));
console.log('');
console.log('| Likely    | Range            | Program | Finding                                        | Location                |');
console.log('|-----------|------------------|---------|------------------------------------------------|-------------------------|');
let total = 0;
for (const f of findings.slice(0, top)) {
  const b = f.predictedBountyUsd;
  total += b.likely;
  const lk = '\$' + b.likely.toLocaleString();
  const rng = '\$' + b.low.toLocaleString() + '–\$' + b.high.toLocaleString();
  const vuln = (f.vuln||'').slice(0, 46).padEnd(46);
  const loc = (f.file + ':' + f.line).slice(0, 23).padEnd(23);
  console.log('| ' + lk.padEnd(9) + ' | ' + rng.padEnd(16) + ' | ' + (b.program || '-').padEnd(7) + ' | ' + vuln + ' | ' + loc + ' |');
}
console.log('');
console.log(W('Total likely payouts (top ' + Math.min(top, findings.length) + '): \$' + total.toLocaleString(), GREEN));
console.log(W('Note: amounts scaled down when finding is mitigated-in-prod or behind a 0% flag.', DIM));
" TOP="$TOP" WEB3="$WEB3"
```

## Modes

- **`/bounty`** — Top 20 by likely payout.
- **`/bounty --top 50`** — Show more.
- **`/bounty --web3`** — Solidity-only (Immunefi-style payouts).

Data is bucketed per `(CWE × severity)`. Findings without a known bug-bounty class (concurrency, spec-drift, info disclosure on non-prod paths) get no prediction.

🛡  agentic-security · created by ClearCapabilities.Com
