---
description: Pre-incident archaeology — given a finding, walks git history to answer "when did this codebase first become vulnerable to this?" Essential for post-mortems, root-cause analysis, and regulatory due-diligence.
argument-hint: "--finding <id-or-stableId> | --cwe <CWE-NNN>"
---

For a finding, surface the first commit where the vulnerable code shape appears, how long the codebase has been exposed, and the most recent commit where the same file was safe.

Requires the project to be a git repository.

```bash
MODE=""
ARG=""
for arg in "$@"; do
  case "$arg" in
    --finding) MODE="--finding" ;;
    --cwe) MODE="--cwe" ;;
    *) [ -n "$MODE" ] && [ -z "$ARG" ] && ARG="$arg" ;;
  esac
done

if [ -z "$ARG" ]; then
  echo "Usage: /archaeology --finding <id>     (or --cwe <CWE-NNN>)"
  echo ""
  echo "Examples:"
  echo "  /archaeology --finding sast:42"
  echo "  /archaeology --finding a3b8f1c92d4e7855       # 16-hex stableId"
  echo "  /archaeology --cwe CWE-89                     # all CWE-89 findings"
  exit 1
fi

node -e "
const fs = require('fs');
const { archaeologyForFinding } = require('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/pre-incident-archaeology.js');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const mode = process.env.MODE;
const arg = process.env.ARG;
const findings = scan.findings || [];
let target;
if (mode === '--finding') target = findings.filter(f => f.id === arg || f.stableId === arg);
else if (mode === '--cwe')  target = findings.filter(f => (f.cwe || '').toUpperCase() === arg.toUpperCase());
else target = [];

if (!target.length) { console.log('No matching finding(s) in last scan.'); process.exit(0); }

const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', YELLOW='33';

(async () => {
  for (const f of target.slice(0, 10)) {
    console.log('');
    console.log(W('━'.repeat(72), DIM));
    console.log(W((f.vuln || '') + '  ' + f.file + ':' + f.line, BOLD));
    const r = await Promise.resolve(archaeologyForFinding({
      file: f.file,
      line: f.line,
      snippet: f.snippet,
      stableId: f.stableId,
      vuln: f.vuln,
    }, process.cwd()));
    if (!r.available) { console.log(W('  Archaeology unavailable: ' + r.reason, DIM)); continue; }
    const c0 = r.introducingCommit;
    console.log('  ' + W('First vulnerable commit:', BOLD) + ' ' + c0.sha.slice(0, 12));
    console.log('    ' + W('author: ', DIM) + c0.author);
    console.log('    ' + W('date:   ', DIM) + c0.ts);
    console.log('    ' + W('msg:    ', DIM) + (c0.message || '').slice(0, 80));
    console.log('  ' + W('Vulnerable for:        ', BOLD) + W(r.vulnerableForDays + ' days', YELLOW));
    if (r.lastSafeCommit) {
      console.log('  ' + W('Last safe commit:      ', BOLD) + r.lastSafeCommit.sha.slice(0, 12) + '  (' + r.lastSafeCommit.ts + ')');
    }
    console.log('  ' + W('History walked:        ', BOLD) + r.historyLength + ' commit(s)');
  }
  console.log('');
})();
" MODE="$MODE" ARG="$ARG"
```

## Use cases

- **Post-mortem**: when a CVE in your code surfaces, prove (or disprove) "we were already vulnerable when X happened."
- **Regulatory due-diligence**: pinpoint the exposure window for a compliance report.
- **Root-cause**: surface the PR that introduced the pattern; sometimes the message is the smoking gun.

## Limitations

- Uses substring presence as a proxy for "scanner would have fired" — does not re-run SAST against historical revisions (that's a separate, expensive operation).
- Walks the last 50 commits affecting the file by default.
- Returns `available: false` when not in a git repo or when the finding has no snippet.

🛡  agentic-security · created by ClearCapabilities.Com
