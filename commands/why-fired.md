---
description: Show the provenance graph for ONE finding — exactly which detector fired, which rule matched, what evidence was present, and which suppressions / mitigations were considered. No black boxes.
argument-hint: "--finding <id-or-stableId>"
---

Print the v3 `whyFired` provenance record for a finding. Every finding shipped by the scanner carries this record so a security engineer can understand *exactly* why the engine emitted it.

```bash
ID=""
for arg in "$@"; do
  case "$arg" in
    --finding) : ;;
    *) [ -z "$ID" ] && ID="$arg" ;;
  esac
done

if [ -z "$ID" ]; then
  echo "Usage: /why-fired --finding <id-or-stableId>"
  echo ""
  echo "Example:"
  echo "  /why-fired --finding a3b8f1c92d4e7855"
  echo "  /why-fired --finding sast:42"
  exit 1
fi

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const id = process.env.ID;
const f = (scan.findings || []).find(x => x.id === id || x.stableId === id);
if (!f) { console.log('No finding matches ' + id + '. Use /show-findings --all to browse.'); process.exit(0); }
const w = f.whyFired;
if (!w) { console.log('Finding has no whyFired record. Re-run /scan with v0.52+.'); process.exit(0); }

const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', YELLOW='33', GREEN='32';

console.log('');
console.log(W('Provenance: ' + (f.vuln || ''), BOLD));
console.log(W('  ' + f.file + ':' + f.line + ' [' + (f.severity || '').toUpperCase() + ']', DIM));
console.log('');
console.log(W('Detector:        ', BOLD) + w.detector);
console.log(W('Rule ID:         ', BOLD) + w.ruleId);
console.log(W('Parser:          ', BOLD) + w.parser);
if (w.scanner && w.scanner.rulesetVersion) console.log(W('Rule pack:       ', BOLD) + w.scanner.rulesetVersion);
console.log('');
console.log(W('Evidence', BOLD));
if (w.evidence.sourceSnippet) console.log('  ' + W('source: ', DIM) + w.evidence.sourceSnippet.slice(0, 80));
if (w.evidence.sinkSnippet)   console.log('  ' + W('sink:   ', DIM) + w.evidence.sinkSnippet.slice(0, 80));
if (w.evidence.pathSteps && w.evidence.pathSteps.length) {
  console.log('  ' + W('flow:', DIM));
  for (const s of w.evidence.pathSteps.slice(0, 8)) console.log('    → ' + s.type + ' ' + (s.label || ''));
}
console.log('  ' + W('sanitizers considered: ', DIM) + (w.evidence.sanitizers.length ? w.evidence.sanitizers.join(', ') : '(none rejected)'));
console.log('  ' + W('guards observed:       ', DIM) + (w.evidence.guards.length ? w.evidence.guards.join(', ') : '(none)'));
console.log('');
console.log(W('What the engine considered', BOLD));
console.log('  reachability filter:    ' + w.considered.reachabilityFilter);
console.log('  cluster collapsed:      ' + (w.considered.clusterCollapsed ? 'yes (multiple flows → one finding)' : 'no'));
console.log('  type-narrowed:          ' + (w.considered.typeNarrowed ? 'yes (callsite types narrow this) — confidence demoted' : 'no'));
console.log('  crown-jewel tier:       ' + (w.considered.crownJewelTier || '(unscored)'));
console.log('  production verdict:     ' + (w.considered.mitigationVerdict || '(no prod context)'));
console.log('  suppressions applied:   ' + (w.considered.suppressionsApplied.length ? w.considered.suppressionsApplied.join(', ') : '(none)'));
console.log('  suppressions skipped:   ' + (w.considered.suppressionsSkipped.length ? w.considered.suppressionsSkipped.join(', ') : '(none)'));
console.log('');
if (f.exploitabilityFactors) {
  console.log(W('Exploitability factors:  ', BOLD) + f.exploitabilityFactors.join(', '));
}
if (f.calibrated_confidence != null) {
  console.log(W('Calibrated confidence:   ', BOLD) + (f.calibrated_confidence * 100).toFixed(1) + '%' +
              (f.calibrated_n ? '  (N=' + f.calibrated_n + ')' : ''));
}
console.log('');
" ID="$ID"
```

## Related transparency commands

- **`/why-not <CWE-NNN>`** — Inverse: what did the engine consider for this CWE that it did NOT emit?
- **`/explain --finding <id>`** — Plain-English explanation of the finding's impact and fix.
- **`/archaeology --finding <id>`** — When did this finding first appear in the codebase?

🛡  agentic-security · created by ClearCapabilities.Com
