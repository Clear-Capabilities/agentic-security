---
description: Single-point-of-failure defensive controls — counterfactual analysis of which auth / sanitizer / rate-limit / CSRF middleware, if removed or bypassed, would expose the most high+ findings. Prioritizes hardening BEFORE the attacker tests it.
argument-hint: "[--threshold <N>]"
---

Show the v3 counterfactual report. Each entry is a defensive control whose removal would expose ≥ 3 high+ findings — the brittlest pieces of your defense-in-depth.

```bash
THRESHOLD="3"
for arg in "$@"; do
  case "$arg" in
    --threshold) THRESHOLD="next" ;;
    *) [ "$THRESHOLD" = "next" ] && THRESHOLD="$arg" ;;
  esac
done

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const c = scan._v3 && scan._v3.counterfactual;
const threshold = parseInt(process.env.THRESHOLD || '3', 10);
const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', YELLOW='33', RED='31';

console.log('');
console.log(W('Single-point-of-failure controls (counterfactual)', BOLD));
if (!c) { console.log(W('Re-run /scan with v0.52+.', DIM)); process.exit(0); }
if (c.note === 'no-controls-detected') {
  console.log(W('No defensive controls detected in this codebase.', DIM));
  console.log(W('This is itself a finding — defense-in-depth is absent.', DIM));
  process.exit(0);
}
console.log(W('  ' + (c.controlsDetected || 0) + ' control(s) detected across the codebase', DIM));
console.log('');

const spof = (c.spofControls || []).filter(s => s.wouldExpose >= threshold);
if (!spof.length) {
  console.log(W('✅  No SPOF controls — every defensive control has redundant siblings or covers < ' + threshold + ' high+ findings.', '32'));
  process.exit(0);
}

console.log(W('  ' + spof.length + ' control(s) would expose ≥ ' + threshold + ' high+ findings if removed/bypassed:', RED));
console.log('');
for (const s of spof.slice(0, 20)) {
  console.log(W('  ' + s.control + ' @ ' + s.location, BOLD));
  console.log('    ' + W('Would expose: ', DIM) + s.wouldExpose + ' high+ finding(s)');
  for (const ex of (s.examples || []).slice(0, 3)) {
    console.log('      • ' + ex.family + '  ' + ex.file + ':' + ex.line + '  [' + (ex.severity || '').toUpperCase() + ']');
  }
  console.log('    ' + W('Recommend: ', YELLOW) + s.recommendation);
  console.log('');
}
" THRESHOLD="$THRESHOLD"
```

## Why this matters

A defensive control that is the SOLE protection between an attacker and ≥ 3 high-severity findings is brittle by definition. Standard SAST does not flag it — it only flags the bugs the control happens to be guarding. This command surfaces the structural risk: where would damage concentrate if ONE control fails?

Typical findings:
- A single `requireAuth` middleware guarding the whole admin surface
- A single `DOMPurify.sanitize` call wrapping every user-content render
- A single signature-verify helper feeding multiple webhook handlers

Mitigation pattern: add defense-in-depth at the route or the sink, not only at the middleware.

🛡  agentic-security · created by ClearCapabilities.Com
