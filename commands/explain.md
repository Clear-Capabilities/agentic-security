---
description: Explain a specific finding in plain English — what it means, how an attacker would exploit it, the worst case, and how to fix it. Designed for non-technical builders.
argument-hint: "<finding-id-or-CWE-or-vuln-name>"
---

Explain a security finding in plain English. The user can pass:

- A finding id (`struct:src/api.js:42:SQL_Injection`)
- A CWE number (`CWE-89` or just `89`)
- A vuln name fragment (`SQL Injection`)

```bash
node -e "
const fs = require('fs');
const path = require('path');

const arg = (process.argv[1] || '').trim();
if (!arg) {
  console.error('Usage: /explain <finding-id | CWE-89 | vuln-name>');
  console.error('  Example: /explain CWE-89');
  console.error('  Example: /explain SQL Injection');
  process.exit(1);
}

const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.dirname(path.dirname(__filename));
const explainerPath = path.join(pluginRoot, 'data', 'cwe-explainer.json');
let explainer = {};
try { explainer = JSON.parse(fs.readFileSync(explainerPath, 'utf8')); } catch (e) {
  console.error('Could not load CWE explainer table from ' + explainerPath);
  process.exit(1);
}

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

// Resolve the input to a finding (or just a CWE)
let finding = null;
let cweKey = null;
const argLower = arg.toLowerCase();

// Try as CWE first
const cweMatch = arg.match(/CWE[-_]?(\d+)/i) || arg.match(/^(\d+)\$/);
if (cweMatch) cweKey = 'CWE-' + cweMatch[1];

// If we have a scan, try to match a finding by id, vuln name, or CWE
if (scan && Array.isArray(scan.findings)) {
  finding =
    scan.findings.find(f => f.id === arg) ||
    scan.findings.find(f => (f.id || '').includes(arg)) ||
    (cweKey && scan.findings.find(f => f.cwe === cweKey)) ||
    scan.findings.find(f => (f.vuln || '').toLowerCase().includes(argLower));
  if (finding && !cweKey) cweKey = finding.cwe;
}

const explainEntry = cweKey ? explainer[cweKey] : null;

// Render
const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
const BOLD = '1', RED = '31', YELLOW = '33', CYAN = '36', DIM = '2';

console.log('');
if (finding) {
  console.log(W('━━━ ' + (finding.vuln || 'Finding') + ' ━━━', BOLD));
  console.log(\`File:     \${finding.file}:\${finding.line}\`);
  console.log(\`Severity: \${W(finding.severity.toUpperCase(), finding.severity === 'critical' ? RED : finding.severity === 'high' ? YELLOW : CYAN)}\`);
  if (finding.cwe) console.log(\`CWE:      \${finding.cwe}\`);
  if (finding.toxicity != null) console.log(\`Toxicity: \${finding.toxicity}/100 (\${finding.toxicityLabel || ''})\`);
  if (finding.kev) console.log(\`KEV:      \${W('Yes — actively exploited in the wild', RED)}\`);
  console.log('');
} else if (cweKey) {
  console.log(W('━━━ ' + cweKey + (explainEntry ? ': ' + explainEntry.name : '') + ' ━━━', BOLD));
  console.log(W('(Generic explanation — no specific finding matched.)', DIM));
  console.log('');
} else {
  console.error(\`No finding or CWE matched '\${arg}'.\`);
  console.error('Run /scan --all first, then /explain <finding-id>.');
  process.exit(1);
}

if (explainEntry) {
  console.log(W('What this means', BOLD));
  console.log('  ' + explainEntry.risk);
  console.log('');
  console.log(W('How an attacker exploits it', BOLD));
  for (const line of explainEntry.attackerStory.match(/.{1,90}(\\s|\$)/g) || [explainEntry.attackerStory]) console.log('  ' + line.trim());
  console.log('');
  console.log(W('Worst case if not fixed', BOLD));
  for (const line of explainEntry.worstCase.match(/.{1,90}(\\s|\$)/g) || [explainEntry.worstCase]) console.log('  ' + line.trim());
  console.log('');
  console.log(W('How to fix it', BOLD));
  for (const line of explainEntry.fix.match(/.{1,90}(\\s|\$)/g) || [explainEntry.fix]) console.log('  ' + line.trim());
  console.log('');
} else {
  // Fallback to the finding's own fix description if we don't have a plain-English entry
  if (finding && finding.fix) {
    console.log(W('Fix recommendation (from scanner)', BOLD));
    const text = typeof finding.fix === 'string' ? finding.fix : (finding.fix.description || JSON.stringify(finding.fix));
    for (const line of text.match(/.{1,90}(\\s|\$)/g) || [text]) console.log('  ' + line.trim());
    console.log('');
  } else {
    console.log(W('No plain-English explainer for ' + (cweKey || arg) + ' yet.', DIM));
    console.log(W('The top 30 CWEs cover ~85% of findings; this one falls outside that set.', DIM));
    console.log('');
  }
}

if (finding) {
  console.log(W('What to do now', BOLD));
  console.log('  Apply the fix:    /agentic-security:security-fix ' + finding.id);
  console.log('  See in context:   open ' + finding.file);
  if (finding.severity === 'critical' || finding.severity === 'high') {
    console.log('  Generate PoC:     /agentic-security:exploit-poc ' + finding.id);
  }
  console.log('');
}
" -- "$1"
```

Print the output verbatim. The user wants the explanation as a single self-contained card.
