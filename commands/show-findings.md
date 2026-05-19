---
description: Triage findings for false positives then view results. Default (--all) opens an interactive HTML report. Use --kev for weaponized CVEs, --chains for attack chains, or --threat-model [--stride|--llm] for a threat model table.
argument-hint: "[path] [--all] [--kev] [--chains [--severity critical|high|all]] [--threat-model [--stride|--llm]]"
---

Triage findings from `.agentic-security/last-scan.json` for false positives, suppress confirmed FPs, then render the requested view.

## Step 1 — Triage (runs before every view)

For each finding:
1. Read the file at the reported path and extract ±20 lines around the flagged line.
2. Evaluate true positive vs. false positive:
   - **True positive**: user-controlled input reaches the sink without validation — keep it.
   - **False positive**: validated against an allowlist/switch/enum before the sink; safe API overload; test fixture or mock; internal constant as source.
3. For confirmed false positives, add to `.agentic-security/rules.yml`:

```yaml
suppressions:
  - rule: "<vuln name>"
    files: ["<file path>"]
    reason: "<why this is a FP>"
```

Do not suppress anything uncertain. When in doubt, mark TP.

Print a brief summary: `Triage: N reviewed — X true positives, Y suppressed as false positives`

## Step 2 — View

Parse flags and dispatch:

```bash
MODE="--all"
SEVERITY="high"
THREAT_MODE="--stride"
PATH_ARG="."
for arg in "$@"; do
  case "$arg" in
    --all) MODE="--all" ;;
    --kev) MODE="--kev" ;;
    --chains) MODE="--chains" ;;
    --threat-model) MODE="--threat-model" ;;
    --stride|--llm) THREAT_MODE="$arg" ;;
    --severity) : ;;
    critical|high|all) SEVERITY="$arg" ;;
    *) PATH_ARG="$arg" ;;
  esac
done

if [ "$MODE" = "--all" ]; then

mkdir -p reports
REPORT="reports/findings-$(date +%Y%m%d-%H%M%S).html"
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format html --output "$REPORT"
ec=$?
if [ $ec -le 3 ]; then
  open "$REPORT" 2>/dev/null \
    || xdg-open "$REPORT" 2>/dev/null \
    || echo "Open $REPORT in your browser to view the report."
  exit 0
fi
exit $ec

elif [ "$MODE" = "--kev" ]; then

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan --all first.'); process.exit(0); }
const findings = (scan.findings||[]).filter(f => f.kev === true);
const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
console.log('');
console.log(W('CISA KEV findings: ' + findings.length, '1'));
console.log('');
for (const f of findings.slice(0, 50)) {
  const ransom = f.kevRansomware ? W(' [ransomware]', '91') : '';
  const cve = (f.cveAliases||[])[0] || '';
  console.log('  ' + f.severity.toUpperCase().padEnd(8) + ' ' + cve.padEnd(18) + ' ' + (f.name||f.package||'') + '@' + (f.version||'') + '  added ' + (f.kevDateAdded||'') + ransom);
}
if (!findings.length) console.log('  No KEV findings. Dependencies look clean against CISA BOD 22-01.');
console.log('');
console.log(W('KEV = actively abused in the wild. Treat these as P0.', '2'));
"

elif [ "$MODE" = "--chains" ]; then
  echo "Invoking security-chain-synthesizer subagent on findings with severity >= $SEVERITY..."
  echo "(Load .agentic-security/last-scan.json, filter to severity >= $SEVERITY, pass to security-chain-synthesizer, print Markdown output verbatim.)"
  echo ""
  echo "After chains: suggest /validate-findings <chain-name> to validate, /fix --one <id> to break at weakest link."

elif [ "$MODE" = "--threat-model" ]; then

if [ "$THREAT_MODE" = "--llm" ]; then
node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan --all first.'); process.exit(0); }
const findings = scan.findings || [];
const supplyChain = scan.supplyChain || [];
const tag = (id) => (f) => f && f.owaspLlm === id;
const LLM_TOP_10 = [
  { id: 'LLM01', name: 'Prompt Injection',              matches: (f) => tag('LLM01')(f) || /prompt.injection|llm.+injection|llm-pi|MCP.+prompt|tool description|prompt template.+isolation/i.test(f.vuln || '') },
  { id: 'LLM02', name: 'Sensitive Information Disclosure', matches: (f) => tag('LLM02')(f) || /system.prompt.+(?:leak|exfil)|hardcoded.(?:secret|key|token|password)|CWE-200|information disclosure|api.key|sensitive.+log/i.test(f.vuln || '') || f.cwe === 'CWE-798' || f.cwe === 'CWE-200' },
  { id: 'LLM03', name: 'Supply Chain',                  matches: (f) => tag('LLM03')(f) || /typosquat|dep.confusion|dependency.confusion|floating tag|trust_remote_code|from_pretrained without pinned|http.+model|pickle\.load|joblib|yaml\.(?:load|unsafe)|allow_pickle/i.test(f.vuln || '') || f.cwe === 'CWE-1357' || f.cwe === 'CWE-494' || f.cwe === 'CWE-502' },
  { id: 'LLM04', name: 'Data and Model Poisoning',      matches: (f) => tag('LLM04')(f) || /trust_remote_code|untrusted.+install|curl.+sh|http.+model|allow_pickle|pickle.+load|poisoned.+dataset|backdoor.+trigger/i.test(f.vuln || '') },
  { id: 'LLM05', name: 'Improper Output Handling',      matches: (f) => tag('LLM05')(f) || /improper output handling|llm.output|unsafe.html|unsanitized.llm|response.+innerHTML|dangerouslySetInnerHTML.+llm|llm.+sql|llm.+exec|XSS.+llm|model instructed to emit/i.test(f.vuln || '') },
  { id: 'LLM06', name: 'Excessive Agency',              matches: (f) => tag('LLM06')(f) || /excessive agency|dangerous capability|tool.+(?:shell|exec|eval)|MCP.+(?:fs.overscope|dangerous|filesystem.+root|HOME)|excessive.+perm|write-all|action.+dispatch|unrestricted.+\(\)/i.test(f.vuln || '') },
  { id: 'LLM07', name: 'System Prompt Leakage',         matches: (f) => tag('LLM07')(f) || /system prompt leakage|system.prompt.+(?:leak|disclosure|reveal|exfil|reflected)|secrets embedded in (?:system )?prompt|prompt.+log/i.test(f.vuln || '') },
  { id: 'LLM08', name: 'Vector and Embedding Weaknesses', matches: (f) => tag('LLM08')(f) || /vector.+embedding weakness|(?:embedding|vector.store|rag).+(?:poison|injection|tainted|provenance)|untrusted.rag|mutable embedding store/i.test(f.vuln || '') },
  { id: 'LLM09', name: 'Misinformation',                matches: (f) => tag('LLM09')(f) || /misinformation.+(?:prompt|fabric)|fabricated specificity/i.test(f.vuln || '') },
  { id: 'LLM10', name: 'Unbounded Consumption',         matches: (f) => tag('LLM10')(f) || /unbounded consumption|rate.limit|denial.of.service|ReDoS|resource.exhaust|unbounded|GraphQL.+depth|no token budget|missing timeout/i.test(f.vuln || '') || f.cwe === 'CWE-400' || f.cwe === 'CWE-1333' },
];
const all = [...findings, ...supplyChain.filter(s => s.type === 'vulnerable_dep')];
const buckets = LLM_TOP_10.map(cat => ({ ...cat, findings: all.filter(f => cat.matches(f)) }));
const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
const BOLD = '1', GREEN = '32', YELLOW = '33', RED = '31', DIM = '2';
console.log(''); console.log(W('OWASP LLM Top 10 (2025) — Coverage Map', BOLD));
console.log(W('Source: https://genai.owasp.org/llm-top-10/', DIM)); console.log('');
console.log('| ID    | Category                                | Findings | Status |');
console.log('|-------|-----------------------------------------|----------|--------|');
let total = 0;
for (const b of buckets) {
  const n = b.findings.length; total += n;
  const status = b.id === 'LLM09' ? W('out of scope', DIM) : n === 0 ? W('no exposure', GREEN) : n > 5 ? W(n + ' findings', RED) : W(n + ' findings', YELLOW);
  console.log('| ' + b.id + ' | ' + (b.name + ' '.repeat(40 - b.name.length)) + '| ' + (n + ' '.repeat(8 - String(n).length)) + ' | ' + status + ' |');
}
console.log(''); console.log(W('Top per category (up to 3 each):', BOLD)); console.log('');
for (const b of buckets) {
  if (!b.findings.length) continue;
  console.log(W(b.id + '  ' + b.name, BOLD) + '  (' + b.findings.length + ')');
  for (const f of b.findings.slice(0, 3)) {
    const sev = (f.severity || 'medium').toUpperCase();
    const file = f.file ? f.file + ':' + (f.line || '?') : (f.name + '@' + f.version);
    console.log('  [' + sev + ']  ' + (f.vuln || f.advisory || '').slice(0, 80) + '   ' + W(file, DIM));
  }
  if (b.findings.length > 3) console.log('  ' + W('... and ' + (b.findings.length - 3) + ' more', DIM));
  console.log('');
}
console.log(W('Summary: ' + total + ' total findings mapped to LLM Top 10.', BOLD));
"
else
node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan --all first.'); process.exit(0); }
const findings = scan.findings || [];
const STRIDE = [
  { id: 'S', name: 'Spoofing' }, { id: 'T', name: 'Tampering' }, { id: 'R', name: 'Repudiation' },
  { id: 'I', name: 'Information Disclosure' }, { id: 'D', name: 'Denial of Service' }, { id: 'E', name: 'Elevation of Privilege' },
];
const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
const BOLD = '1', DIM = '2', YELLOW = '33', GREEN = '32';
// v3: prefer the new f.strideCategory (lowercase camelCase from threat-model.js),
// fall back to legacy f.stride for older scans.
const STRIDE_KEY = { S: 'spoofing', T: 'tampering', R: 'repudiation', I: 'informationDisclosure', D: 'denialOfService', E: 'elevationOfPrivilege' };
const buckets = STRIDE.map(cat => ({
  ...cat,
  findings: findings.filter(f =>
    f.strideCategory === STRIDE_KEY[cat.id] ||
    f.stride === cat.id || f.stride === cat.name
  ),
}));
console.log(''); console.log(W('STRIDE Coverage Table', BOLD)); console.log('');
console.log('| Category               | Count | Top finding |');
console.log('|------------------------|-------|-------------|');
for (const b of buckets) {
  const n = b.findings.length;
  const top = b.findings[0] ? (b.findings[0].title || b.findings[0].vuln || '').slice(0, 50) : W('no findings', DIM);
  const count = n === 0 ? W('0', GREEN) : W(String(n), YELLOW);
  console.log('| ' + (b.name + ' '.repeat(22 - b.name.length)) + ' | ' + count + ' '.repeat(5 - String(n).length) + ' | ' + top + ' |');
}
console.log('');
const zero = buckets.filter(b => b.findings.length === 0);
if (zero.length) { console.log(W('No findings (under-covered or absent):', BOLD)); for (const b of zero) console.log('  ' + b.name); console.log(''); }
const top2 = buckets.filter(b => b.findings.length);
if (top2.length) { console.log(W('Highest-impact per category:', BOLD)); for (const b of top2) { const f = b.findings[0]; console.log('  [' + b.name + ']  ' + (f.severity||'').toUpperCase() + '  ' + (f.title||f.vuln||'')); } }
"
fi

fi
```

## Views

**`/show-findings` or `/show-findings --all`** — Triage FPs then write a self-contained HTML report to `reports/findings-<timestamp>.html` and open it. Includes severity charts, filterable findings list, per-finding code evidence, and fix templates.

**`/show-findings --kev`** — Triage then list only CVEs on the CISA KEV (Known Abused CVEs) catalog. These are actively weaponized in the wild — treat as P0. `kevRansomware: true` means CISA has linked the CVE to ransomware campaigns.

**`/show-findings --chains [--severity critical|high|all]`** — Triage then invoke the `security-chain-synthesizer` subagent to find multi-finding attack chains (e.g., IDOR + missing auth = account takeover). Prints Markdown chain report verbatim. After: suggest `/validate-findings <chain-name>` to validate and `/fix --one <id>` to break at the weakest link.

**`/show-findings --threat-model`** _(default: --stride)_ — Triage then render a STRIDE coverage table from the last scan. Add `--llm` for the OWASP LLM Top 10 (2025) coverage map instead.

## How to respond to the user

After any view, tell the user how many findings were suppressed as FPs. For the default HTML view, give the report path and platform open command if it didn't auto-open. Don't list individual findings inline.

🛡  agentic-security · created by ClearCapabilities.Com
