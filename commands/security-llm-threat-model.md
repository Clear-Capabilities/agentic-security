---
description: Map your existing findings to the OWASP LLM Top 10 (2025) — Prompt Injection, Sensitive Info Disclosure, Supply Chain, Data/Model Poisoning, Improper Output Handling, Excessive Agency, System Prompt Leakage, Vector & Embedding Weaknesses, Misinformation, Unbounded Consumption.
---

Render an OWASP LLM Top 10 coverage table from `.agentic-security/last-scan.json`.

```bash
node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /security-scan-all first.'); process.exit(0); }

const findings = scan.findings || [];
const supplyChain = scan.supplyChain || [];
const components = scan.components || [];

// OWASP LLM Top 10 (2025) — each entry maps existing finding signals to a category.
// Detector hits that explicitly tag `owaspLlm: 'LLM0X'` (from llm-owasp.js) match first.
const tag = (id) => (f) => f && f.owaspLlm === id;
const LLM_TOP_10 = [
  {
    id: 'LLM01', name: 'Prompt Injection',
    matches: (f) => tag('LLM01')(f) || /prompt.injection|llm.+injection|llm-pi|MCP.+prompt|tool description|prompt template.+isolation/i.test(f.vuln || ''),
  },
  {
    id: 'LLM02', name: 'Sensitive Information Disclosure',
    matches: (f) => tag('LLM02')(f) || /system.prompt.+(?:leak|exfil)|hardcoded.(?:secret|key|token|password)|CWE-200|information disclosure|api.key|sensitive.+log/i.test(f.vuln || '') || f.cwe === 'CWE-798' || f.cwe === 'CWE-200',
  },
  {
    id: 'LLM03', name: 'Supply Chain',
    matches: (f) => tag('LLM03')(f) || /typosquat|dep.confusion|dependency.confusion|floating tag|trust_remote_code|from_pretrained without pinned|http.+model|pickle\.load|joblib|yaml\.(?:load|unsafe)|allow_pickle/i.test(f.vuln || '') || f.cwe === 'CWE-1357' || f.cwe === 'CWE-494' || f.cwe === 'CWE-502',
  },
  {
    id: 'LLM04', name: 'Data and Model Poisoning',
    matches: (f) => tag('LLM04')(f) || /trust_remote_code|untrusted.+install|curl.+sh|http.+model|allow_pickle|pickle.+load|poisoned.+dataset|backdoor.+trigger/i.test(f.vuln || ''),
  },
  {
    id: 'LLM05', name: 'Improper Output Handling',
    matches: (f) => tag('LLM05')(f) || /improper output handling|llm.output|unsafe.html|unsanitized.llm|response.+innerHTML|dangerouslySetInnerHTML.+llm|llm.+sql|llm.+exec|XSS.+llm|model instructed to emit/i.test(f.vuln || ''),
  },
  {
    id: 'LLM06', name: 'Excessive Agency',
    matches: (f) => tag('LLM06')(f) || /excessive agency|dangerous capability|tool.+(?:shell|exec|eval)|MCP.+(?:fs.overscope|dangerous|filesystem.+root|HOME)|excessive.+perm|write-all|action.+dispatch|unrestricted.+\(\)/i.test(f.vuln || ''),
  },
  {
    id: 'LLM07', name: 'System Prompt Leakage',
    matches: (f) => tag('LLM07')(f) || /system prompt leakage|system.prompt.+(?:leak|disclosure|reveal|exfil|reflected)|secrets embedded in (?:system )?prompt|prompt.+log/i.test(f.vuln || ''),
  },
  {
    id: 'LLM08', name: 'Vector and Embedding Weaknesses',
    matches: (f) => tag('LLM08')(f) || /vector.+embedding weakness|(?:embedding|vector.store|rag).+(?:poison|injection|tainted|provenance)|untrusted.rag|mutable embedding store/i.test(f.vuln || ''),
  },
  {
    id: 'LLM09', name: 'Misinformation',
    matches: (f) => tag('LLM09')(f) || /misinformation.+(?:prompt|fabric)|fabricated specificity/i.test(f.vuln || ''),
  },
  {
    id: 'LLM10', name: 'Unbounded Consumption',
    matches: (f) => tag('LLM10')(f) || /unbounded consumption|rate.limit|denial.of.service|ReDoS|resource.exhaust|unbounded|GraphQL.+depth|no token budget|missing timeout/i.test(f.vuln || '') || f.cwe === 'CWE-400' || f.cwe === 'CWE-1333',
  },
];

const all = [...findings, ...supplyChain.filter(s => s.type === 'vulnerable_dep')];
const buckets = LLM_TOP_10.map(cat => ({
  ...cat,
  findings: all.filter(f => cat.matches(f)),
}));

const W = (s, code) => process.stdout.isTTY ? '\\x1b[' + code + 'm' + s + '\\x1b[0m' : s;
const BOLD = '1', GREEN = '32', YELLOW = '33', RED = '31', DIM = '2';

console.log('');
console.log(W('OWASP LLM Top 10 (2025) — Coverage Map', BOLD));
console.log(W('Source: https://genai.owasp.org/llm-top-10/', DIM));
console.log('');
console.log('| ID    | Category                              | Findings | Status |');
console.log('|-------|---------------------------------------|----------|--------|');
let totalFindings = 0;
for (const b of buckets) {
  const n = b.findings.length;
  totalFindings += n;
  const status = b.id === 'LLM09'
    ? W('out of scope', DIM)
    : n === 0
    ? W('no exposure', GREEN)
    : n > 5
    ? W(n + ' findings', RED)
    : W(n + ' findings', YELLOW);
  console.log('| ' + b.id + ' | ' + (b.name + ' '.repeat(38 - b.name.length)) + '| ' + (n + ' '.repeat(8 - String(n).length)) + ' | ' + status + ' |');
}
console.log('');
console.log(W('Top per category (up to 3 each):', BOLD));
console.log('');
for (const b of buckets) {
  if (!b.findings.length) continue;
  console.log(W(b.id + '  ' + b.name, BOLD) + '  (' + b.findings.length + ')');
  for (const f of b.findings.slice(0, 3)) {
    const sev = (f.severity || 'medium').toUpperCase();
    const file = f.file ? f.file + ':' + (f.line || '?') : (f.name + '@' + f.version);
    console.log('  [' + sev + ']  ' + (f.vuln || f.advisory || '').slice(0, 80) + '   ' + W(file, DIM));
  }
  if (b.findings.length > 3) console.log('  ' + W('  ... and ' + (b.findings.length - 3) + ' more', DIM));
  console.log('');
}

console.log(W('Summary: ' + totalFindings + ' total findings mapped to LLM Top 10 categories.', BOLD));
"
```

Print the output verbatim.

## Why this exists

The OWASP LLM Top 10 is the industry-standard taxonomy for LLM-app security risks, just like the OWASP Top 10 has been for web apps for two decades. This command projects your existing scanner findings (already covered by `/security-scan-all`) into the LLM Top 10 categories so you can:

- Answer "are we covered against LLM01 Prompt Injection?" in one glance
- Hand a security reviewer a one-page risk-coverage table mapped to a public framework
- Identify gaps in your own coverage (LLM08 Vector & Embedding Weaknesses is most often where teams have nothing)

LLM09 (Misinformation) is intentionally marked "out of scope" — it's a runtime / human-review problem, not a static-analysis one.
