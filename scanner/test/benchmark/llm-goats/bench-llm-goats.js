#!/usr/bin/env node
// OWASP LLM Top 10 — coverage benchmark against AIGoat + LLMGoat.
//
// Usage:
//   node scanner/test/benchmark/llm-goats/bench-llm-goats.js
//   node scanner/test/benchmark/llm-goats/bench-llm-goats.js --json
//
// Each target is cloned (once) into `.cache/<name>/`. We invoke the bundled
// CLI (`dist/agentic-security.mjs scan`) on each target and tally how many
// findings map to each OWASP LLM Top 10 category. The result is a simple
// coverage matrix that should not silently regress.

import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../..');                 // scanner/
const CLI = resolve(REPO_ROOT, 'dist/agentic-security.mjs');
const CACHE = join(__dirname, '.cache');
const ARGS = new Set(process.argv.slice(2));
const AS_JSON = ARGS.has('--json');

const TARGETS = [
  { name: 'AIGoat',  url: 'https://github.com/AISecurityConsortium/AIGoat.git' },
  { name: 'LLMGoat', url: 'https://github.com/LiteshGhute/LLMGoat.git' },
];

// Mapping rules. Prefer the explicit `owaspLlm` field; fall back to vuln
// text and CWE so OSV / SCA findings (which don't carry owaspLlm) still
// bucket correctly.
const tag = (id) => (f) => f && f.owaspLlm === id;
const RULES = {
  LLM01: (f) => tag('LLM01')(f) || /prompt injection|llm.+injection|llm-pi/i.test(f.vuln || ''),
  LLM02: (f) => tag('LLM02')(f) || /system prompt.+(?:leak|exfil)|hardcoded.(?:secret|key|token|password)|information disclosure|secrets embedded/i.test(f.vuln || '') || f.cwe === 'CWE-798' || f.cwe === 'CWE-200',
  LLM03: (f) => tag('LLM03')(f) || /typosquat|dep.confusion|dependency confusion|floating tag|trust_remote_code|pickle.load|allow_pickle/i.test(f.vuln || '') || f.cwe === 'CWE-1357' || f.cwe === 'CWE-494' || f.cwe === 'CWE-502',
  LLM04: (f) => tag('LLM04')(f) || /trust_remote_code|untrusted.+install|allow_pickle|pickle.+load|poisoned dataset|backdoor trigger/i.test(f.vuln || ''),
  LLM05: (f) => tag('LLM05')(f) || /improper output handling|llm output|unsafe html|unsanitized llm|instructed to emit/i.test(f.vuln || ''),
  LLM06: (f) => tag('LLM06')(f) || /excessive agency|dangerous capability|tool.+(?:shell|exec|eval)|MCP.+(?:fs.overscope|dangerous)|action.+dispatch|unrestricted/i.test(f.vuln || ''),
  LLM07: (f) => tag('LLM07')(f) || /system prompt leakage|secrets embedded in (?:system )?prompt/i.test(f.vuln || ''),
  LLM08: (f) => tag('LLM08')(f) || /vector.+embedding weakness|untrusted.rag|mutable embedding store|ingests untrusted/i.test(f.vuln || ''),
  LLM09: (f) => tag('LLM09')(f) || /misinformation/i.test(f.vuln || ''),
  LLM10: (f) => tag('LLM10')(f) || /unbounded consumption|rate.limit|denial.of.service|ReDoS|resource exhaust|unbounded|no token budget|missing timeout/i.test(f.vuln || '') || f.cwe === 'CWE-400' || f.cwe === 'CWE-1333',
};

function ensureClones() {
  if (!existsSync(CACHE)) mkdirSync(CACHE, { recursive: true });
  for (const t of TARGETS) {
    const dir = join(CACHE, t.name);
    if (existsSync(dir)) continue;
    console.error(`[clone] ${t.name} <- ${t.url}`);
    execSync(`git clone --depth 1 ${t.url} ${dir}`, { stdio: 'inherit' });
  }
}

function runScan(target) {
  const dir = join(CACHE, target);
  const out = join(CACHE, `${target}.json`);
  const args = ['scan', '--profile', 'pro', '--format', 'json', '--no-network', '--firehose', '--output', out];
  const r = spawnSync('node', [CLI, ...args], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  if (r.status !== 0 && r.status !== 1 && r.status !== 2 && r.status !== 3) {
    console.error(`[scan ${target}] non-finding exit ${r.status}: ${r.stderr?.toString().slice(0, 400) || ''}`);
  }
  return JSON.parse(readFileSync(out, 'utf8'));
}

function bucket(scan) {
  const all = [
    ...(scan.findings || []),
    ...((scan.supplyChain || []).filter((s) => s.type === 'vulnerable_dep')),
  ];
  const counts = {};
  for (const [k, fn] of Object.entries(RULES)) counts[k] = all.filter(fn).length;
  return { total: all.length, counts };
}

function main() {
  ensureClones();
  const report = {};
  for (const t of TARGETS) {
    const scan = runScan(t.name);
    report[t.name] = bucket(scan);
  }
  if (AS_JSON) {
    process.stdout.write(JSON.stringify(report, null, 2));
    return;
  }
  console.log('');
  console.log('OWASP LLM Top 10 — coverage on goat benchmarks');
  console.log('================================================');
  for (const [name, r] of Object.entries(report)) {
    console.log('');
    console.log(`${name} (${r.total} total findings)`);
    console.log('-'.repeat(50));
    for (const k of Object.keys(RULES)) {
      const n = r.counts[k];
      const status = n === 0 ? '  no hits  ' : `   ${String(n).padStart(3)}     `;
      console.log(`  ${k} ${status}`);
    }
  }
  console.log('');
  console.log('Source: LLMGoat = https://github.com/LiteshGhute/LLMGoat');
  console.log('Source: AIGoat  = https://github.com/AISecurityConsortium/AIGoat');
}

main();
