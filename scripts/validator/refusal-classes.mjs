#!/usr/bin/env node
// Vuln classes the validator can't reliably prove with a sub-minute regression
// test. For these, the validator returns INDETERMINATE_BY_CLASS rather than
// guess. Lists the classes (by CWE or vuln-substring), with one-line reasons.
//
// Usage:
//   refusal-classes.js list                       → prints the full table
//   refusal-classes.js check <cwe> <vuln-string>  → exit 0 if validator can
//                                                   prove it, exit 11 if it
//                                                   should refuse; reason on
//                                                   stdout.

const REFUSALS = [
  { cwe: 'CWE-208', match: /Timing Oracle|timing.attack/i,
    reason: 'Timing oracles require statistical signal across many requests; a single test cannot reliably prove the bug.' },
  { cwe: 'CWE-367', match: /TOCTOU|Race Condition.*Filesystem/i,
    reason: 'Filesystem TOCTOU races require precise interleaving across processes — a single test rarely reproduces.' },
  { cwe: 'CWE-1333', match: /ReDoS|Regex ReDoS|Catastrophic Backtracking/i,
    reason: 'ReDoS proof depends on input length and engine version. A test that hangs in CI is not a useful proof.' },
  { cwe: 'CWE-330', match: /Weak Randomness|Cryptographically Weak PRNG|Math\.random/i,
    reason: 'Weak RNG is only abusable in security-sensitive contexts; static analysis is more reliable than a test.' },
  { cwe: 'CWE-798', match: /Hardcoded Secret|High-Entropy Credential|Password in URL/i,
    reason: 'Secret leakage proof requires checking external breach databases; the validator does not query them.' },
  { cwe: 'CWE-693', match: /Verify x-powered-by|Cookie Set Without|header.hardening/i,
    reason: 'Header-hardening findings are best practices, not abusable bugs; the validator does not generate PoCs for them.' },
  { cwe: 'CWE-501', match: /Trust Boundary|User Data Stored in Session/i,
    reason: 'Trust-boundary findings depend on downstream usage; static analysis identifies the boundary, not the abuse.' },
];

function check(cwe, vuln) {
  for (const r of REFUSALS) {
    if (r.cwe === cwe || (vuln && r.match.test(vuln))) {
      process.stdout.write(r.reason + '\n');
      process.exit(11);
    }
  }
  process.exit(0);
}

function list() {
  for (const r of REFUSALS) {
    process.stdout.write(`${r.cwe.padEnd(10)}  ${r.match.source.slice(0, 50).padEnd(52)}  ${r.reason}\n`);
  }
}

const [, , cmd, cwe, ...rest] = process.argv;
if (cmd === 'list') list();
else if (cmd === 'check') check(cwe, rest.join(' '));
else { console.error('Usage: refusal-classes.js list | check <cwe> <vuln-string>'); process.exit(2); }
