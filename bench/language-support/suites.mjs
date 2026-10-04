// The test suites that back each non-corpus capability row, and a runner that records their real results.
//
//   node bench/language-support/suites.mjs [--out results/suites.json]
//
// A suite that fails because a required tool is absent (a compiler, nix) is recorded as BLOCKED with the reason, not skipped and not
// passed. The runner records counts and the failing test names; it never edits or filters a suite.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './lib.mjs';

const SCANNER = path.join(REPO, 'scanner');

/** Which external tools exist on this host. A capability that NEEDS a tool is blocked when it is absent, whatever its tests say. */
export function probeTools() {
  const has = (bin) => { const r = spawnSync(process.platform === 'win32' ? 'where' : 'which', [bin], { encoding: 'utf8' }); return r.status === 0; };
  return { ghc: has('ghc'), cabal: has('cabal'), stack: has('stack'), nix: has('nix'), nixos: fs.existsSync('/etc/NIXOS'), platform: process.platform, arch: process.arch };
}

/** capability -> test files (relative to scanner/), per ecosystem. */
export const CAPABILITY_SUITES = {
  haskell: {
    auth: ['test/haskell/haskell-web-auth.test.js'],
    sca: ['test/haskell/haskell-sca.test.js', 'test/haskell/haskell-manifests.test.js', 'test/haskell/haskell-resolved-graph.test.js'],
    bom: ['test/language/language-bom.test.js', 'test/language/language-aibom.test.js'],
    fix: ['test/haskell/haskell-remediation.test.js', 'test/language/language-proof-remediation.test.js'],
    integration: ['test/language/language-integrations.test.js', 'test/language/language-report-formats.test.js'],
  },
  nix: {
    sca: ['test/nix/nix-input-inventory.test.js', 'test/nix/nix-resolved-closure.test.js', 'test/nix/nix-sca-patches.test.js'],
    bom: ['test/language/language-bom.test.js', 'test/language/language-aibom.test.js'],
    fix: ['test/nix/nix-remediation.test.js', 'test/language/language-proof-remediation.test.js'],
    integration: ['test/language/language-integrations.test.js', 'test/language/language-report-formats.test.js'],
    'nix-eval': ['test/nix/nix-eval-isolation.test.js'],
    'nixos-host': [],
  },
};

const BLOCKED = /requires (?:GHC|a compiler|nix|a NixOS host|the nix binary)|not installed|unavailable compiler/i;

// This process disables state writes for its own scans (lib.mjs); a test suite is a different program and needs the real state behavior.
const childEnv = () => { const e = { ...process.env }; delete e.AGENTIC_SECURITY_NO_STATE; return e; };

export function runSuite(file) {
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=600000`, file], { cwd: SCANNER, encoding: 'utf8', timeout: 900000, env: childEnv() });
  const out = `${r.stdout || ''}\n${r.stderr || ''}`;
  const n = (k) => { const m = new RegExp(`^# ${k} (\\d+)`, 'm').exec(out); return m ? Number(m[1]) : 0; };
  const failing = [...out.matchAll(/^not ok \d+ - (.+)$/gm)].map((m) => m[1].trim());
  const blocked = failing.filter((t) => BLOCKED.test(t));
  return { name: path.basename(file), file, tests: n('tests'), pass: n('pass'), fail: n('fail'), skipped: n('skipped'), cancelled: n('cancelled'), failing, ...(blocked.length && blocked.length === failing.length ? { blocked: blocked.join('; ') } : {}) };
}

export function runAll(only = null) {
  const results = {};
  const files = new Set(Object.values(CAPABILITY_SUITES).flatMap((c) => Object.values(c).flat()));
  for (const f of [...files].sort()) {
    const name = path.basename(f);
    if (only && !only.includes(name)) continue;
    results[name] = runSuite(f);
  }
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const i = process.argv.indexOf('--out');
  const results = runAll();
  const body = `${JSON.stringify({ schema: 'agentic-security/language-support-suites@1', ranAt: new Date().toISOString().slice(0, 10), node: process.version, tools: probeTools(), capabilitySuites: CAPABILITY_SUITES, results }, null, 2)}\n`;
  if (i > 0) fs.writeFileSync(process.argv[i + 1], body); else process.stdout.write(body);
}
