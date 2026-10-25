#!/usr/bin/env node
// Runs the compatibility test every GA capability names in docs/capabilities.yaml (`contractTest`), and the same for any
// Preview capability that names one. The registry is the list: a contract test nothing runs cannot count as evidence, and a
// registry that names no tests runs none and fails. Used by the `contract-conformance` release check.
//
//   node scripts/check-ga-contracts.mjs [--list]
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { loadRegistry } from './check-positioning-docs.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function contractTests(reg) {
  return [...new Set(reg.capabilities.filter(c => c.contractTest && (c.maturity === 'GA' || c.maturity === 'Preview')).map(c => c.contractTest))].sort();
}

function main() {
  const tests = contractTests(loadRegistry(REPO));
  if (!tests.length) { console.error('check-ga-contracts: the registry names no contract tests'); return 1; }
  if (process.argv.includes('--list')) { console.log(tests.join('\n')); return 0; }
  const r = spawnSync(process.execPath, ['--test', ...tests.map(t => path.join(REPO, t))], { cwd: path.join(REPO, 'scanner'), stdio: 'inherit' });
  if (r.status !== 0) { console.error(`check-ga-contracts: a contract test failed (exit ${r.status}) among ${tests.length} file(s)`); return 1; }
  console.log(`check-ga-contracts: ${tests.length} contract test file(s) passed`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main());
