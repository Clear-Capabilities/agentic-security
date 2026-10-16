#!/usr/bin/env node
// Independent offline verifier for a signed release assurance package (E7-03).
//
//   node scripts/verify-release-package.mjs <package.json> --public-key <public.pem> [--require kind,kind]
//
// Exit 0: every check passed. Exit 1: at least one failed (all failures are listed). Exit 2: unusable input.
//
// The checks live in scanner/src/posture/assurance/release-package-verify.js, which imports only Node built-ins and nothing from the code that builds a
// package: a defect in the producer cannot make the verifier agree with it. See that file for what is checked and under which code.
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyReleasePackage, MINIMUM_KINDS } from '../scanner/src/posture/assurance/release-package-verify.js';

export { verifyReleasePackage, MINIMUM_KINDS };

function main(argv) {
  const file = argv.find((a) => !a.startsWith('--') && argv[argv.indexOf(a) - 1] !== '--public-key' && argv[argv.indexOf(a) - 1] !== '--require');
  const opt = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : null; };
  const keyFile = opt('--public-key');
  if (!file || !keyFile) { console.error('usage: verify-release-package <package.json> --public-key <public.pem> [--require kind,kind]'); return 2; }
  let pkg; let key;
  try { pkg = JSON.parse(fs.readFileSync(file, 'utf8')); key = fs.readFileSync(keyFile, 'utf8'); } catch (e) { console.error(`cannot read input: ${e.message}`); return 2; }
  const r = verifyReleasePackage(pkg, key, { require: (opt('--require') || '').split(',').filter(Boolean) });
  if (r.ok) { console.log(`release package verified: scan ${r.completeness}, ${pkg.evidence.length} records, ${pkg.findings.length} findings`); return 0; }
  for (const e of r.errors) console.error(`${e.code}: ${e.message}`);
  console.error(`release package REJECTED (${r.errors.length} problem${r.errors.length === 1 ? '' : 's'})`);
  return 1;
}
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exit(main(process.argv.slice(2)));
