#!/usr/bin/env node
// Baseline capture CLI (CORE-001). Read-only against application source.
//
//   node scripts/baseline-capture.mjs                      print a human summary
//   node scripts/baseline-capture.mjs --json               print the manifest
//   node scripts/baseline-capture.mjs --out <file>         also write the manifest
//   node scripts/baseline-capture.mjs --compare <file>     compare a recorded manifest with this checkout
//   node scripts/baseline-capture.mjs --root <dir>         capture another checkout
//
// Exit codes: 0 captured (and, with --compare, nothing invalidated); 1 the capture
// found problems (a cited path or symbol is missing) or --compare found invalidated
// capabilities; 2 usage error or a refused output path.
//
// The manifest records HEAD, dirty paths and tool versions, so it differs between
// machines and is generated on demand rather than committed.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureBaseline, evaluateBaseline, validateBaseline, assertSafeOutput } from '../scanner/src/posture/assurance/baseline.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const o = { root: path.resolve(HERE, '..'), json: false, out: null, compare: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--out') o.out = argv[++i];
    else if (a === '--compare') o.compare = argv[++i];
    else if (a === '--root') o.root = path.resolve(argv[++i] || '');
    else return { error: `unknown argument '${a}'` };
  }
  if ((argv.includes('--out') && !o.out) || (argv.includes('--compare') && !o.compare)) return { error: 'missing value' };
  return o;
}

const o = parseArgs(process.argv.slice(2));
if (o.error) { console.error(`baseline-capture: ${o.error}`); process.exit(2); }

const manifest = captureBaseline({ root: o.root });

if (o.out) {
  const safe = assertSafeOutput(o.root, o.out);
  if (!safe.ok) { console.error(`baseline-capture: refusing to write ${o.out}: ${safe.reason}`); process.exit(2); }
  fs.mkdirSync(path.dirname(path.resolve(o.out)), { recursive: true });
  fs.writeFileSync(o.out, `${JSON.stringify(manifest, null, 2)}\n`);
}

let exit = manifest.problems.length ? 1 : 0;
let comparison = null;
if (o.compare) {
  let recorded;
  try { recorded = JSON.parse(fs.readFileSync(o.compare, 'utf8')); } catch (e) { console.error(`baseline-capture: cannot read ${o.compare}: ${e.message}`); process.exit(2); }
  const v = validateBaseline(recorded);
  if (!v.ok) { console.error(`baseline-capture: ${o.compare} is not a valid baseline: ${v.errors.join('; ')}`); process.exit(2); }
  comparison = evaluateBaseline(recorded, manifest);
  if (comparison.invalidated.length) exit = 1;
}

if (o.json) {
  process.stdout.write(`${JSON.stringify(comparison ? { manifest, comparison } : manifest, null, 2)}\n`);
} else {
  const f = (x) => (x.status === 'known' ? (typeof x.value === 'string' ? x.value : JSON.stringify(x.value)) : `unknown (${x.reason})`);
  const counts = {};
  for (const c of manifest.capabilities) counts[c.status] = (counts[c.status] || 0) + 1;
  console.log(`baseline ${manifest.baselineId}`);
  console.log(`  head        ${f(manifest.repository.head)} on ${f(manifest.repository.branch)}`);
  console.log(`  dirty paths ${manifest.repository.dirtyPaths.status === 'known' ? manifest.repository.dirtyPaths.value.length : f(manifest.repository.dirtyPaths)}`);
  console.log(`  source      ${manifest.digests.source.status === 'known' ? `${manifest.digests.source.value.digest} (${manifest.digests.source.value.fileCount} files)` : f(manifest.digests.source)}`);
  console.log(`  bundle      ${manifest.digests.bundle.status === 'known' ? manifest.digests.bundle.value.digest : f(manifest.digests.bundle)}`);
  for (const [k, v] of Object.entries(manifest.versions)) console.log(`  ${k.padEnd(11)} ${f(v)}`);
  console.log(`  capabilities ${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', ')}`);
  console.log(`  mappings    ${manifest.recommendationMappings.length} recommendations`);
  if (comparison) {
    console.log(`compare: ${comparison.valid.length} valid, ${comparison.invalidated.length} invalidated${comparison.invalidated.length ? ` (${comparison.invalidated.join(', ')})` : ''}`);
    const u = comparison.userChanges;
    if (u.comparable) console.log(`  user changes: ${u.retained.length} retained, ${u.introduced.length} introduced, ${u.changedSince.length} changed since, ${u.resolved.length} resolved`);
  }
  for (const p of manifest.problems) console.log(`PROBLEM ${p}`);
  if (o.out) console.log(`wrote ${o.out}`);
}
// A natural exit, not process.exit(): after this much work (several module loads, git, hashing) an explicit exit can deadlock inside the Node
// runtime's platform shutdown when the machine is busy. Measured on this script under ten-way parallel load: 23 hangs in 600 runs with
// process.exit(), 0 in 600 with the exit code set and the process left to end on its own.
process.exitCode = exit;
