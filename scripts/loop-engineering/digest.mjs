#!/usr/bin/env node
// Digest of the files matching a requirement's watch globs, computed with the SAME code the controller uses, so a hosted runner can
// report the digest of the bytes it tested and the controller can compare it with its own.
//
//   node scripts/loop-engineering/digest.mjs '["docs/**","README.md"]'     # prints {"digest": "...", "fileCount": N}
//
// Reads the repository this script lives in; never writes anything.
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TreeIndex } from './lib/tree.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
let globs;
try { globs = JSON.parse(process.argv[2] || ''); } catch { globs = null; }
if (!Array.isArray(globs) || !globs.length || globs.some((g) => typeof g !== 'string')) { console.error('usage: digest.mjs \'["glob", ...]\''); process.exit(2); }
const t = new TreeIndex(ROOT).build();
console.log(JSON.stringify(t.digestFor(globs)));
