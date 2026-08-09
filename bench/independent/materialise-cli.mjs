#!/usr/bin/env node
// Driver for materialise.mjs — rebuild every entry's pre/post trees with context.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { materialiseEntry } from './materialise.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const man = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));

let ok = 0, failed = 0, exceeded = 0;
const t0 = Date.now();
for (const e of man.entries) {
  const scope = materialiseEntry(e);
  if (!scope) { failed++; process.stderr.write(`  ✗ ${e.id} — could not materialise; entry will be UNSCORED\n`); continue; }
  ok++;
  if (scope.pre.exceededCap) exceeded++;
  process.stderr.write(`  ✓ ${e.id}  ${scope.pre.dir || '(whole repo)'}  ${scope.pre.files} source file(s)\n`);
}
process.stderr.write(`\nmaterialised ${ok}, failed ${failed}, of ${man.entries.length} — ${Math.round((Date.now() - t0) / 1000)}s\n`);
if (exceeded) {
  process.stderr.write(`${exceeded} entr(y|ies) EXCEEDED the file cap: the changed file sits at the repository\n` +
    'root, so there is no narrower directory and the scope is the whole repository.\n');
}
