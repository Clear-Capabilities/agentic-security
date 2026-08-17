#!/usr/bin/env node
// Materialise only manifest entries not already present under cache/ — the
// existing 110 are already fetched and scored; re-running materialise-cli.mjs
// for the whole manifest after mining would re-download all of them for
// nothing. Same underlying materialiseEntry, just filtered to what's new.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { materialiseEntry, CACHE_DIR } from './materialise.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const man = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));

const isNew = (e) => !fs.existsSync(path.join(CACHE_DIR, e.id, 'pre'));
const targets = man.entries.filter(isNew);
process.stderr.write(`${targets.length} new entries to materialise (of ${man.entries.length} total)\n`);

let ok = 0, failed = 0;
for (const e of targets) {
  const scope = materialiseEntry(e);
  if (!scope) { failed++; process.stderr.write(`  ✗ ${e.id} — could not materialise; entry will be UNSCORED\n`); continue; }
  ok++;
  process.stderr.write(`  ✓ ${e.id}  ${scope.pre.dir || '(whole repo)'}  ${scope.pre.files} source file(s)\n`);
}
process.stderr.write(`\nmaterialised ${ok}, failed ${failed}, of ${targets.length} new entries\n`);
