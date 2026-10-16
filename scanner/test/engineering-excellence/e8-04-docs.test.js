// E8-04: the public documentation for what the programme added. Example output in it is captured from the implementation, not typed, and the "not proven" section exists.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CAPTURES, DOCS, process_ } from '../../../scripts/engineering-excellence/doc-captures.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

test('EVERY CAPTURED BLOCK EQUALS WHAT THE IMPLEMENTATION OR THE RESULT FILE PRODUCES NOW', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/engineering-excellence/doc-captures.mjs'), '--check'], { cwd: ROOT, encoding: 'utf8', timeout: 240_000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  for (const d of DOCS) { const { stale } = process_(read(d), { write: false }); assert.deepEqual(stale, [], d); }
});

test('A STALE CAPTURE IS DETECTED: a doctored block fails the check, and no block is a placeholder', () => {
  const text = read('docs/engineering-excellence/README.md');
  const { stale } = process_(text.replace('localized precision', 'localized precisionX'), { write: false }); assert.ok(stale.includes('baseline-headline'));
  for (const d of DOCS) { assert.ok(!/\nplaceholder\n/.test(read(d)), d); const ids = [...read(d).matchAll(/<!-- capture: ([\w-]+) -->/g)].map((m) => m[1]); assert.ok(ids.length >= 4, d); for (const id of ids) assert.ok(CAPTURES[id], id); }
});

test('THE DOCS HAVE A "WHAT IS NOT PROVEN" SECTION THAT NAMES THE PROGRAMME\'S OWN OPEN ITEMS, and the guide says what the verdict does not do', () => {
  const idx = read('docs/engineering-excellence/README.md'); const section = idx.slice(idx.indexOf('## What is NOT proven'));
  for (const w of ['Independent accuracy is low', 'not independent', 'not incremental', 'constant operands', 'below its 95 percent target', 'not default behaviour', 'local data', 'not authorised']) assert.ok(section.includes(w), w);
  const guide = read('docs/guides/release-assurance.md'); assert.ok(guide.includes('## What this does not do')); assert.match(guide, /never says a release is \*safe\*/); assert.ok(!/\bis safe to (ship|deploy|release)\b/i.test(guide));
});

test('EVERY LINK THE NEW PAGES AND THE INDEXES MAKE TO A LOCAL FILE RESOLVES, and the indexes link both pages', () => {
  for (const [file, base] of [['docs/engineering-excellence/README.md', 'docs/engineering-excellence'], ['docs/guides/release-assurance.md', 'docs/guides'], ['README.md', '.'], ['docs/README.md', 'docs']]) {
    for (const m of read(file).matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) { const t = m[1]; if (/^(https?:|mailto:)/.test(t)) continue; assert.ok(fs.existsSync(path.join(ROOT, base, t)), `${file} -> ${t}`); }
  }
  for (const f of ['README.md', 'docs/README.md']) { const t = read(f); assert.ok(t.includes('release-assurance.md') && t.includes('engineering-excellence/README.md'), f); }
});

test('THE NEW PUBLIC COMMAND IS DOCUMENTED AND ITS HELP IS REAL: release-view appears in the CLI help, in the guide, and the guide\'s options exist in the implementation', () => {
  const help = spawnSync(process.execPath, [path.join(ROOT, 'scanner/bin/agentic-security.js'), '--help'], { encoding: 'utf8' }).stdout; assert.match(help, /release-view <package\.json>/);
  const guide = read('docs/guides/release-assurance.md'); const bin = read('scanner/bin/agentic-security.js');
  for (const opt of ['--view', '--format', '--previous', '--public-key']) { assert.ok(guide.includes(opt), opt); assert.ok(bin.includes(opt), opt); }
  assert.match(guide, /node scripts\/engineering-excellence\/e2e-demo\.mjs/);
});
