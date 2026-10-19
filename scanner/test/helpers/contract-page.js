// Shared by the contract tests that hold an implementation's output to the field tables on a reference page.
//
// A table is the markdown table that follows a bold heading line such as `**Report**`; its first column holds the field names in
// backticks. `sameFields` compares in both directions: a field the output has that the page does not list fails, and so does a field
// the page lists that the output lacks.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

export const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

export function readPage(rel) { return fs.readFileSync(path.join(REPO, rel), 'utf8'); }

/** Field names (first backticked cell) of the table under the bold heading that starts with `heading`. */
export function fieldsUnder(page, heading) {
  const lines = page.split('\n');
  const at = lines.findIndex(l => l.startsWith(`**${heading}`));
  assert.ok(at >= 0, `the page has no "${heading}" table`);
  const names = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].startsWith('**') || lines[i].startsWith('#')) break;
    const m = /^\| `([^`]+)` \|/.exec(lines[i]);
    if (m) names.push(m[1]);
  }
  assert.ok(names.length, `the "${heading}" table lists no fields`);
  return names;
}

export function sameFields(actual, documented, label, optional = []) {
  const opt = new Set(optional);
  const have = Object.keys(actual).filter(k => !opt.has(k)).sort();
  const want = documented.filter(k => !opt.has(k)).sort();
  assert.deepEqual(have, want, `${label}: the output and the page disagree`);
}
