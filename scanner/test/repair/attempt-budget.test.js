// The per-finding fix attempt budget counts patch applications, not files (found while proving multi-file repair, M2-04).
//
// Before: every file write was one attempt, so a three-file patch was refused on its own third file at the default budget of two.
// After: files written under one `attemptGroup` (the apply batch) are one attempt; separate applications still count one each, and a
// third separate attempt is still refused.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { applyFix, FixAttemptBudgetExceededError } from '../../src/posture/fix-history.js';

function project() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'attempt-budget-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
  for (const f of ['a.js', 'b.js', 'c.js']) fs.writeFileSync(path.join(root, f), `// ${f}\n`);
  return root;
}
const write = (root, file, group, finding = 'F1') => applyFix({ scanRoot: root, file, originalContent: fs.readFileSync(path.join(root, file), 'utf8'), newContent: `// patched ${group}\n`, findingId: finding, stableId: `s-${finding}`, attemptGroup: group });

test('a three-file patch is one attempt: its third file is not refused', async () => {
  const root = project();
  for (const f of ['a.js', 'b.js', 'c.js']) await write(root, f, 'batch-1');
  assert.equal(fs.readFileSync(path.join(root, 'c.js'), 'utf8'), '// patched batch-1\n');
});

test('separate applications still count one each, and the budget still refuses the third', async () => {
  const root = project();
  await write(root, 'a.js', 'batch-1');
  await write(root, 'a.js', 'batch-2');
  await assert.rejects(write(root, 'a.js', 'batch-3'), FixAttemptBudgetExceededError);
});

test('entries written without a group count one each, as before', async () => {
  const root = project();
  await write(root, 'a.js', null);
  await write(root, 'b.js', null);
  await assert.rejects(write(root, 'c.js', null), FixAttemptBudgetExceededError);
});
