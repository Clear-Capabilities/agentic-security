import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { annotateGitProvenance } from '../../src/posture/provenance/coordinator.js';
import { computeStableId } from '../../src/posture/stable-id.js';
import { validateFindingsProvenance } from '../../src/posture/provenance/validate.js';

test('Scenario G: uncommitted finding gets status uncommitted, author unknown, no email', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'safe();\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('a.js', 'eval(x); // uncommitted\n');
    const finding = { file: 'a.js', line: 1, ruleId: 'eval-use' };
    finding.stableId = computeStableId(finding);

    await annotateGitProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard' });

    assert.equal(finding.findingProvenance.status, 'uncommitted');
    assert.equal(finding.findingProvenance.findingOrigin, null);
    const { valid } = validateFindingsProvenance([finding]);
    assert.equal(valid, true);
  } finally {
    fx.cleanup();
  }
});

test('Scenario K: not a git repo still emits a finding, status not_available, never throws', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-nogit-'));
  const finding = { file: 'a.js', line: 1, ruleId: 'x', stableId: 'sid1' };
  await annotateGitProvenance([finding], { scanRoot: tmp, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
  assert.equal(finding.findingProvenance.status, 'not_available');
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('every finding always gets a terminal findingProvenance, even on internal error', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // Deliberately malformed finding (no ruleId/sink/stableId at all) to force
    // the not_available path rather than throwing.
    const finding = { file: 'a.js', line: 1 };
    await annotateGitProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    assert.ok(finding.findingProvenance);
    assert.ok(['not_available', 'error', 'partial', 'complete'].includes(finding.findingProvenance.status));
  } finally {
    fx.cleanup();
  }
});

test('a throw inside per-finding resolution degrades to status error, never propagates', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // Simulate a downstream module throwing mid-resolution: reading .stableId
    // blows up, which is exactly the shape of any git/replay/cache failure
    // that escapes its own try/catch.
    const boom = { file: 'a.js', line: 1 };
    Object.defineProperty(boom, 'stableId', { get() { throw new Error('simulated downstream failure'); } });
    const ok = { file: 'a.js', line: 1, stableId: 'sid-ok' };

    await annotateGitProvenance([boom, ok], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });

    assert.equal(boom.findingProvenance.status, 'error');
    assert.match(boom.findingProvenance.limitations[0], /simulated downstream failure/);
    // The sibling finding is unaffected — one bad finding does not poison the batch.
    assert.ok(ok.findingProvenance);
    assert.notEqual(ok.findingProvenance.status, 'error');
    assert.equal(validateFindingsProvenance([boom, ok]).valid, true);
  } finally {
    fx.cleanup();
  }
});

test('the bounded-concurrency scheduler drains a list longer than MAX_CONCURRENCY', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // 9 > MAX_CONCURRENCY (4): the refill path in the scheduler has to run
    // twice and still settle. A hang or an early resolve both fail here.
    const findings = Array.from({ length: 9 }, (_, i) => ({ file: 'a.js', line: 1, stableId: `sid-${i}` }));
    await annotateGitProvenance(findings, { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    for (const f of findings) assert.ok(f.findingProvenance, 'every finding annotated');
    assert.equal(validateFindingsProvenance(findings).valid, true);
  } finally {
    fx.cleanup();
  }
});

test('--no-provenance (ctx.disabled) short-circuits to not_available for every finding', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n'); fx.commit('c1');
    const findings = [{ file: 'a.js', line: 1, stableId: 's1' }, { file: 'a.js', line: 1, stableId: 's2' }];
    await annotateGitProvenance(findings, { scanRoot: fx.root, disabled: true });
    for (const f of findings) {
      assert.equal(f.findingProvenance.status, 'not_available');
      assert.match(f.findingProvenance.limitations[0], /disabled/);
    }
  } finally {
    fx.cleanup();
  }
});
