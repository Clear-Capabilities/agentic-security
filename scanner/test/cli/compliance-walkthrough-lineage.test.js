// Final whole-branch review of M4 sub-project 6c found finding R2: the
// same lineage-graph starvation bug the review's B2/Task-2 defects
// concerned for `attest --obligations` also existed, undisclosed, in
// `agentic-security compliance --walkthrough` — shipped since sub-project
// 6b. `evaluateFramework(scanRoot, fw, scan)` reads `scan.lineageGraph`,
// but that field is never present in last-scan.json (the real graph gets
// its own signed artifact, .agentic-security/lineage-graph.json), so
// every graph: mapping has always read "unknown" through this command
// regardless of whether AGENTIC_SECURITY_LINEAGE_DEEP=1 was ever set.
// Fixed alongside --obligations's own identical fix; this file is the
// regression guard for the --walkthrough half.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// Same real, proven PHI-to-model-provider shape as
// test/cli/attest-obligations.test.js and
// bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi.
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

test('compliance --walkthrough --format json: a real deep scan produces a non-vacuous graph: obligationMapping (not the always-unknown pre-fix answer)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const wtR = spawnSync(process.execPath, [CLI, 'compliance', '--report', 'hipaa-security-rule', '--format', 'json'], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(wtR.status, 0, `compliance --report failed: ${wtR.stderr}\n${wtR.stdout}`);

  const evaluation = JSON.parse(wtR.stdout);
  const control = evaluation.find((e) => e.control?.id === '§164.312(e)');
  assert.ok(control, 'expected §164.312(e) in the real HIPAA evaluation');
  const mapping = (control.obligationMappings ?? []).find((m) => m.requirementId === '§164.312(e)');
  assert.ok(mapping, 'expected a real graph: obligationMapping on this control');

  // The load-bearing regression assertion: before the fix, this state was
  // ALWAYS 'unknown' with an empty graphId/graphDigest, regardless of
  // AGENTIC_SECURITY_LINEAGE_DEEP. A real (even if honestly-unassessed)
  // graph must now be threaded through — proven by a real, non-placeholder
  // graphId/graphDigest on the mapping.
  assert.notEqual(mapping.graphId, '(no graph)', 'the real lineage graph must be loaded, not the no-graph placeholder');
  assert.notEqual(mapping.graphDigest, '(no graph)');
  assert.match(mapping.graphDigest, /^[0-9a-f]{64}$/);
});
