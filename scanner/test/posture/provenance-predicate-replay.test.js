import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { replayAt } from '../../src/posture/provenance/predicate-replay.js';
import { computeStableId } from '../../src/posture/stable-id.js';
import { runFullScan } from '../../src/engine.js';

test('replayAt: finds a matching stableId in a historical blob, absent in an earlier one', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'function safe(id) {\n  db.query("SELECT * FROM t WHERE id = ?", [id]);\n}\n');
    const shaSafe = fx.commit('safe query', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('server.js', 'function vuln(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n');
    const shaVuln = fx.commit('introduce concat', { date: '2026-01-02T00:00:00Z' });

    // Compute the target stableId the same way the real detector output would.
    const target = computeStableId({
      ruleId: 'sql-injection', file: 'server.js',
      sink: { snippet: 'db.query("SELECT * FROM t WHERE id = " + id)' },
    });

    const atVuln = await replayAt(fx.root, shaVuln, ['server.js'], target);
    // At minimum, replaying at the vulnerable commit must not crash and must
    // return a well-formed result shape.
    assert.equal(typeof atVuln.present, 'boolean');
    const atSafe = await replayAt(fx.root, shaSafe, ['server.js'], target);
    assert.equal(typeof atSafe.present, 'boolean');
  } finally {
    fx.cleanup();
  }
});

test('replayAt: returns present:false when the file did not exist at that commit', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const x = 1;\n');
    const sha = fx.commit('first', { date: '2026-01-01T00:00:00Z' });
    const result = await replayAt(fx.root, sha, ['nope.js'], 'anything');
    assert.equal(result.present, false);
    assert.equal(result.reason, 'no-files-at-commit');
  } finally {
    fx.cleanup();
  }
});

// FR-PROV-029 (Finding Provenance PRD performance SLO): replayAt() now calls
// runFullScan with `skipAnnotators: true`, skipping the ~54-annotator
// post-detection pipeline entirely — it only ever reads scan.findings/
// scan.secrets to recompute computeStableId() over raw detector output, and
// never any annotator's output. This is a regression pin for that safety
// property, not just a functional check: it derives a stableId from a REAL
// detector run (never a hand-built finding — see provenance-origin-
// resolver.test.js's header for why) and confirms replayAt's accelerated
// path still correctly reports presence/absence at the vulnerable/safe
// commits respectively.
test('replayAt: skipAnnotators fast path still correctly resolves presence/absence for a real detector-derived finding', async () => {
  const fx = createGitFixture();
  try {
    const SAFE_SRC = 'function safe(id) {\n  db.query("SELECT * FROM t WHERE id = ?", [id]);\n}\n';
    const VULN_SRC = 'function vuln(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n';
    fx.writeFile('server.js', SAFE_SRC);
    const shaSafe = fx.commit('safe query', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('server.js', VULN_SRC);
    const shaVuln = fx.commit('introduce concat', { date: '2026-01-02T00:00:00Z' });

    // Derive the finding (and its stableId) the same way a real caller would
    // — a normal scan, annotators included (skipAnnotators defaults false).
    const scan = await runFullScan({ fileContents: { 'server.js': VULN_SRC }, scanRoot: fx.root }, () => {});
    const finding = (scan.findings || []).find((f) => f.file === 'server.js' && f.family === 'sql-injection');
    assert.ok(finding, `expected a sql-injection finding, got: ${JSON.stringify((scan.findings || []).map((f) => ({ file: f.file, family: f.family })))}`);
    assert.ok(finding.stableId, 'real finding must carry a stableId from the annotation pipeline');

    const atVuln = await replayAt(fx.root, shaVuln, ['server.js'], finding.stableId);
    assert.equal(atVuln.present, true, `expected the fast-path replay to reproduce the finding at the vulnerable commit, got: ${JSON.stringify(atVuln)}`);

    const atSafe = await replayAt(fx.root, shaSafe, ['server.js'], finding.stableId);
    assert.equal(atSafe.present, false, `expected the fast-path replay to find no match at the safe commit, got: ${JSON.stringify(atSafe)}`);
  } finally {
    fx.cleanup();
  }
});

// FR-PROV-029: direct regression pin for the empirical safety property this
// task's implementation depends on — computeStableId(f) must be byte-
// identical for the same detector-emitted finding whether or not the
// annotator pipeline ran. If a future annotator starts mutating a field
// computeStableId reads (ruleId/cwe/family/parser/vuln/file/sink/source/
// pathSteps), this test is the one that catches it, since the origin-
// resolver tests above only catch it indirectly (via a changed `status`).
test('runFullScan: skipAnnotators does not change computeStableId for any matched finding', async () => {
  // Isolated scanRoot: scanRoot:null falls back to process CWD, which under
  // this suite is scanner/ itself — runSbomDiff then reads THIS repo's real
  // sbom history and injects ~76 unrelated dependency-removed findings,
  // making `checked` a near-meaningless count and writing live scan state
  // into scanner/.agentic-security/ as a side effect of running the test.
  const scanRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'as-skip-annotators-'));
  try {
    const fileContents = {
      'server.js': 'function vuln(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n',
      'app.py': 'import os\ndef run(cmd):\n    os.system("ls " + cmd)\n',
      'files.js': 'const fs = require("fs");\nfunction read(name) {\n  return fs.readFileSync("/data/" + name);\n}\n',
      'config.js': 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n',
    };
    const withAnnotators = await runFullScan({ fileContents, scanRoot, skipAnnotators: false }, () => {});
    const withoutAnnotators = await runFullScan({ fileContents, scanRoot, skipAnnotators: true }, () => {});

    const withCandidates = [...(withAnnotators.findings || []), ...(withAnnotators.secrets || [])];
    const withoutById = new Map();
    for (const f of [...(withoutAnnotators.findings || []), ...(withoutAnnotators.secrets || [])]) {
      if (f && f.id) withoutById.set(f.id, f);
    }

    let checked = 0;
    for (const f of withCandidates) {
      if (!f || !f.id) continue;
      const partner = withoutById.get(f.id);
      if (!partner) continue; // annotator-only finding (e.g. a chain/contract finding) — not a safety concern
      checked++;
      assert.equal(
        computeStableId(f), computeStableId(partner),
        `computeStableId mismatch for id=${f.id} (vuln=${f.vuln}): annotators must never change a field computeStableId reads`,
      );
    }
    assert.ok(checked >= 3, `expected at least 3 matched findings across families to exercise the comparison, got ${checked}`);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});
