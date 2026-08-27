// Finding Provenance — pipeline integration (Task 15).
//
// Every other provenance test drives the coordinator directly. This one drives
// the REAL `runScan` -> `runFullScan` pipeline, because "the coordinator works" and "a scan
// produces provenance" are two different claims and only the second one is what
// FR-PROV-001..013 actually promise. It is deliberately the slow test in this
// suite: it runs every detector, the whole annotation pipeline, and then the
// provenance pass over the result.
//
// The two cases are the two halves of the terminal-status guarantee: inside a
// real git repository every finding gets *some* terminal status, and outside one
// every finding gets `not_available` rather than an absent field.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';

const TERMINAL_STATUSES = ['complete', 'partial', 'not_available', 'uncommitted', 'budget_exhausted', 'error'];

test('runScan attaches findingProvenance to every SAST finding in a real git repo', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    fx.commit('introduce sqli', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });

    const { scan } = await runScan(fx.root, { network: false });
    assert.ok(Array.isArray(scan.findings));
    assert.ok(scan.findings.length > 0, 'fixture should produce at least one finding');
    for (const f of scan.findings) {
      assert.ok(f.findingProvenance, `finding ${f.id} missing findingProvenance`);
      assert.ok(
        TERMINAL_STATUSES.includes(f.findingProvenance.status),
        `finding ${f.id} has non-terminal provenance status ${f.findingProvenance.status}`,
      );
    }
  } finally {
    fx.cleanup();
  }
});

test('runScan on a non-git directory still returns findings with status not_available', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-nogit-integration-'));
  try {
    fs.writeFileSync(path.join(tmp, 'server.js'), 'db.query("SELECT * FROM t WHERE id = " + x);\n');
    const { scan } = await runScan(tmp, { network: false });
    assert.ok(scan.findings.length > 0, 'fixture should produce at least one finding');
    for (const f of scan.findings) {
      assert.ok(f.findingProvenance, `finding ${f.id} missing findingProvenance`);
      assert.equal(f.findingProvenance.status, 'not_available');
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('AGENTIC_SECURITY_NO_PROVENANCE=1 yields a terminal status and writes NOTHING to disk', async () => {
  // Two claims in one, because the opt-out has two halves and only one of them
  // is obvious. (1) The opt-out must not become an "absent field" path — a
  // consumer reading `.findingProvenance.status` keeps working with the feature
  // off. (2) "Disabled" must mean the feature writes nothing: the lifecycle
  // store is a real write into the scanned tree, and a disabled feature that
  // still creates `.agentic-security/provenance/` is not disabled. The first
  // wiring gated only the annotator calls on `disabled`, so updateLifecycle ran
  // regardless.
  const fx = createGitFixture();
  const prev = process.env.AGENTIC_SECURITY_NO_PROVENANCE;
  process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
  try {
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    fx.commit('introduce sqli');
    const { scan } = await runScan(fx.root, { network: false });
    assert.ok(scan.findings.length > 0, 'fixture should produce at least one finding');
    for (const f of scan.findings) {
      assert.ok(f.findingProvenance, `finding ${f.id} missing findingProvenance`);
      assert.equal(f.findingProvenance.status, 'not_available');
    }
    assert.equal(
      fs.existsSync(path.join(fx.root, '.agentic-security', 'provenance', 'lifecycle.json')),
      false,
      'lifecycle store was written despite AGENTIC_SECURITY_NO_PROVENANCE=1',
    );
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_NO_PROVENANCE;
    else process.env.AGENTIC_SECURITY_NO_PROVENANCE = prev;
    fx.cleanup();
  }
});

test('verifyPatch does not touch the lifecycle store', async () => {
  // The sharpest form of the "internal runFullScan callers must opt out" rule.
  // updateLifecycle marks every open stableId ABSENT from the finding set it is
  // handed as `remediated`. verifyPatch deliberately re-scans only the patched
  // file(s), so if it reached updateLifecycle it would mass-mark the rest of the
  // project remediated — and every /fix, apply_fix, and autopilot iteration runs
  // one. Asserting on the store rather than on a call count keeps this honest
  // whichever way a future change routes the opt-out.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    fx.writeFile('b.js', 'const p = req.query.p;\neval(p);\n');
    fx.commit('two vulns');

    // A real scan first: this one legitimately populates the lifecycle store.
    await runScan(fx.root, { network: false });
    const store = path.join(fx.root, '.agentic-security', 'provenance', 'lifecycle.json');
    assert.ok(fs.existsSync(store), 'a real scan should have written the lifecycle store');
    const before = fs.readFileSync(store, 'utf8');

    // Now verify a patch to a.js only. b.js's finding must not be remediated.
    const { verifyPatch } = await import('../../src/posture/fix-verify.js');
    await verifyPatch({
      scanRoot: fx.root,
      originalFindingStableId: 'does-not-matter',
      files: { 'a.js': 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = ?", [input]);\n' },
    });

    assert.equal(fs.readFileSync(store, 'utf8'), before,
      'verifyPatch mutated the lifecycle store from a partial file set');
  } finally {
    fx.cleanup();
  }
});
