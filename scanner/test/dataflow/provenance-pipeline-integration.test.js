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
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';
import { seedAdvisory } from '../helpers/seed-osv-cache.js';

const LSP_HELPER = fileURLToPath(new URL('../helpers/lsp-scan-file.mjs', import.meta.url));
const SCA_HELPER = fileURLToPath(new URL('../helpers/sca-provenance-scan.mjs', import.meta.url));

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

test('an LSP on-save scan does not touch the lifecycle store', async () => {
  // Same corruption class as verifyPatch, at the highest frequency in the
  // product: the LSP server re-scans on EVERY file save, against the user's
  // real project root, handing runScan a fileContents map with exactly one
  // entry. updateLifecycle marks every open stableId absent from the set it is
  // handed as `remediated`, so without a guard each save would remediate the
  // whole project and the next real scan would reintroduce it.
  //
  // Driven through the same child-process helper test/lsp-server.test.js uses,
  // because scanFile() writes real LSP frames to stdout and doing that inside
  // the test runner interferes with its reporting.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    fx.writeFile('b.js', 'const p = req.query.p;\neval(p);\n');
    fx.commit('two vulns');

    // A real, whole-project scan first — this one legitimately owns the store.
    await runScan(fx.root, { network: false });
    const store = path.join(fx.root, '.agentic-security', 'provenance', 'lifecycle.json');
    assert.ok(fs.existsSync(store), 'a real scan should have written the lifecycle store');
    const before = fs.readFileSync(store, 'utf8');
    const stateBefore = fs.readdirSync(path.join(fx.root, '.agentic-security')).sort().join(',');

    const r = spawnSync(process.execPath, [LSP_HELPER, fx.root, path.join(fx.root, 'a.js')], {
      encoding: 'utf8', timeout: 120000,
    });
    assert.equal(r.status, 0, `lsp scanFile helper failed: ${r.stderr}`);

    assert.equal(fs.readFileSync(store, 'utf8'), before,
      'an LSP on-save scan mutated the lifecycle store from a single-file finding set');
    // The wrapper is withStateWritesDisabled, so it also must not have created
    // any OTHER state artifact (dpia.md, ropa.md, threat-model.json, …) in the
    // user's tree — an editor plugin mutating the project on save is the
    // broader FR-704 problem this shares a fix with.
    assert.equal(fs.readdirSync(path.join(fx.root, '.agentic-security')).sort().join(','), stateBefore,
      'an LSP on-save scan wrote new state artifacts into the project');
  } finally {
    fx.cleanup();
  }
});

test('every supplyChain entry carries a terminal findingProvenance, transitive deps included', () => {
  // The gap the isDirect fix exposed. Once the direct-SCA filter correctly
  // excludes transitive entries, nothing annotates them — and report/index.js
  // normalizes EVERY supplyChain entry into an SCA finding, while
  // pipeline/finding-schema.js requires findingProvenance on every channel and
  // reads an absent field as "this finding escaped annotation entirely".
  //
  // HERMETIC BY CONSTRUCTION. `supplyChain` is populated by queryOSV, which hits
  // api.osv.dev and falls back to a disk cache under the user's home directory.
  // Asserting on vulnerable_dep entries without controlling that would make this
  // test pass on a machine with a warm cache and fail offline or on a cold
  // runner — unacceptable in a gated suite whose own CLAUDE.md requires that an
  // offline developer can still push. So: run in a child process with HOME
  // redirected at a throwaway dir (engine.js resolves the cache from
  // os.homedir() at import time, which is why this cannot be done in-process),
  // seed exactly the keys the scan will look up, and set
  // AGENTIC_SECURITY_OFFLINE=1 so the EPSS and KEV enrichers short-circuit too.
  // With every comp: key pre-seeded, queryOSV builds an empty query list and
  // never calls fetch at all.
  //
  // The fixture's package-lock.json nests lodash under express, so
  // _parsePackageLockJson gives lodash a 2-segment depChain -> isDirect:false,
  // yielding a real TRANSITIVE entry alongside express's direct one.
  const root = path.resolve(process.cwd(), 'test/fixtures/sca-transitive-provenance');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-osv-home-'));
  try {
    seedAdvisory(home, {
      ecosystem: 'npm', name: 'express', version: '4.18.2',
      id: 'FIXTURE-DIRECT-0001', description: 'Fixture advisory for a DIRECT dependency.',
      fixedVersions: ['4.19.0'], severity: 'high',
    });
    seedAdvisory(home, {
      ecosystem: 'npm', name: 'lodash', version: '4.17.20',
      id: 'FIXTURE-TRANSITIVE-0001', description: 'Fixture advisory for a TRANSITIVE dependency.',
      fixedVersions: ['4.17.21'], severity: 'high',
    });

    const r = spawnSync(process.execPath, [SCA_HELPER, root], {
      encoding: 'utf8', timeout: 300000,
      env: {
        ...process.env,
        HOME: home,
        AGENTIC_SECURITY_OFFLINE: '1',
        AGENTIC_SECURITY_NO_STATE: '1',   // keep the committed fixture clean
      },
    });
    assert.equal(r.status, 0, `sca provenance helper failed: ${r.stderr}`);
    const sc = JSON.parse(r.stdout);

    // Not a vacuous pass: the seeded advisories must actually have materialized.
    assert.ok(sc.length > 0, `expected supply-chain entries; helper stderr: ${r.stderr}`);
    // And PROOF the data came from the seed rather than from a warm real cache
    // or the live API: these advisory ids are fabricated. api.osv.dev would
    // return GHSA-/CVE- ids for express and lodash, never `FIXTURE-*`. If this
    // assertion ever fails while the rest passes, the test has quietly gone back
    // to depending on the network and must be fixed, not re-baselined.
    const ids = sc.map(e => e.osvId).filter(Boolean).sort();
    assert.deepEqual(ids, ['FIXTURE-DIRECT-0001', 'FIXTURE-TRANSITIVE-0001'],
      `supply-chain advisories did not come from the seeded cache: ${JSON.stringify(sc)}`);

    for (const e of sc) {
      assert.ok(e.provenance, `supplyChain entry ${e.type}:${e.name} has no findingProvenance`);
      assert.ok(TERMINAL_STATUSES.includes(e.provenance.status),
        `supplyChain entry ${e.type}:${e.name} has non-terminal status ${e.provenance.status}`);
    }

    const transitive = sc.filter(e => e.type === 'vulnerable_dep' && !e.isDirect);
    assert.ok(transitive.length > 0, `expected a TRANSITIVE vulnerable_dep; got ${JSON.stringify(sc)}`);
    for (const e of transitive) {
      assert.equal(e.provenance.status, 'not_available');
      assert.match(e.provenance.limitations.join(' '), /transitive dependency origin resolution/,
        'a transitive dep must say WHY its origin is unavailable, not just that it is');
    }
    // And the direct half must still be routed to the resolver rather than swept
    // up by the same blanket stamp — otherwise this test would pass on a wiring
    // that annotated nothing at all.
    const direct = sc.filter(e => e.type === 'vulnerable_dep' && e.isDirect);
    assert.ok(direct.length > 0, `expected a DIRECT vulnerable_dep; got ${JSON.stringify(sc)}`);
    for (const e of direct) {
      assert.ok(!/transitive dependency origin resolution/.test(e.provenance.limitations.join(' ')),
        'a DIRECT dep was stamped with the transitive limitation — it never reached the resolver');
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
