// X-508: adversarial enforcement tests.
//
// Runs the disposable malicious-repository corpus (adversarial/corpus.js) against
// the enforcement backend this host can prove (the macOS userspace backend,
// `host-proved`, not advertised) and records what it covered.
//
//   - Execution cases need a probed backend and SKIP LOUDLY elsewhere ("SKIPPED,
//     NOT PASSED"); a skip is a recorded gap and keeps enforced mode unreleasable.
//   - Policy-level cases (tool confusion, delegation, receipts, refusals before
//     execution) run on every platform.
//   - No Linux outcome is asserted anywhere. Passing proves these attempts were
//     stopped here; it is not evidence of a universally secure sandbox.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ATTACK_CLASSES, KNOWN_LIMITS, buildAttackCoverage, enforcedModeReleaseGate } from '../../src/capabilities/attack-coverage.js';
import { CASES, CASE_BY_ID, newFixture, findLeaks, leakedInRepo } from './adversarial/corpus.js';
import { SKIP, BACKEND, CAN_RUN, ON_LINUX, bind, run, tmp } from './helpers.js';

const results = [];
// The level this host's backend reaches: the Linux namespace backend is the advertised one and runs `enforced` when its probes pass; the macOS
// backend is `host-proved` only. A test below checks that a real run says the same, so this constant cannot drift from what the runner reports.
const LEVEL = ON_LINUX ? 'enforced' : CAN_RUN ? 'host-proved' : 'none';

describe('[X-508.AC01] the corpus covers prompt injection, build scripts, secret reads, exfiltration, tool confusion, descendants and verifier tampering', () => {
  test('every named attack class has at least one mandatory case, and ids are unique', () => {
    const named = ['prompt-injection', 'malicious-build-script', 'secret-read', 'network-exfiltration', 'tool-confusion', 'descendant-escape', 'verifier-tampering'];
    for (const cls of named) assert.ok(ATTACK_CLASSES.includes(cls), cls);
    for (const cls of ATTACK_CLASSES) assert.ok(CASES.some((c) => c.class === cls), `no case for ${cls}`);
    const ids = CASES.map((c) => c.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const c of CASES) { assert.ok(ATTACK_CLASSES.includes(c.class), c.id); assert.equal(typeof c.run, 'function'); }
  });

  test('the fixture is a real malicious repository: hostile files exist and every canary is planted outside the repository', async () => {
    const fx = newFixture();
    await CASE_BY_ID['PI-01 injected instruction makes an allowed reader cat a secret outside the roots'].run(fx).catch(() => {});
    assert.match(fs.readFileSync(path.join(fx.repo, 'README.md'), 'utf8'), /ignore previous instructions/);
    for (const f of [fx.secretFile, fx.sshKey, fx.labelFile, fx.keyFile, fx.receiptFile]) {
      assert.ok(!f.startsWith(fx.repo + path.sep), `${f} is outside the repository`);
      assert.ok(fs.statSync(f).size > 0);
    }
    assert.ok(fs.readFileSync(fx.secretFile, 'utf8').includes(fx.canaries.outside));
    assert.ok(fs.readFileSync(fx.sshKey, 'utf8').includes(fx.canaries.ssh));
    assert.ok(fx.inRepoSecret.startsWith(fx.repo + path.sep), 'the one in-repository secret is readable by design, to test exfiltration of what the worker CAN read');
  });

  test('the leak detector sees a canary in text, base64 and files, and ignores clean output', () => {
    const fx = newFixture();
    assert.deepEqual(findLeaks(fx, { texts: ['nothing here'] }), []);
    assert.deepEqual(findLeaks(fx, { texts: [`x ${fx.canaries.outside} y`] }), ['outside']);
    assert.deepEqual(findLeaks(fx, { texts: [Buffer.from(fx.canaries.ssh).toString('base64')] }), ['ssh']);
    fs.writeFileSync(path.join(fx.repo, 'loot'), `k=${fx.canaries.key}`);
    assert.deepEqual(findLeaks(fx, { dirs: [fx.repo] }), ['key']);
    assert.equal(leakedInRepo(fx, [encodeURIComponent(fx.canaries.inRepo)]), true);
    assert.equal(leakedInRepo(fx, ['clean']), false);
  });

  test('a deliberately leaky manifest IS detected: the corpus is not vacuous', { skip: SKIP }, async () => {
    const fx = newFixture();
    const bound = bind({ filesystem: { read: [fx.repo, fx.secrets] }, commands: [{ executable: '/bin/cat', args: { mode: 'any' } }] });
    const r = await run(bound, { executable: '/bin/cat', args: [fx.secretFile] }, { home: fx.home, labelDirs: [fx.labels], evidenceDirs: [fx.receipts] });
    assert.equal(r.executed, true);
    assert.deepEqual(findLeaks(fx, { texts: [r] }), ['outside'], 'the secret IS returned once its directory is declared readable');
    const sealed = bind({ filesystem: { read: [fx.repo] }, commands: [{ executable: '/bin/cat', args: { mode: 'any' } }] });
    const r2 = await run(sealed, { executable: '/bin/cat', args: [fx.secretFile] }, { home: fx.home, labelDirs: [fx.labels], evidenceDirs: [fx.receipts] });
    assert.deepEqual(findLeaks(fx, { texts: [r2] }), [], 'and is not once it is not');
  });
});

describe('[X-508.AC02] the enforced supported backend blocks every mandatory escape fixture without leaking a canary; failures block enforced-mode release', () => {
  for (const c of CASES) {
    const skip = c.execution ? SKIP : false;
    if (skip) results.push({ id: c.id, class: c.class, mandatory: c.mandatory !== false, execution: true, outcome: 'skipped', note: String(skip).slice(0, 120) });
    test(c.id, { skip }, async () => {
      const fx = newFixture();
      let r;
      try { r = await c.run(fx); } catch (e) {
        results.push({ id: c.id, class: c.class, mandatory: c.mandatory !== false, execution: c.execution, outcome: 'error', note: e.message });
        throw e;
      }
      const outcome = !r.ran ? 'error' : r.leaks.length ? 'leaked' : (r.observedKnownLimit && c.mandatory === false) ? 'known-limit' : 'blocked';
      results.push({ id: c.id, class: c.class, mandatory: c.mandatory !== false, execution: c.execution, outcome, ...(r.notes && r.notes.length ? { note: r.notes.join('; ') } : {}) });
      assert.equal(r.ran, true, `the attempt did not run, so nothing was proved: ${(r.notes || []).join('; ')}`);
      assert.deepEqual(r.leaks, [], `escape or leak: ${r.leaks.join(', ')}`);
    });
  }

  test('the level recorded for this host is the level a real run reports', { skip: SKIP }, async () => {
    const dir = tmp('adv-level-');
    const bound = bind({ filesystem: { write: [dir] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const r = await run(bound, { executable: '/bin/echo', args: ['level'] });
    assert.equal(r.status, 'ok', JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    assert.equal(r.level, LEVEL);
    assert.equal(r.enforced, LEVEL === 'enforced');
  });

  test('a mandatory leak or error blocks the enforced-mode release; a clean run does not', () => {
    const base = [{ id: 'a', class: 'secret-read', outcome: 'blocked' }];
    const all = (outcomeFor = {}) => ATTACK_CLASSES.map((cls) => ({ id: `case-${cls}`, class: cls, mandatory: true, execution: true, outcome: outcomeFor[cls] ?? 'blocked' }));
    const clean = enforcedModeReleaseGate(buildAttackCoverage(all(), { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(clean.block, false);
    assert.equal(clean.enforcedModeReleasable, true, 'only an enforced-level run with every mandatory case executed can release');
    const leaked = enforcedModeReleaseGate(buildAttackCoverage(all({ 'secret-read': 'leaked' }), { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(leaked.block, true); assert.equal(leaked.enforcedModeReleasable, false);
    assert.match(leaked.reasons.join(), /leaked/);
    const errored = enforcedModeReleaseGate(buildAttackCoverage(all({ 'descendant-escape': 'error' }), { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(errored.block, true);
    const missingClass = enforcedModeReleaseGate(buildAttackCoverage(base, { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(missingClass.block, true);
    assert.match(missingClass.reasons.join(), /no fixture covers/);
    const skipped = enforcedModeReleaseGate(buildAttackCoverage(all({ 'verifier-tampering': 'skipped' }), { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(skipped.block, false, 'a skip is not a failure');
    assert.equal(skipped.enforcedModeReleasable, false, 'but an unexecuted mandatory case never releases enforced mode');
    const host = enforcedModeReleaseGate(buildAttackCoverage(all(), { platform: 'darwin', backend: 'userspace', level: 'host-proved' }));
    assert.equal(host.block, false);
    assert.equal(host.enforcedModeReleasable, false, 'a host-proved backend is not an advertised enforced backend');
    assert.match(host.notes.join(), /not 'enforced'/);
    const limit = enforcedModeReleaseGate(buildAttackCoverage([...all(), { id: 'DE-x', class: 'descendant-escape', mandatory: false, outcome: 'known-limit' }], { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(limit.block, false, 'a documented limit with confinement holding is reported, not hidden and not a block');
    assert.match(limit.notes.join(), /documented limit\(s\) reproduced.*DE-x/);
    assert.equal(buildAttackCoverage([{ id: 'DE-x', class: 'descendant-escape', outcome: 'known-limit' }], {}).totals.knownLimit, 1);
    const unknown = enforcedModeReleaseGate(buildAttackCoverage([...all(), { id: 'x', class: 'made-up', outcome: 'blocked' }], { platform: 'synthetic', backend: 'namespace', level: 'enforced' }));
    assert.equal(unknown.block, true);
  });
});

describe('[X-508.AC03] tests record attack coverage and known limits and do not claim a universally secure sandbox', () => {
  test('the coverage record lists every class, every case outcome and the known limits, and states Linux as unverified', (t) => {
    assert.equal(results.length, CASES.length, 'every case recorded an outcome (run the whole file, not a filtered subset)');
    const coverage = buildAttackCoverage(results, { platform: process.platform, backend: BACKEND, level: LEVEL });
    assert.equal(coverage.schema, 'agentic-security/attack-coverage');
    assert.deepEqual(coverage.uncoveredClasses, []);
    assert.equal(coverage.totals.cases, CASES.length);
    assert.equal(coverage.totals.leaked, 0, 'no mandatory fixture leaked a canary');
    assert.equal(coverage.totals.error, 0);
    assert.equal(coverage.totals.blocked + coverage.totals.skipped + coverage.totals.knownLimit, CASES.length);
    for (const cls of ATTACK_CLASSES) assert.ok(coverage.classes[cls].cases > 0, cls);
    assert.deepEqual(coverage.knownLimits, KNOWN_LIMITS);
    assert.equal(coverage.platforms.linux, 'unverified');
    assert.ok(coverage.cases.every((c) => typeof c.id === 'string' && ['blocked', 'skipped', 'known-limit'].includes(c.outcome)));
    // honesty: only an advertised backend, with every mandatory execution case actually executed, could release enforced mode
    const gate = enforcedModeReleaseGate(coverage);
    assert.equal(gate.block, false, `the release gate found failures: ${gate.reasons.join('; ')}`);
    assert.equal(gate.enforcedModeReleasable, LEVEL === 'enforced' && coverage.totals.skipped === 0,
      'macOS (host-proved) and a skipped corpus never release enforced mode; the Linux namespace backend does only when every mandatory case ran');
    const out = path.join(tmp('adv-cov-'), 'attack-coverage.json');
    fs.writeFileSync(out, JSON.stringify(coverage, null, 2));
    assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).totals.cases, CASES.length);
    t.diagnostic(`attack coverage on ${process.platform}/${BACKEND} (${LEVEL}): ${coverage.totals.blocked} blocked, ${coverage.totals.knownLimit} documented-limit reproductions, ${coverage.totals.skipped} skipped (not passed), ${coverage.totals.leaked} leaked, ${coverage.totals.error} error; Linux unverified`);
  });

  test('no claim of universal security appears in the record, and the limits name what the corpus does not show', () => {
    const coverage = buildAttackCoverage(results, { platform: process.platform, backend: BACKEND, level: LEVEL });
    const text = JSON.stringify(coverage);
    assert.match(coverage.claim, /not evidence of a universally secure sandbox/);
    assert.ok(!/universally secure(?! sandbox)/i.test(text.replace(coverage.claim, '')), 'the only mention is the disclaimer');
    assert.ok(!/\bproves?\b.*\bsecure\b/i.test(text));
    const limits = KNOWN_LIMITS.join('\n');
    assert.match(limits, /not a proof/);
    assert.match(limits, /Linux is unverified/);
    assert.match(limits, /double-forks/);
    assert.match(limits, /opaque tunnel/);
    assert.match(limits, /Process-count caps are not asserted/);
  });

  test('a skipped execution case is recorded as a skip, never as a pass', () => {
    const cov = buildAttackCoverage([{ id: 'x', class: 'secret-read', outcome: 'skipped', execution: true }], { platform: 'linux', backend: 'namespace', level: 'none' });
    assert.equal(cov.totals.blocked, 0);
    assert.equal(cov.totals.skipped, 1);
    assert.equal(cov.platforms.linux, 'unverified');
  });
});
