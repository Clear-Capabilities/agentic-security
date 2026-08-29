// FR-PROV-017 — missing-control-resolver.js wired to a real, reachable
// finding type (rate-limit.js) for the first time. Every other test of
// resolveMissingControl (provenance-missing-control-resolver.test.js) drives
// it directly with a hand-built predicate; this file proves the whole path
// end-to-end through a REAL scan: rate-limit.js sets
// `missingControlCandidate: true` at finding-construction time,
// coordinator.js branches on that marker (not a string-match on
// finding.id/finding.vuln — see coordinator.js's own comment on why), and
// resolveMissingControl gets rate-limit.js's own `hasRateLimit` as its
// predicate so the historical-blob check and the live detector never drift
// apart.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';
import { hasRateLimit } from '../../src/sast/rate-limit.js';

test('hasRateLimit is exported and behaves identically to the former internal predicate', () => {
  assert.equal(hasRateLimit("const rl = require('express-rate-limit');"), true);
  assert.equal(hasRateLimit("router.post('/login', rateLimit(), h);"), true);
  assert.equal(hasRateLimit("router.post('/login', h);"), false);
});

test('missing-control wiring: a genuine rate-limit REMOVAL resolves complete, attributed to the removal commit, method missing-control-regression', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  fx.writeFile(
    'routes/auth.js',
    "const router = require('express').Router();\nrouter.post('/login', rateLimit(), (req, res) => { res.send('ok'); });\nmodule.exports = router;\n",
  );
  fx.commit('add rate limiting to /login', { date: '2026-01-01T00:00:00Z' });

  fx.writeFile(
    'routes/auth.js',
    "const router = require('express').Router();\nrouter.post('/login', (req, res) => { res.send('ok'); });\nmodule.exports = router;\n",
  );
  const removedSha = fx.commit('remove rate limiting (regression)', { date: '2026-01-02T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const finding = (scan.findings || []).find(
    (f) => f.file === 'routes/auth.js' && f.missingControlCandidate === true,
  );
  assert.ok(finding, `expected a missingControlCandidate rate-limit finding; got ${JSON.stringify((scan.findings || []).map((f) => ({ file: f.file, vuln: f.vuln })))}`);
  assert.equal(finding.vuln, 'Auth endpoint missing rate limiting');

  assert.ok(finding.findingProvenance, 'finding missing findingProvenance entirely');
  const fp = finding.findingProvenance;
  assert.equal(fp.status, 'complete');
  assert.equal(fp.method, 'missing-control-regression');
  assert.ok(fp.findingOrigin, 'expected a populated findingOrigin for a genuine regression');
  assert.equal(fp.findingOrigin.commit, removedSha);
  assert.ok(
    fp.limitations.some((l) => /control-removal event/.test(l)),
    `expected a limitation distinguishing a control-removal event from an ordinary origin; got ${JSON.stringify(fp.limitations)}`,
  );
});

// Second independent Finding Provenance PRD audit (Task 7, item 1): the
// audit found `evidenceAttribution`'s `removed_guard` role was dead code —
// nothing in scanner/src ever set it, even though this exact scenario (a
// rate-limit guard present then removed) is precisely what that role
// describes. The wiring lives in coordinator.js: when
// `isMissingControlCandidate` and `resolveMissingControlOrigin` reaches
// `status:'complete'`, `attributeEvidence` is called with
// `{ removedGuard: true }`, so the finding's own file:line evidence node
// (there is no source/sink/pathSteps shape for a control-absence finding)
// gets role `removed_guard` instead of the generic `sink`.
test('missing-control wiring: a genuine rate-limit REMOVAL emits a removed_guard evidence-attribution node, not a generic sink', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  fx.writeFile(
    'routes/auth.js',
    "const router = require('express').Router();\nrouter.post('/login', rateLimit(), (req, res) => { res.send('ok'); });\nmodule.exports = router;\n",
  );
  fx.commit('add rate limiting to /login', { date: '2026-01-01T00:00:00Z' });

  fx.writeFile(
    'routes/auth.js',
    "const router = require('express').Router();\nrouter.post('/login', (req, res) => { res.send('ok'); });\nmodule.exports = router;\n",
  );
  fx.commit('remove rate limiting (regression)', { date: '2026-01-02T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const finding = (scan.findings || []).find(
    (f) => f.file === 'routes/auth.js' && f.missingControlCandidate === true,
  );
  assert.ok(finding, 'expected a missingControlCandidate rate-limit finding');
  const fp = finding.findingProvenance;
  assert.equal(fp.status, 'complete');
  assert.ok(Array.isArray(fp.evidenceAttribution) && fp.evidenceAttribution.length > 0,
    'expected at least one evidence-attribution node');
  const removedGuardNode = fp.evidenceAttribution.find((n) => n.role === 'removed_guard');
  assert.ok(removedGuardNode, `expected a removed_guard-shaped node; got roles ${JSON.stringify(fp.evidenceAttribution.map((n) => n.role))}`);
  assert.equal(removedGuardNode.path, 'routes/auth.js');
  assert.ok(!fp.evidenceAttribution.some((n) => n.role === 'sink'),
    'a control-absence finding must not ALSO get a generic sink node at the same location');
});

test('missing-control wiring: a rate-limit finding on code that NEVER had rate limiting resolves not_available, never falsely attributed to the root commit', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  fx.writeFile(
    'routes/auth.js',
    "const router = require('express').Router();\nrouter.post('/login', (req, res) => { res.send('ok'); });\nmodule.exports = router;\n",
  );
  fx.commit('root — no rate limiting, never had one', { date: '2026-01-01T00:00:00Z' });

  fx.writeFile(
    'routes/auth.js',
    "const router = require('express').Router();\nrouter.post('/login', (req, res) => { res.send('ok'); }); // still no rate limit\nmodule.exports = router;\n",
  );
  fx.commit('later, unrelated touch — still no rate limiting', { date: '2026-01-02T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const finding = (scan.findings || []).find(
    (f) => f.file === 'routes/auth.js' && f.missingControlCandidate === true,
  );
  assert.ok(finding, `expected a missingControlCandidate rate-limit finding; got ${JSON.stringify((scan.findings || []).map((f) => ({ file: f.file, vuln: f.vuln })))}`);

  const fp = finding.findingProvenance;
  assert.ok(fp, 'finding missing findingProvenance entirely');
  assert.equal(fp.status, 'not_available');
  assert.equal(fp.findingOrigin, null, 'must never fabricate an origin for a control that was never present');
  assert.ok(
    fp.limitations.some((l) => /never present/.test(l) || /no prior version/.test(l)),
    `expected the honest "never observed present" limitation; got ${JSON.stringify(fp.limitations)}`,
  );
});
