// R2's differentiator — auto-enrolling an execution-proven finding as a
// permanent corpus entry.
//
// The refusal tests carry most of the weight. The failure this automates away
// is the v0.106.0 one (fixtures committed without verifying they score), so
// every way an unscored or unproven entry could reach the corpus is asserted
// to be refused, and the success path is proven by re-scoring the entry off
// disk rather than by trusting the writer's own verdict.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { runScan } from '../src/runScan.js';
import { preHit, postHit, matcherFor } from '../src/posture/corpus-match.js';
import {
  isEnrollable, buildCandidate, enrollProvenFinding, entryIdFor, _internals,
} from '../src/posture/corpus-enroll.js';

const VULN = [
  "const { exec } = require('child_process');",
  'module.exports = function handler(req, res) {',
  "  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));",
  '};',
].join('\n') + '\n';

// The fix is an allowlist plus argv-form exec. Note that argv form ALONE is
// not enough to clear the detector here — the engine still reports
// `execFile('ping', ['-c','1', String(req.query.host)])`. That is exactly the
// kind of thing enrolment must discover by scanning rather than assume: a
// plausible-looking fix that leaves the entry scoring post:FP.
const FIXED = [
  "const { execFile } = require('child_process');",
  "const ALLOWED = new Set(['alpha.internal', 'beta.internal']);",
  'module.exports = function handler(req, res) {',
  '  const host = String(req.query.host);',
  "  if (!ALLOWED.has(host)) return res.status(400).send('bad host');",
  "  execFile('ping', ['-c', '1', host], (e, out) => res.send(out));",
  '};',
].join('\n') + '\n';

function tmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-`));
}

// Build a finding the way the pipeline would: scan the real vulnerable file
// and take a real finding off it, rather than hand-writing a `vuln` string the
// detector never emits.
async function realProvenFinding() {
  const dir = tmp('enroll-src');
  try {
    fs.writeFileSync(path.join(dir, 'handler.js'), VULN);
    const { scan } = await runScan(dir);
    const f = (scan.findings || []).find(x => /command/i.test(x.family || '') || /command/i.test(x.vuln || ''));
    assert.ok(f, 'the fixture must produce a command-injection finding for this test to mean anything');
    return {
      ...f,
      file: 'handler.js',
      proofTier: 'execution-proven',
      proofEvidence: {
        tier: 'execution-proven', ran: true, backend: 'userspace',
        observed: "proof marker 'PROVEN' written by the proof-of-concept",
        at: '2026-08-07T00:00:00.000Z', reason: null, exitCode: 0, timedOut: false,
      },
    };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

const files = { pre: { 'handler.js': VULN }, post: { 'handler.js': FIXED } };

// ---------------------------------------------------------------- gate

test('only execution-proven findings may enrol', () => {
  for (const tier of ['taint-proven', 'proof-failed', 'unproven', undefined]) {
    const r = isEnrollable({ proofTier: tier, proofEvidence: { ran: true, tier } });
    assert.equal(r.ok, false, `tier ${tier} must be refused`);
    assert.match(r.reason, /execution-proven/);
  }
});

test('an execution-proven tier with no run behind it is refused', () => {
  const r = isEnrollable({
    proofTier: 'execution-proven',
    proofEvidence: { tier: 'execution-proven', ran: false, observed: 'x' },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /does not record a run/);
});

test('a tier that disagrees with its own evidence is refused, not reconciled', () => {
  const r = isEnrollable({
    proofTier: 'execution-proven',
    proofEvidence: { tier: 'taint-proven', ran: true, observed: 'x' },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /disagrees/);
});

test('execution-proven with nothing observed is refused', () => {
  const r = isEnrollable({
    proofTier: 'execution-proven',
    proofEvidence: { tier: 'execution-proven', ran: true, observed: null },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no observed effect/);
});

// ---------------------------------------------------------------- build

test('a candidate with no post/ is refused rather than synthesised', async () => {
  const f = await realProvenFinding();
  const r = buildCandidate(f, { preFiles: files.pre });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no post\/ content/);
});

test('post/ identical to pre/ is refused', async () => {
  const f = await realProvenFinding();
  const r = buildCandidate(f, { preFiles: files.pre, postFiles: { 'handler.js': VULN } });
  assert.equal(r.ok, false);
  assert.match(r.reason, /byte-identical/);
});

test('a path that escapes the entry directory is refused', async () => {
  const f = await realProvenFinding();
  const r = buildCandidate(f, {
    preFiles: { '../evil.js': VULN, 'handler.js': VULN },
    postFiles: files.post,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /escapes/);
});

test("a pre/ that does not contain the finding's file is refused", async () => {
  const f = await realProvenFinding();
  const r = buildCandidate(f, { preFiles: { 'other.js': VULN }, postFiles: files.post });
  assert.equal(r.ok, false);
  assert.match(r.reason, /not among the pre\/ files/);
});

test('the manifest matcher is escaped so it cannot match more than the finding', async () => {
  const f = await realProvenFinding();
  const c = buildCandidate({ ...f, vuln: 'exec() with user input (unsafe)' }, {
    preFiles: files.pre, postFiles: files.post,
  });
  assert.equal(c.ok, true);
  const m = matcherFor(c.manifest);
  assert.ok(m.test('exec() with user input (unsafe)'));
  assert.ok(!m.test('execX with user inputX unsafeX'), 'regex metacharacters must not stay live');
});

test('the entry id is stable for the same finding', async () => {
  const f = await realProvenFinding();
  assert.equal(entryIdFor(f), entryIdFor({ ...f }));
});

// ---------------------------------------------------------------- enrol

test('an entry is NOT written when the detector does not fire on pre/', async () => {
  const f = await realProvenFinding();
  const corpus = tmp('enroll-corpus');
  try {
    const r = await enrollProvenFinding(f, {
      corpusRoot: corpus,
      // Harmless pre/ — nothing to detect, so the entry would land already failing.
      preFiles: { 'handler.js': 'module.exports = () => 1;\n' },
      postFiles: files.post,
      runScan,
    });
    assert.equal(r.ok, false);
    assert.match(r.status, /pre:FN/);
    assert.equal(fs.existsSync(path.join(corpus, 'capability')), false, 'nothing may be written on a refusal');
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

test('an entry is NOT written when the detector still fires on post/', async () => {
  const f = await realProvenFinding();
  const corpus = tmp('enroll-corpus');
  try {
    const r = await enrollProvenFinding(f, {
      corpusRoot: corpus,
      preFiles: files.pre,
      // "Fixed" but still vulnerable — post would score FP.
      postFiles: { 'handler.js': VULN.replace('ping -c 1 ', 'ping -c 2 ') },
      runScan,
    });
    assert.equal(r.ok, false);
    assert.match(r.status, /post:FP/);
    assert.equal(fs.existsSync(path.join(corpus, 'capability')), false);
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

test('enrolment refuses without a runScan — an entry may never be committed unscored', async () => {
  const f = await realProvenFinding();
  const corpus = tmp('enroll-corpus');
  try {
    const r = await enrollProvenFinding(f, { corpusRoot: corpus, ...{ preFiles: files.pre, postFiles: files.post } });
    assert.equal(r.ok, false);
    assert.match(r.reason, /unscored/);
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

test('a proven finding enrols, and the WRITTEN entry re-scores pre:TP post:TN off disk', async (t) => {
  const f = await realProvenFinding();
  const corpus = tmp('enroll-corpus');
  try {
    const r = await enrollProvenFinding(f, {
      corpusRoot: corpus, preFiles: files.pre, postFiles: files.post, runScan,
    });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.status, 'pre:TP post:TN');
    assert.equal(r.tier, 'capability', 'automated writes must not land in the CI-gated tier');

    // Structure the runner expects.
    const dir = r.dir;
    assert.ok(fs.existsSync(path.join(dir, 'manifest.json')));
    assert.ok(fs.existsSync(path.join(dir, 'pre', 'handler.js')));
    assert.ok(fs.existsSync(path.join(dir, 'post', 'handler.js')));
    assert.equal(fs.existsSync(path.join(dir, 'pre', '.agentic-security')), false,
      'scan state must not be committed inside a fixture');

    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    assert.equal(manifest.source, 'execution-proven');
    assert.equal(manifest.expected.file, 'handler.js');
    assert.equal(manifest.provenance.proofBackend, 'userspace');

    // The load-bearing assertion: score the entry AS COMMITTED, from disk,
    // with the same matcher the gate uses. The writer's own verdict is not
    // evidence — this is.
    const matcher = matcherFor(manifest);
    const { scan: pre } = await runScan(path.join(dir, 'pre'));
    const { scan: post } = await runScan(path.join(dir, 'post'));
    assert.equal(preHit(pre, manifest, matcher), true, 'the committed pre/ must fire');
    assert.equal(postHit(post, manifest, matcher), false, 'the committed post/ must not fire');
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

test('re-enrolling the same finding is refused rather than duplicated', async () => {
  const f = await realProvenFinding();
  const corpus = tmp('enroll-corpus');
  try {
    const first = await enrollProvenFinding(f, {
      corpusRoot: corpus, preFiles: files.pre, postFiles: files.post, runScan,
    });
    assert.equal(first.ok, true, first.reason);
    const second = await enrollProvenFinding(f, {
      corpusRoot: corpus, preFiles: files.pre, postFiles: files.post, runScan,
    });
    assert.equal(second.ok, false);
    assert.match(second.reason, /already exists/);
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

test('dryRun scores without writing', async () => {
  const f = await realProvenFinding();
  const corpus = tmp('enroll-corpus');
  try {
    const r = await enrollProvenFinding(f, {
      corpusRoot: corpus, preFiles: files.pre, postFiles: files.post, runScan, dryRun: true,
    });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.status, 'pre:TP post:TN');
    assert.equal(fs.existsSync(path.join(corpus, 'capability')), false);
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

// ------------------------------------------------- the full chain, for real
//
// Everything above supplies `proofEvidence` by hand, which tests enrolment but
// not the claim R2 actually makes. This one runs the real chain: a real PoC is
// executed in the real sandbox, `proveFinding` decides the tier from what the
// sandbox observed, and only then is the finding offered for enrolment. If the
// sandbox is unavailable the test SKIPS loudly rather than passing.

// Exploits the injection by appending a shell command that creates the proof
// marker. `> PROVEN` is a shell redirect, not a program, so it works under the
// sandbox's minimal environment where PATH lookups may fail.
// The safety timer is `unref`'d deliberately. Without that it keeps the event
// loop alive for its full duration even after the exploit has already landed,
// and on a loaded machine the PoC process then outlives `proveFinding`'s
// budget. That path is not a false pass — `attachProofTier` demotes anything
// with `ran:false`, so a written marker plus a timeout still yields
// `taint-proven` — but it turns a real proof into a skipped test, which is a
// silently weaker suite. Exit as soon as the handler responds.
const REAL_POC = {
  lang: 'js',
  code: [
    "import handler from './handler.js';",
    'await new Promise((resolve) => {',
    '  const res = { send: () => resolve(), status: () => ({ send: () => resolve() }) };',
    "  try { handler({ query: { host: 'x; > PROVEN' } }, res); } catch { resolve(); }",
    '  setTimeout(resolve, 4000).unref();',
    '});',
  ].join('\n'),
};

test('the real chain: sandbox proof decides the tier, and only a proven finding enrols', async (t) => {
  const { proveFinding } = await import('../src/posture/execution-proof.js');
  const { sandboxAvailable } = await import('../src/sandbox/index.js');
  if (!sandboxAvailable()) {
    t.skip('SKIPPED, NOT PASSED: no confinement backend on this host, so no proof could be executed');
    return;
  }

  const base = await realProvenFinding();
  // Discard the hand-written evidence — the sandbox decides.
  const bare = { ...base, proofTier: undefined, proofEvidence: undefined, parser: 'IR-TAINT', poc: REAL_POC };

  const provenVuln = await proveFinding({ ...bare }, { files: { 'handler.js': VULN } });
  if (provenVuln.proofTier !== 'execution-proven') {
    t.skip(`SKIPPED, NOT PASSED: the PoC did not execute here (${provenVuln.proofEvidence?.reason})`);
    return;
  }
  assert.equal(provenVuln.proofEvidence.ran, true);

  // Same PoC against the FIXED tree must not prove anything. This is the
  // direction that makes the proof mean something.
  const provenFixed = await proveFinding({ ...bare }, { files: { 'handler.js': FIXED } });
  assert.notEqual(provenFixed.proofTier, 'execution-proven',
    'the fix must defeat the PoC, or the PoC is not testing the vulnerability');

  // The genuinely-proven finding enrols; the unproven one does not.
  assert.equal(isEnrollable(provenVuln).ok, true);
  assert.equal(isEnrollable(provenFixed).ok, false);

  const corpus = tmp('enroll-corpus');
  try {
    const r = await enrollProvenFinding({ ...provenVuln, file: 'handler.js' }, {
      corpusRoot: corpus, preFiles: files.pre, postFiles: files.post, runScan,
    });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.status, 'pre:TP post:TN');
    const manifest = JSON.parse(fs.readFileSync(path.join(r.dir, 'manifest.json'), 'utf8'));
    assert.equal(manifest.provenance.observed, provenVuln.proofEvidence.observed);
  } finally { fs.rmSync(corpus, { recursive: true, force: true }); }
});

// Stage 5 correctness audit: this module's own header comment and
// posture/CLAUDE.md both assert "scoreCandidate is deliberately unexported
// so no caller can score by one route and write by another" — the
// structural guarantee that makes it impossible to reintroduce the
// v0.106.0 unscored-write mistake. But scoreCandidate WAS reachable, just
// one property-access away, via `_internals.scoreCandidate` — the same
// _internals convention this module (and autopilot.js, corpus-match.js)
// uses to expose genuinely test-only pure helpers. A future contributor
// trusting the header comment could import _internals for an unrelated
// reason and unknowingly get the "unexported" function back.
test('scoreCandidate is genuinely unreachable through _internals (the documented guarantee actually holds)', () => {
  assert.equal('scoreCandidate' in _internals, false,
    'scoreCandidate must not be reachable via _internals — the module docs assert it is deliberately unexported');
});
