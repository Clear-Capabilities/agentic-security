// Determinism is a PUBLISHED property: an auditor who re-runs a scan on the
// same input must get the same artifact, byte for byte, or an attestation over
// that artifact means nothing.
//
// It held for every emitted format when this was written — which is exactly
// why it needs a gate. Nothing was stopping the next `new Date()`, `Math.random()`,
// unsorted `Object.keys()` or Set-iteration order from silently breaking it,
// and the failure is invisible in ordinary use: the scan still succeeds, the
// output still parses, and only a byte comparison across two runs shows it.
//
// One run per format pair, on the smallest fixture that produces findings —
// this is a property check, not a corpus sweep, and it has to stay cheap
// enough that nobody is tempted to drop it from the gate.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const CLI = path.join(ROOT, 'bin', 'agentic-security.js');

// `--deterministic` REFUSES to run without a rules lockfile, printing to stderr
// and emitting nothing on stdout. A first version of this file scanned the
// fixture in place, got empty output from both runs, and reported every format
// as deterministic — two empty strings hash identically. That is the same
// vacuous pass these tests exist to prevent, so the target is a scratch copy
// with a real lockfile, and every case asserts non-empty output before
// comparing.
let TARGET;

before(() => {
  TARGET = fs.mkdtempSync(path.join(os.tmpdir(), 'fmt-determinism-'));
  fs.cpSync(path.join(HERE, 'fixtures', 'vulnerable-js'), TARGET, { recursive: true });
  const lock = spawnSync(process.execPath, [CLI, 'rules', 'lock'], { cwd: TARGET, encoding: 'utf8' });
  assert.equal(lock.status, 0, `could not write a lockfile: ${lock.stderr}`);
});

after(() => { try { fs.rmSync(TARGET, { recursive: true, force: true }); } catch { /* best effort */ } });

// Every format the CLI can emit to stdout. A format added without being listed
// here is a format nobody checks — see the completeness test at the end.
const FORMATS = ['sarif', 'json', 'junit', 'csv', 'md', 'cyclonedx', 'sbom', 'spdx', 'vex', 'html', 'oscal'];

function emit(format) {
  const r = spawnSync(process.execPath, [CLI, 'scan', '.', '--format', format, '--deterministic'], {
    cwd: TARGET, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  return r.stdout || '';
}

const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// A scan WRITES state (last-scan.json and its .sig) that a later scan READS —
// the privacy-framework assessment checks whether that signature exists. So the
// very first scan of a fresh directory legitimately differs from every scan
// after it: the input changed, because the first run created part of it.
//
// That is not the property under test. Determinism means identical input gives
// identical output, and the state directory is part of the input. One warm-up
// scan settles it, and the comparison is then between two runs that genuinely
// see the same thing. The warm-up is deliberately NOT hidden — it is the
// difference between "the emitter is stable" and "nothing is writing state",
// and only the first is being claimed.
before(() => { emit('json'); });

for (const format of FORMATS) {
  test(`--deterministic makes ${format} byte-identical across runs`, () => {
    const first = emit(format);
    assert.ok(first.length > 0, `${format} produced no output — the check would be vacuous`);

    const second = emit(format);
    assert.equal(
      sha(second),
      sha(first),
      `${format} differs between two identical runs (${first.length} vs ${second.length} bytes) — `
      + 'something time-, order- or randomness-dependent leaked into the artifact',
    );
  });
}

// The fixture above is copied into a plain tmpdir with NO `git init` — so
// `annotateGitProvenance` (engine.js) short-circuits every finding straight
// to `stampAll(NOT_AVAILABLE)`, `firstObserved` never gets set, and the
// `observedAt` freeze (engine.js, search `isDeterministic() ?
// '1970-01-01T00:00:00.000Z'`) is never actually exercised by any test
// above — they would pass identically with or without that freeze. This
// block git-inits a second fixture so real origin resolution runs and
// `findingProvenance.firstObserved.observedAt` is genuinely populated and
// compared across two runs.
let GIT_TARGET;

before(() => {
  GIT_TARGET = fs.mkdtempSync(path.join(os.tmpdir(), 'fmt-determinism-git-'));
  fs.cpSync(path.join(HERE, 'fixtures', 'vulnerable-js'), GIT_TARGET, { recursive: true });
  const git = (gitArgs) => {
    const r = spawnSync('git', gitArgs, { cwd: GIT_TARGET, encoding: 'utf8' });
    assert.equal(r.status, 0, `git ${gitArgs.join(' ')} failed: ${r.stderr}`);
    return r;
  };
  git(['init']);
  git(['config', 'user.email', 'determinism-test@example.com']);
  git(['config', 'user.name', 'Determinism Test']);
  git(['add', '-A']);
  git(['commit', '-m', 'initial commit']);
  const lock = spawnSync(process.execPath, [CLI, 'rules', 'lock'], { cwd: GIT_TARGET, encoding: 'utf8' });
  assert.equal(lock.status, 0, `could not write a lockfile: ${lock.stderr}`);
});

after(() => { try { fs.rmSync(GIT_TARGET, { recursive: true, force: true }); } catch { /* best effort */ } });

function emitGit(format) {
  const r = spawnSync(process.execPath, [CLI, 'scan', '.', '--format', format, '--deterministic'], {
    cwd: GIT_TARGET, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  return r.stdout || '';
}

// Same warm-up reasoning as above: the first scan of a fresh directory
// legitimately differs from every scan after it because it creates
// last-scan.json/.sig, which is itself part of the input to the next scan.
before(() => { emitGit('json'); });

test('--deterministic makes SARIF byte-identical across runs against a real git history (findingProvenance exercised)', () => {
  const first = emitGit('sarif');
  assert.ok(first.length > 0, 'sarif produced no output — the check would be vacuous');

  // Guard against a vacuous pass: if provenance resolution never actually ran
  // (e.g. the CLI silently ignored the git history), every finding would be
  // stamped not_available/firstObserved:null just like the ungited fixture
  // above, and this test would pass identically with or without the
  // observedAt freeze — the exact gap this block exists to close.
  const parsed = JSON.parse(first);
  const results = parsed?.runs?.[0]?.results || [];
  assert.ok(results.length > 0, 'sarif produced no results — the check would be vacuous');
  const withResolvedOrigin = results.filter((r) => {
    const fp = r?.properties?.findingProvenance;
    return fp && fp.status !== 'not_available' && fp.firstObserved && fp.firstObserved.observedAt;
  });
  assert.ok(
    withResolvedOrigin.length > 0,
    'no SARIF result resolved a real findingProvenance.firstObserved.observedAt against the git history — ' +
    'this test would not actually exercise the observedAt freeze',
  );

  const second = emitGit('sarif');
  assert.equal(
    sha(second),
    sha(first),
    `sarif differs between two identical runs against a real git history (${first.length} vs ${second.length} bytes) — ` +
    'findingProvenance.firstObserved.observedAt (or something else provenance-derived) leaked non-determinism into the artifact',
  );
});

test('the format list still matches what the CLI accepts', () => {
  // Anti-rot: this file is only as good as its list. If a new output format
  // ships, it must be added here rather than silently going unchecked.
  const help = spawnSync(process.execPath, [CLI, 'scan', '--help'], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
  });
  const text = `${help.stdout || ''}${help.stderr || ''}`;
  // Only assert on formats the help text actually enumerates; the point is to
  // catch an ADDED format, so a name in the help that we do not cover fails.
  const advertised = [...text.matchAll(/\b(sarif|oscal|junit|cyclonedx|spdx|openvex|vex|sbom|pbom|aibom|csv|html|stix)\b/g)]
    .map((m) => m[1]);
  const uncovered = [...new Set(advertised)].filter((f) => !FORMATS.includes(f));
  assert.deepEqual(
    uncovered,
    [],
    `formats advertised by --help but not determinism-checked: ${uncovered.join(', ')}`,
  );
});
