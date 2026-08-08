// The corpus scoring predicate, shared by the gate (bench/cve-replay/runner.mjs)
// and by auto-enrolment (posture/corpus-enroll.js).
//
// The symmetry property is the point of this file. `pre` and `post` used to
// disagree: an entry could score a true positive on a `family` match but only
// score a false positive on an exact `vuln` match, so the bar to pass was
// lower than the bar to fail. These tests pin the fixed behaviour so it cannot
// silently drift back.
import test from 'node:test';
import assert from 'node:assert/strict';
import { matcherFor, preHit, postHit, _internals } from '../src/posture/corpus-match.js';

const manifest = {
  cwe: 'CWE-78',
  family: 'command-injection',
  expected: { vuln_match: 'Command Injection' },
};

const scanWith = (f) => ({ findings: [f] });

test('pre and post agree on every input — the predicate is one predicate', () => {
  const cases = [
    { vuln: 'Command Injection (User-Controlled Input)', family: 'command-injection', cwe: 'CWE-78' },
    { vuln: 'something else', family: 'command-injection', cwe: 'CWE-78' },
    { vuln: 'Command Injection', family: 'other', cwe: 'CWE-78' },
    { vuln: 'unrelated', family: 'unrelated', cwe: 'CWE-79' },
    { vuln: 'Command Injection', family: 'command-injection', cwe: 'CWE-79' },
    { vuln: '', family: '', cwe: '' },
  ];
  for (const f of cases) {
    const scan = scanWith(f);
    assert.equal(
      preHit(scan, manifest), postHit(scan, manifest),
      `pre and post disagreed on ${JSON.stringify(f)} — an asymmetric bar flatters the corpus`,
    );
  }
});

test('a family-only match now counts as a post hit', () => {
  // This is the case the old asymmetry got wrong: the scanner is still
  // reporting the vulnerability, just under the family name, so the entry has
  // NOT gone quiet and must not score TN.
  //
  // The matcher has to be able to reach the family string for this to test
  // anything — `/Command Injection/i` does not match `command-injection`,
  // since the separator differs. `[- ]` spans both spellings.
  const m = { cwe: 'CWE-78', family: 'command-injection', expected: { vuln_match: 'command[- ]injection' } };
  const scan = scanWith({ vuln: 'renamed by a detector refactor', family: 'command-injection', cwe: 'CWE-78' });
  assert.equal(preHit(scan, m), true);
  assert.equal(postHit(scan, m), true, 'still reported by family = still reported');
});

test('a genuinely silent post tree scores TN', () => {
  assert.equal(postHit({ findings: [] }, manifest), false);
  assert.equal(postHit(scanWith({ vuln: 'Weak Hash', family: 'crypto-weak-hash', cwe: 'CWE-328' }), manifest), false);
});

test('the cwe clause still discriminates', () => {
  const wrongCwe = scanWith({ vuln: 'Command Injection', family: 'command-injection', cwe: 'CWE-79' });
  assert.equal(preHit(wrongCwe, manifest), false);
  assert.equal(postHit(wrongCwe, manifest), false);
});

test('a manifest with no cwe does not constrain on cwe', () => {
  const m = { family: 'command-injection', expected: { vuln_match: 'Command Injection' } };
  assert.equal(preHit(scanWith({ vuln: 'Command Injection', cwe: 'CWE-999' }), m), true);
});

test('every emit channel is consulted, not just findings', () => {
  for (const channel of _internals.CHANNELS) {
    const scan = { [channel]: [{ vuln: 'Command Injection', family: 'command-injection', cwe: 'CWE-78' }] };
    assert.equal(preHit(scan, manifest), true, `channel ${channel} was not consulted`);
    assert.equal(postHit(scan, manifest), true, `channel ${channel} was not consulted`);
  }
});

test('a manifest with nothing to match on cannot match everything', () => {
  // An empty matcher source would compile to //i and match every string,
  // turning a malformed manifest into an entry that always "passes".
  const m = matcherFor({});
  assert.equal(m.test('anything at all'), false);
  assert.equal(preHit(scanWith({ vuln: 'x', family: 'y', cwe: 'z' }), {}), false);
});

test('falls back through vuln_match -> family -> cwe', () => {
  assert.equal(matcherFor({ expected: { vuln_match: 'alpha' } }).test('ALPHA'), true);
  assert.equal(matcherFor({ family: 'beta' }).test('BETA'), true);
  assert.equal(matcherFor({ cwe: 'CWE-1' }).test('cwe-1'), true);
});

test('malformed scans are refused rather than throwing', () => {
  for (const scan of [null, undefined, {}, { findings: null }, { findings: 'nope' }]) {
    assert.equal(preHit(scan, manifest), false);
    assert.equal(postHit(scan, manifest), false);
  }
});
