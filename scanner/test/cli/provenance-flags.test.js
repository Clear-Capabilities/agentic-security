import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProvenanceFlags } from '../../bin/agentic-security.js';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// 0.145.0 inverted this: provenance is OPT-IN. On-by-default cost 4.5s -> 45s
// of time-to-first-finding on a 207-file tree, a 7.6x regression on the metric
// bench/ttff calls this product's binding ICP constraint. `mode` still defaults
// to 'standard' because it describes HOW to resolve once asked, not WHETHER to.
test('parseProvenanceFlags: with no flags, provenance is off (opt-in) and mode still defaults to standard', () => {
  const f = parseProvenanceFlags([]);
  assert.equal(f.mode, 'standard');
  assert.equal(f.disabled, true, 'provenance must be OFF unless explicitly requested');
  assert.equal(f.includeEmail, false);
  assert.equal(f.pseudonymize, false);
  assert.equal(f.requireProvenance, false);
});

// Each of these means "I want provenance"; requiring a redundant bare
// --provenance alongside them would be a papercut with no upside.
test('parseProvenanceFlags: every provenance-shaped flag enables it, not just --provenance', () => {
  assert.equal(parseProvenanceFlags(['--provenance']).disabled, false);
  assert.equal(parseProvenanceFlags(['--provenance=deep']).disabled, false);
  assert.equal(parseProvenanceFlags(['--provenance-since', 'v1.0.0']).disabled, false);
  assert.equal(parseProvenanceFlags(['--provenance-timeout', '30000']).disabled, false);
  assert.equal(parseProvenanceFlags(['--require-provenance']).disabled, false);
  assert.equal(parseProvenanceFlags(['--include-author-email']).disabled, false);
  assert.equal(parseProvenanceFlags(['--pseudonymize-authors']).disabled, false);
  // ...and an explicit --no-provenance still wins over the default-off, so the
  // flag keeps working for anyone who already has it in a script.
  assert.equal(parseProvenanceFlags(['--no-provenance']).disabled, true);
});

test('parseProvenanceFlags: --no-provenance disables', () => {
  const f = parseProvenanceFlags(['--no-provenance']);
  assert.equal(f.disabled, true);
});

test('parseProvenanceFlags: --provenance deep genuinely sets deep mode, no warning', () => {
  const f = parseProvenanceFlags(['--provenance', 'deep']);
  assert.equal(f.mode, 'deep');
  assert.equal(f.warning, null);
});

test('parseProvenanceFlags: --provenance-since, --provenance-timeout, --include-author-email, --require-provenance', () => {
  const f = parseProvenanceFlags(['--provenance-since', 'v1.0.0', '--provenance-timeout', '30000', '--include-author-email', '--require-provenance']);
  assert.equal(f.since, 'v1.0.0');
  assert.equal(f.timeoutMs, 30000);
  assert.equal(f.includeEmail, true);
  assert.equal(f.requireProvenance, true);
});

test('parseProvenanceFlags: --pseudonymize-authors', () => {
  const f = parseProvenanceFlags(['--pseudonymize-authors']);
  assert.equal(f.pseudonymize, true);
});

// Regression for a Critical bug found in review: `bin/agentic-security.js`
// must run its CLI dispatch (main()) when invoked THROUGH A SYMLINK, which
// is exactly how npm/npx run every `bin` entry (`npm install -g`, `npx`,
// `node_modules/.bin/<name>`) — including this package's own published
// `agentic-security`/`as`/`agentic-security-scanner` commands. A guard of
// the form `import.meta.url === file://${process.argv[1]}` is FALSE through
// a symlink (import.meta.url resolves to the realpath; process.argv[1]
// stays the symlink path), so the CLI would silently exit 0 with no output
// for every real installed user. The fix is `import.meta.main`, which
// resolves correctly through a symlink.
test('CLI entry point runs (produces output) when invoked through a symlink', () => {
  const realScript = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
  const dir = mkdtempSync(path.join(tmpdir(), 'as-symlink-test-'));
  const linkPath = path.join(dir, 'agentic-security-link.js');
  try {
    symlinkSync(realScript, linkPath);
    const result = spawnSync(process.execPath, [linkPath, 'version'], { encoding: 'utf8' });
    assert.equal(result.status, 0, `expected exit 0, got ${result.status}; stderr: ${result.stderr}`);
    assert.match(result.stdout, /agentic-security \d+\.\d+\.\d+/, 'symlinked invocation must produce real CLI output, not silently exit with nothing');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Final whole-branch review — I2, I3, I4, I5.
// ---------------------------------------------------------------------------

// I4: every other flag in this CLI accepts `--flag=value` (parseArgs splits on
// `=`), but parseProvenanceFlags did exact-string argv matching, so the `=`
// form was silently IGNORED — no warning, defaults quietly used. Each case
// below asserts the `=` form produces the same result as the spaced form.
test('parseProvenanceFlags: --flag=value form is accepted for every value-taking flag', () => {
  const f = parseProvenanceFlags([
    '--provenance=deep', '--provenance-since=v1.0.0', '--provenance-timeout=30000',
  ]);
  assert.equal(f.mode, 'deep');
  assert.equal(f.warning, null);
  assert.equal(f.since, 'v1.0.0');
  assert.equal(f.timeoutMs, 30000);
});

test('parseProvenanceFlags: --provenance=standard is accepted and warns about nothing', () => {
  const f = parseProvenanceFlags(['--provenance=standard']);
  assert.equal(f.mode, 'standard');
  assert.equal(f.warning, null);
});

test('parseProvenanceFlags: bare --provenance does not swallow the scan target', () => {
  // `--flag value` support must not turn `scan --provenance ./src` into
  // "unrecognised mode './src'". The space form claims the next token only when
  // it actually names a mode; the inline form, which cannot be anything BUT a
  // mode, still rejects a typo.
  const positional = parseProvenanceFlags(['scan', '--provenance', './src']);
  assert.equal(positional.mode, 'standard');
  assert.equal(positional.warning, null);

  const typo = parseProvenanceFlags(['--provenance=deeep']);
  assert.equal(typo.mode, 'standard');
  assert.match(typo.warning, /unrecognised --provenance mode 'deeep'/);
});

test('parseProvenanceFlags: a value containing = survives (split on the FIRST = only)', () => {
  // parseArgs's own `split('=', 2)` would drop everything after the second `=`.
  // A git ref is a legal place for one, and truncating it silently resolves
  // provenance against the wrong boundary.
  const f = parseProvenanceFlags(['--provenance-since=refs/tags/v1=rc1']);
  assert.equal(f.since, 'refs/tags/v1=rc1');
});

// I5: `parseInt('30s', 10)` is 30 — a 30-MILLISECOND provenance budget, which
// expires before a single `git blame` returns, so every finding came back
// `budget_exhausted` and nothing anywhere said why.
test('parseProvenanceFlags: a non-integer --provenance-timeout warns and falls back to the default', () => {
  for (const bad of ['30s', 'abc', '1.5', '-5', '0']) {
    const f = parseProvenanceFlags(['--provenance-timeout', bad]);
    assert.equal(f.timeoutMs, undefined, `'${bad}' was accepted as a timeout`);
    assert.match(f.warning, /MILLISECONDS|requires a value/, `'${bad}' produced no warning`);
  }
  // …and the `=` form is validated identically.
  const eqForm = parseProvenanceFlags(['--provenance-timeout=30s']);
  assert.equal(eqForm.timeoutMs, undefined);
  assert.match(eqForm.warning, /MILLISECONDS/);
});

test('parseProvenanceFlags: a valid --provenance-timeout still parses, and a missing value warns', () => {
  assert.equal(parseProvenanceFlags(['--provenance-timeout', '45000']).timeoutMs, 45000);
  const missing = parseProvenanceFlags(['--provenance-timeout']);
  assert.equal(missing.timeoutMs, undefined);
  assert.match(missing.warning, /requires a value in milliseconds/);
  // A following flag is another flag, not this one's value.
  const followed = parseProvenanceFlags(['--provenance-timeout', '--require-provenance']);
  assert.equal(followed.timeoutMs, undefined);
  assert.equal(followed.requireProvenance, true);
});

// I2: the provenance rendering built in Task 16 (explainProvenance +
// toCLI's `{provenance}` option) had NO production caller — it was reachable
// only from its own unit test, so a shipped feature could never be seen by a
// user. It now rides the existing --verbose convention.
test('I2: --verbose --firehose renders the provenance block on a real git repo scan', () => {
  const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
  const dir = mkdtempSync(path.join(tmpdir(), 'as-cli-prov-'));
  const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8' });
  try {
    git('init', '-q');
    git('config', 'user.email', 'fixture@example.com');
    git('config', 'user.name', 'Fixture Author');
    writeFileSync(path.join(dir, 'server.js'),
      'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    git('add', '-A');
    git('commit', '-q', '-m', 'introduce sqli');

    // `--provenance` is explicit as of 0.145.0: provenance became opt-in when
    // the release gate measured on-by-default at 4.5s -> 45s time-to-first-
    // finding. Without it there is no provenance block to render, and this
    // test would be asserting the absence of a feature rather than its output.
    const run = (extra) => spawnSync(process.execPath,
      [CLI, 'scan', dir, '--format', 'ship', '--firehose', '--no-network', '--provenance', ...extra],
      { encoding: 'utf8', timeout: 300000, env: { ...process.env, NO_COLOR: '1' } });

    const verbose = run(['--verbose']);
    assert.equal(verbose.status !== null, true, `CLI did not exit: ${verbose.stderr}`);
    assert.match(verbose.stdout, /Introduced:/,
      `--verbose scan printed no provenance block; stdout=${verbose.stdout.slice(-1500)}`);
    assert.match(verbose.stdout, /Method:\s+semantic-history-replay|Origin:/,
      'the provenance block rendered without its method/origin line');

    // The block is opt-in, not unconditional: a plain --firehose (no --verbose)
    // must stay as dense as it was before this feature existed.
    const plain = run([]);
    assert.doesNotMatch(plain.stdout, /Introduced:/,
      'the provenance block leaked into non-verbose output');

    // …and --no-provenance suppresses it even under --verbose, rather than
    // printing five lines of "we did not look" per finding.
    const off = run(['--verbose', '--no-provenance']);
    assert.doesNotMatch(off.stdout, /Introduced:/,
      '--no-provenance still rendered a provenance block');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// I3: --require-provenance set `scanHealth.provenanceIncomplete`, a key NO
// consumer reads — pipeline/assurance-mode.js and posture/compliance-policy.js
// both read `status`/`conditions[]` only, so the flag changed no behaviour
// anywhere. It now writes a condition and demotes the status, the same way
// every other scan-health signal does.
test('I3: --require-provenance records a scanHealth condition and demotes the status', () => {
  const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
  const dir = mkdtempSync(path.join(tmpdir(), 'as-cli-reqprov-'));
  try {
    // A NON-git directory: every finding resolves to `not_available`, which is
    // exactly the "unresolved provenance" condition the flag exists to report.
    writeFileSync(path.join(dir, 'server.js'),
      'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    const run = (extra) => spawnSync(process.execPath,
      [CLI, 'scan', dir, '--format', 'json', '--no-network', ...extra],
      { encoding: 'utf8', timeout: 300000 });

    const withFlag = JSON.parse(run(['--require-provenance']).stdout);
    assert.equal(withFlag.scanHealth.status, 'partial',
      '--require-provenance did not demote scanHealth.status, so assurance-mode/compliance-policy still see a clean scan');
    assert.ok(withFlag.scanHealth.conditions.some((c) => /require-provenance/.test(c)),
      `no --require-provenance condition recorded: ${JSON.stringify(withFlag.scanHealth.conditions)}`);
    assert.ok(Array.isArray(withFlag.scanHealth.provenanceIncomplete) && withFlag.scanHealth.provenanceIncomplete.length > 0,
      'the finding-id list was dropped along the way');

    // Without the flag the same scan is untouched — the flag is what adds the
    // condition, not the mere presence of unresolved provenance.
    const without = JSON.parse(run([]).stdout);
    assert.equal(without.scanHealth.status, 'complete');
    assert.ok(!without.scanHealth.conditions.some((c) => /require-provenance/.test(c)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Task 4 (PRD Section 8): --pseudonymize-authors must genuinely change real
// scan output, not merely flip a flag the report layer ignores. Spawns the
// real CLI against a real git fixture with a distinctive author name/email
// and confirms findingOrigin.authorName becomes a Contributor-XXXXXXXX
// pseudonym instead of the real name, while the same scan without the flag
// still reports the real name (backward-compatible default).
test('--pseudonymize-authors replaces the real author name with a stable Contributor-XXXXXXXX id in real scan output', () => {
  const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
  const dir = mkdtempSync(path.join(tmpdir(), 'as-cli-pseudo-'));
  const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8' });
  try {
    git('init', '-q');
    git('config', 'user.email', 'jamie@example.com');
    git('config', 'user.name', 'Jamie Chen');
    writeFileSync(path.join(dir, 'server.js'),
      'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    git('add', '-A');
    git('commit', '-q', '-m', 'introduce sqli');

    const run = (extra) => spawnSync(process.execPath,
      [CLI, 'scan', dir, '--format', 'json', '--no-network', ...extra],
      { encoding: 'utf8', timeout: 300000 });

    const withFlag = JSON.parse(run(['--pseudonymize-authors']).stdout);
    const originsWithFlag = (withFlag.findings || [])
      .map((f) => f.findingProvenance?.findingOrigin)
      .filter(Boolean);
    assert.ok(originsWithFlag.length > 0, 'no findingOrigin present to assert against');
    for (const origin of originsWithFlag) {
      assert.match(origin.authorName, /^Contributor-[0-9a-f]{8}$/,
        `--pseudonymize-authors did not pseudonymize authorName: ${JSON.stringify(origin)}`);
      assert.ok(!origin.authorName.includes('Jamie'), 'real author name leaked through pseudonymization');
    }

    // Without the PSEUDONYMIZE flag the real name still ships. `--provenance`
    // is still needed here: as of 0.145.0 provenance is opt-in, so a bare
    // `run([])` would have no findingOrigin at all and this control case would
    // pass vacuously rather than proving the name survives.
    // (`--pseudonymize-authors` above enables provenance on its own — asking
    // to pseudonymize authors is asking for provenance.)
    const without = JSON.parse(run(['--provenance']).stdout);
    const originsWithout = (without.findings || [])
      .map((f) => f.findingProvenance?.findingOrigin)
      .filter(Boolean);
    assert.ok(originsWithout.length > 0, 'no findingOrigin present to assert against');
    assert.ok(originsWithout.some((o) => o.authorName === 'Jamie Chen'),
      'real author name missing from output when --pseudonymize-authors was not passed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
