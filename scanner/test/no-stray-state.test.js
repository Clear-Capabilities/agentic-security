// State-write seam guard.
//
// HISTORY, kept because the numbers are the argument. Two PRDs drove this work
// (docs/NON_MUTATING_SCAN_PRD.md, then a completion PRD whose file was removed
// once every workstream landed), so what they established lives here:
//
//   · 59 modules once built `.agentic-security` paths by hand against 5 that
//     used the seam. The migration ledger below is now EMPTY.
//   · A scan of a foreign tree wrote 10 files into it; it now writes none, in
//     six different scan configurations.
//   · The cve-replay corpus — behind the gate that runs on every push — held
//     420 contaminated trees and ~20.8 MB of the engine's own output, growing
//     by 420 files per run. It holds none.
//   · The repository itself held 298 stray state directories, in docs/,
//     commands/ and .github/workflows/, created by the self-scan harness.
//
// The recurring lesson, which is why these guards exist rather than a
// convention: every one of those defects was invisible until something
// asserted its absence, and `state-dir.js` — the correct fix — had existed the
// whole time and was simply not used.
//
// WHY THIS EXISTS
// ---------------
// `posture/state-dir.js` is the one place allowed to decide where
// `.agentic-security/` lives. It refuses to write outside a project root, and it
// now honours a global read-only switch so a scan can leave the scanned tree
// untouched.
//
// None of that helps if callers build the path themselves. Measured when this
// guard was written: 59 modules under `scanner/src/` constructed
// `.agentic-security` paths directly, against 5 that routed through the seam. A
// guard 8% of callers use is documentation, not a control.
//
// The consequences were not theoretical. `state-dir.js`'s own header records a
// user who uninstalled the plugin when stray state directories broke their
// build, and this project's independent benchmark was silently contaminated for
// weeks — 220 polluted trees, 544 state files carrying CWE identifiers, so the
// engine was partly grading itself.
//
// HOW THIS GUARD WORKS
// --------------------
// The ALLOWLIST below is a MIGRATION LEDGER, not a set of exemptions. It is
// seeded with the modules that already bypassed the seam, so the guard can be
// enforced from today: it cannot fix history, but it makes the list strictly
// non-growing. Every new violation fails the build.
//
// Entries come OFF this list as modules migrate. Nothing goes ON it without a
// written reason, reviewed — the same rule `no-dead-modules.test.js` uses, which
// has caught four real defects in this repository.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
// `bin/` as well as `src/`. The guard originally walked only `src/`, and the
// three largest artifacts a scan leaves behind — findings.json, last-scan.json
// and its .sig — are written by `bin/agentic-security.js`. A seam guard blind to
// the CLI entry point misses the primary writer.
const ROOTS = ['src', 'bin'].map(d => path.join(SCANNER, d));

/**
 * Writers that DELIBERATELY do not honour the read-only scan switch.
 *
 * `AGENTIC_SECURITY_NO_STATE` means "this SCAN must not modify the tree it was
 * pointed at". It does not mean "this process may not write anything", and
 * conflating the two would break things that are not scans — or, worse, would
 * hand an attacker an off switch:
 *
 *  · mcp/audit.js       — the MCP audit log. An audit log that any environment
 *                         variable can silence is not an audit log. Guarding it
 *                         would convert a security control into a suggestion.
 *  · mcp/tools.js       — the agent scratchpad, owned by the MCP session
 *                         lifecycle rather than by a scan.
 *  · corpus-enroll.js   — writing a corpus entry IS its purpose; it is invoked
 *                         explicitly and never during a scan.
 *  · deterministic.js   — `rules lock` writes the lockfile the user asked for.
 *  · fix-plan.js        — the fix path, invoked explicitly on the user's own
 *                         project.
 *  · integrations/tickets.js — ticket sync, an explicit user command.
 *  · bin/agentic-security-rule.js — writes to an output path the user named on
 *                         the command line, not to scan state.
 *
 * Listed so that "unguarded" is never mistaken for "unfinished". Anything NOT
 * on this list and not guarded is a gap.
 */
const DELIBERATELY_UNGUARDED = new Set([
  'src/mcp/audit.js', 'src/mcp/tools.js', 'src/posture/corpus-enroll.js',
  'src/posture/deterministic.js', 'src/posture/fix-plan.js',
  'src/integrations/tickets.js',
  'bin/agentic-security-rule.js',
]);

/**
 * Occurrences that are NOT state-path construction, with reasons.
 *
 * The detector looks for a `.agentic-security` string literal. That is the
 * right signal for "is this module building a state path by hand", and it also
 * matches things that merely NAME the directory. Those are not migrations
 * waiting to happen — routing them through the seam would be wrong, not late:
 *
 *  · src/engine.js                — `.agentic-security` inside IGNORE_DIRS is a
 *      directory NAME in a skip-list, not a path being built.
 *  · bin/agentic-security.js      — the remaining hits are console output, help
 *      text, and prompt templates that TELL the user where state lives.
 *  · posture/license-policy.js    — a finding's `file:` field, i.e. the location
 *      shown to a human, not a path anything opens.
 *  · posture/pr-augment.js        — likewise a `path:` field in emitted output.
 *  · posture/rule-overrides.js    — prose inside a warning message.
 *  · mcp/tools.js                 — the reserved-write denylist and the
 *      scratchpad prefix are a security CONTROL over that directory; they are
 *      compared against, never joined to a root.
 *  · bin/agentic-security-rule.js — a confinement prefix check (`is this path
 *      inside the state dir?`), same shape as above.
 *  · posture/corpus-enroll.js     — locates state dirs in order to REMOVE them
 *      while building a corpus entry.
 *  · posture/scan-checkpoint.js   — documented in the module: statePath() falls
 *      back to process.cwd() when the given root does not exist, which resolved
 *      a checkpoint into the scanner's own source tree. Explicit join is the
 *      safer construction here, and a test pins it.
 *  · posture/threat-model-grounding.js — the prefix constant is the mechanism
 *      that routes only the state entry of a MIXED path list through the seam.
 *  · posture/agents-memory.js, discovery/memory.js, posture/verifier-target.js —
 *      exported relative-path constants that document where the file lives and
 *      are joined to a root by callers (including tests). The literal IS the
 *      published location.
 *
 * This is NOT a second allowlist. Every entry is a place the string appears
 * without a path being constructed, and the test below proves each one still
 * exists so the list cannot rot into a dumping ground.
 */
const NOT_PATH_CONSTRUCTION = new Set([
  'src/engine.js', 'bin/agentic-security.js', 'src/posture/license-policy.js',
  'src/posture/pr-augment.js', 'src/posture/rule-overrides.js', 'src/mcp/tools.js',
  'bin/agentic-security-rule.js', 'src/posture/corpus-enroll.js',
  'src/posture/scan-checkpoint.js', 'src/posture/threat-model-grounding.js',
  'src/posture/agents-memory.js', 'src/discovery/memory.js',
  'src/posture/verifier-target.js',
]);

/** The seam itself, plus modules awaiting migration. NON-GROWING. */
const ALLOWLIST = new Set([
  'src/posture/state-dir.js',       // the seam
  // --- migration ledger: seeded 2026-08-09 with 59 modules, now EMPTY ---
  // Every module that built a state path by hand now routes through
  // posture/state-dir.js. What remains under NOT_PATH_CONSTRUCTION above are
  // occurrences where the string names the directory without constructing a
  // path to it. Nothing goes back on this list.
]);

/**
 * Strip comments before looking for violations.
 *
 * Without this the guard flags a module for DOCUMENTING its own state files —
 * `// writes .agentic-security/foo.json` reads identically to a path
 * construction. Two modules migrated in this change (`compliance-policy.js`,
 * `pqc-migration-plan.js`) still describe their artifacts in header comments, so
 * a comment-blind guard would pin them to the ledger permanently and make the
 * ledger un-shrinkable — the exact rot the stale-entry test exists to prevent.
 *
 * ORDER IS LOAD-BEARING: line comments FIRST, then block comments.
 *
 * The reverse order silently defeats the guard. `custom-rules.js` carries the
 * line comment `// File location: .agentic-security/rules/*.yml`. Stripping
 * blocks first, that glob's `/*` opens a block comment which runs to the next
 * `*​/` in the file — measured: 12,198 characters consumed, swallowing the real
 * violation on line 51 (`path.join(scanRoot, '.agentic-security', 'rules')`)
 * and reporting the module as clean. Removing `//` lines first deletes the
 * spurious opener before it can match. Both cases are asserted below.
 */
function stripComments(src) {
  return src.replace(/(^|[^:])\/\/.*$/gm, '$1').replace(/\/\*[\s\S]*?\*\//g, '');
}

function offenders() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules' && e.name !== '.git') walk(p); continue; }
      if (!e.name.endsWith('.js')) continue;
      const rel = path.relative(SCANNER, p);
      const src = stripComments(fs.readFileSync(p, 'utf8'));
      // A literal '.agentic-security' used to build a path.
      if (/['"`]\.agentic-security['"`/]/.test(src)) out.push(rel);
    }
  };
  for (const r of ROOTS) walk(r);
  return out;
}

test('no NEW module constructs a .agentic-security path outside the seam', () => {
  const found = offenders().filter(f => !ALLOWLIST.has(f) && !NOT_PATH_CONSTRUCTION.has(f));
  assert.deepEqual(found, [],
    'These modules build state paths directly instead of using posture/state-dir.js.\n' +
    'Route the write through stateDir()/statePath()/safeWriteState(), which enforce the\n' +
    'project-root check AND the read-only scan switch. Adding to the ALLOWLIST is not the\n' +
    'fix — that list is a shrinking migration ledger, not a set of exemptions.');
});

test('the allowlist is a shrinking ledger — it never lists a module that is already clean', () => {
  // Stops the ledger rotting into permanent scaffolding: once a module is
  // migrated its entry MUST be removed, or the guard silently stops watching it.
  const current = new Set(offenders());
  const stale = [...ALLOWLIST].filter(f => f !== 'src/posture/state-dir.js' && !current.has(f));
  // The same rule binds NOT_PATH_CONSTRUCTION: an entry whose literal is gone
  // must be deleted, or the set silently stops covering a file it no longer
  // describes.
  const staleExempt = [...NOT_PATH_CONSTRUCTION].filter(f => !current.has(f));
  assert.deepEqual(staleExempt, [],
    'These NOT_PATH_CONSTRUCTION entries no longer contain the string at all — delete them.');
  assert.deepEqual(stale, [],
    'These allowlist entries no longer violate anything — delete them so the guard covers them again.');
});

test('the guard actually detects a violation (proven, not assumed)', () => {
  // A guard demonstrated only in the passing direction has not been
  // demonstrated. This asserts the detection regex on a constructed sample
  // rather than trusting that a clean tree means it works.
  const hit = (s) => /['"`]\.agentic-security['"`/]/.test(stripComments(s));
  assert.ok(hit(`const p = path.join(root, '.agentic-security', 'x.json');`),
    'the detector must match a direct construction');
  assert.ok(!hit('const p = stateDir(root);'),
    'and must not match a call through the seam');

  // Comment stripping, both directions. A guard that flags prose would pin
  // migrated modules to the ledger forever; one that strips too eagerly would
  // miss a real violation sharing a line with a comment.
  assert.ok(!hit(`// writes ".agentic-security/report.json" after each scan`),
    'documentation of a state file is not a violation');
  assert.ok(!hit(`/*\n * Artifacts land in '.agentic-security/'.\n */`),
    'a block comment describing state is not a violation');
  assert.ok(hit(`const p = path.join(r, '.agentic-security'); // legacy path`),
    'a real violation must still be caught when a comment follows it');

  // Regression: a glob inside a LINE comment must not open a block comment and
  // swallow the code after it. This shape is verbatim from custom-rules.js and
  // hid a genuine violation until the strip order was fixed.
  assert.ok(hit([
    `// File location: .agentic-security/rules/*.yml`,
    `function rulesDir(scanRoot) {`,
    `  return path.join(scanRoot, '.agentic-security', 'rules');`,
    `}`,
  ].join('\n')), 'a glob in a line comment must not mask the code below it');
});

// --- S1 acceptance: a scan of a foreign tree leaves it byte-identical --------

/** Every path under `dir`, relative and sorted. */
function snapshot(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.name === '.git') continue;
      const p = path.join(d, e.name);
      out.push(path.relative(dir, p));
      if (e.isDirectory()) walk(p);
    }
  };
  walk(dir);
  return out;
}

test('a --no-state scan of a foreign tree adds ZERO new paths', async (t) => {
  // THE ACCEPTANCE CRITERION, not a proxy for it.
  //
  // `git status` alone is not sufficient evidence and was actively misleading
  // here: git does not track empty directories, so an earlier revision of this
  // change reported a clean status while still creating `sbom-history/` and
  // `fix-history/` in the scanned tree. Comparing the full path listing is what
  // caught that. Directory creation IS mutation — on a read-only mount it fails,
  // and in someone else's repository it is still litter.
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'nostate-scan-'));
  try {
    await fsp.writeFile(path.join(tmp, 'package.json'), '{"name":"victim","version":"1.0.0"}');
    await fsp.writeFile(path.join(tmp, 'app.js'), [
      "const { exec } = require('child_process');",
      "app.get('/r', (req, res) => { exec('ls ' + req.query.dir, (e, o) => res.send(o)); });",
      'app.get(\'/q\', (req, res) => { db.query("SELECT * FROM u WHERE id=" + req.query.id); });',
    ].join('\n'));

    const before = snapshot(tmp);
    const cli = path.join(SCANNER, 'bin', 'agentic-security.js');
    const run = spawnSync(process.execPath, [cli, 'scan', '.', '--format', 'sarif'], {
      cwd: tmp,
      env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' },
      encoding: 'utf8',
    });

    // The scan must still WORK. A read-only scan that fails, or that reports
    // nothing, would "pass" a zero-new-paths check for entirely the wrong
    // reason — so the findings are asserted before the paths are.
    assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
    const sarif = JSON.parse(run.stdout.slice(run.stdout.indexOf('{')));
    assert.ok((sarif.runs?.[0]?.results || []).length > 0,
      'the read-only scan must still report findings');

    assert.deepEqual(snapshot(tmp), before,
      'a --no-state scan must not add, remove, or rename any path in the scanned tree');
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
});

// ── Every scan-path writer honours the read-only switch ─────────────────────

test('a ledger module that writes state either honours --no-state or is a declared exception', () => {
  // The ledger says "builds a path by hand". This asks the question that
  // actually matters: can it MUTATE a tree during a read-only scan?
  //
  // Modules with no write syscall at all cannot, provably — that partition is
  // by ABSENCE, not by tracing a path to a write, which is why it holds where
  // three successive regexes disagreed (they reported 10, 12 and 13 writers;
  // reading the files found ~30).
  const WRITE = /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|mkdir|rmSync|renameSync|copyFileSync|unlinkSync|cpSync)\s*\(/;
  const SEAM = /stateWritesEnabled|safeWriteState|ensureStateDir/;
  // Iterates every module that names the state directory — NOT the ledger.
  // The ledger is now empty, and a guard that walks an empty list checks
  // nothing; emptying a list must never be a way to switch a control off.
  const gaps = [];
  for (const rel of offenders()) {
    if (rel === 'src/posture/state-dir.js' || DELIBERATELY_UNGUARDED.has(rel)) continue;
    const src = stripComments(fs.readFileSync(path.join(SCANNER, rel), 'utf8'));
    if (!WRITE.test(src)) continue;      // cannot write — nothing to guard
    if (SEAM.test(src)) continue;        // honours the switch
    gaps.push(rel);
  }
  assert.deepEqual(gaps, [],
    'These modules write state but never consult the read-only switch, so a\n' +
    '`--no-state` scan can still mutate the tree through them. Route the write\n' +
    'through safeWriteState(), or guard it with stateWritesEnabled(). If the write\n' +
    'is genuinely not part of a scan, add it to DELIBERATELY_UNGUARDED with a\n' +
    'written reason — an audit log or an explicit user command is not scan state.');
});

test('the deliberate-exception list is honest — every entry really does write', () => {
  // Stops the exception list becoming a place to park anything inconvenient.
  const WRITE = /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|mkdir|rmSync|renameSync|copyFileSync|unlinkSync|cpSync)\s*\(/;
  for (const rel of DELIBERATELY_UNGUARDED) {
    const src = stripComments(fs.readFileSync(path.join(SCANNER, rel), 'utf8'));
    assert.ok(WRITE.test(src),
      `${rel} is listed as a deliberately-unguarded WRITER but contains no write — remove it`);
  }
});

// ── M2: the zero-paths property across scan CONFIGURATIONS ──────────────────

/**
 * Fixtures that reach different writers. A single default scan of a two-file
 * project exercises one path through the engine; the writers migrated in M1
 * (`custom-rules`, `ifds-precise`, `sca-policy`, `pr-augment`, `scan-checkpoint`)
 * are reached only with a custom rule present, a dependency manifest, or
 * summary caching / resume enabled — none of which the original fixture had.
 * A guard that only ever sees one configuration proves one configuration.
 */
const MATRIX = [
  { name: 'default', args: [], env: {} },
  { name: 'deep', args: ['--deep'], env: {} },
  { name: 'all', args: ['--all'], env: {} },
  { name: 'resume enabled (scan-checkpoint)', args: [], env: { AGENTIC_SECURITY_RESUME: '1' } },
  { name: 'shadow custom rule present', args: [], env: {}, shadowRule: true },
  { name: 'dependency manifest present (SCA)', args: [], env: {}, deps: true },
];

for (const cell of MATRIX) {
  test(`--no-state adds ZERO paths — configuration: ${cell.name}`, async () => {
    const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'nostate-matrix-'));
    try {
      await fsp.writeFile(path.join(tmp, 'package.json'), JSON.stringify({
        name: 'victim', version: '1.0.0',
        // A real dependency set so the SCA path has something to resolve.
        ...(cell.deps ? { dependencies: { lodash: '4.17.20', minimist: '1.2.0' } } : {}),
      }));
      await fsp.writeFile(path.join(tmp, 'app.js'), [
        "const { exec } = require('child_process');",
        'function pass(x) { return x; }',
        "app.get('/r', (req, res) => { exec('ls ' + pass(req.query.dir), (e, o) => res.send(o)); });",
        'app.get(\'/q\', (req, res) => { db.query("SELECT * FROM u WHERE id=" + req.query.id); });',
        'const token = "hunter2-shadow-probe";',
      ].join('\n'));
      if (cell.shadowRule) {
        await fsp.mkdir(path.join(tmp, '.agentic-security'), { recursive: true });
        await fsp.writeFile(path.join(tmp, '.agentic-security', 'rules.yml'), [
          'custom:', '  - id: probe/shadow', '    pattern: "hunter2"',
          '    message: shadow probe', '    severity: low', '    shadow: true', '',
        ].join('\n'));
      }

      const before = snapshot(tmp);
      const run = spawnSync(process.execPath,
        [path.join(SCANNER, 'bin', 'agentic-security.js'), 'scan', '.', ...cell.args, '--format', 'sarif'],
        { cwd: tmp, env: { ...process.env, ...cell.env, AGENTIC_SECURITY_NO_STATE: '1' }, encoding: 'utf8' });

      assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
      const sarif = JSON.parse(run.stdout.slice(run.stdout.indexOf('{')));
      assert.ok((sarif.runs?.[0]?.results || []).length > 0,
        'the read-only scan must still report findings — a silent scan would pass the ' +
        'zero-paths check for entirely the wrong reason');

      assert.deepEqual(snapshot(tmp), before,
        `configuration "${cell.name}" mutated the scanned tree under --no-state`);
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
}
