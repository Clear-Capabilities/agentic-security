// QA-004: packaging, CI and built-artifact validation for Haskell and Nix/NixOS support.
// Suite "language-package-ci" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// The built bundle and the packed tarball are what users run, so this suite exercises THEM, not src/.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, cpSync, rmSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCANNER = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ROOT = join(SCANNER, '..');
const pkg = JSON.parse(readFileSync(join(SCANNER, 'package.json'), 'utf8'));
const CI = readFileSync(join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
const TOOLCHAIN = JSON.parse(readFileSync(join(ROOT, 'docs', 'language-toolchain.json'), 'utf8'));
const read = (p) => readFileSync(p, 'utf8');

/** The npm scripts and files each new critical suite is selected by. */
const REQUIRED_SCRIPTS = ['test:haskell', 'test:nix', 'test:language', 'test:language-stress', 'test:language-tools', 'bench:language-support:check', 'bench:language-support:perf'];
const TEST_FILES = (script) => [...new Set((script || '').match(/test\/[\w.\-/]+\.test\.js/g) || [])];

test('[QA-004.AC02] every new critical suite has an npm script with a non-empty list of files that exist', () => {
  for (const name of REQUIRED_SCRIPTS) assert.ok(pkg.scripts[name], `missing npm script ${name}: npm run would fail`);
  for (const name of ['test:haskell', 'test:nix', 'test:language', 'test:language-stress', 'test:language-tools']) {
    const files = TEST_FILES(pkg.scripts[name]);
    assert.ok(files.length > 0, `${name} selects no test file: an empty glob must fail, not pass`);
    for (const f of files) assert.ok(existsSync(join(SCANNER, f)), `${name} names a file that does not exist: ${f}`);
  }
  for (const name of ['bench:language-support:check', 'bench:language-support:perf']) {
    const m = pkg.scripts[name].match(/\.\.\/bench\/[\w\-/]+\.mjs/);
    assert.ok(m && existsSync(join(SCANNER, m[0])), `${name} runs a script that does not exist`);
  }
});

test('[QA-004.AC02] every Haskell, Nix and language test file is selected by exactly the scopes that run it (none is orphaned)', () => {
  const selected = new Set(Object.entries(pkg.scripts).filter(([k]) => /^test:(haskell|nix|language)/.test(k)).flatMap(([, v]) => TEST_FILES(v)));
  for (const dir of ['haskell', 'nix', 'language']) {
    for (const f of readdirSync(join(SCANNER, 'test', dir)).filter((x) => x.endsWith('.test.js'))) {
      assert.ok(selected.has(`test/${dir}/${f}`), `test/${dir}/${f} is run by no language script`);
    }
  }
  // the combined `npm test` carries the three scopes; the two excluded scopes are named, with a reason, in run-unit-tests.mjs
  const runner = read(join(ROOT, 'scripts', 'run-unit-tests.mjs'));
  for (const s of ['haskell', 'nix', 'language']) assert.match(runner, new RegExp(`'${s}'`), `${s} is not in the combined scopes`);
  for (const s of ['language-stress', 'language-tools', 'language-gates', 'language-slow', 'nixos-host']) assert.match(runner, new RegExp(`'${s}'`), `${s} is not named as an exclusion`);
});

test('[QA-004.AC02] the hosted CI workflow selects every new critical suite, and every language job and step has a deadline', () => {
  for (const cmd of ['npm run test:haskell', 'npm run test:nix', 'npm run test:language', 'npm run test:language-stress', 'npm run test:language-tools', 'npm run bench:language-support:check']) {
    assert.ok(CI.includes(cmd), `ci.yml has no step that runs "${cmd}"`);
  }
  const jobs = CI.split(/\n  (?=[a-z][\w-]*:\n)/).filter((b) => /^\s*(language-suites|language-tools-ghc|nixos-runtime):/.test(`  ${b}`) || /^(language-suites|language-tools-ghc|nixos-runtime):/.test(b));
  assert.equal(jobs.length, 3, 'the three language jobs are present');
  for (const j of jobs) {
    const head = j.split('\n    steps:')[0];
    assert.match(head, /timeout-minutes:\s*\d+/, `a language job has no job-level deadline:\n${head.slice(0, 80)}`);
    const steps = j.split('\n      - ').slice(1).filter((s) => /\brun:/.test(s) && /npm run (test|bench)|node --test|nix |ghc /.test(s));
    for (const s of steps) {
      if (/^(uses|run: (node --version|nix --version|ghc --version))/.test(s)) continue;
      assert.match(s, /timeout-minutes:\s*\d+/, `a language step has no deadline: ${s.split('\n')[0]}`);
    }
  }
  // the blocking tier lists the two that can run on a hosted runner without the network; Nix is informational by design
  const tiers = JSON.parse(read(join(ROOT, '.github', 'required-checks.json')));
  assert.ok(tiers.blocking.includes('language-suites') && tiers.blocking.includes('language-tools-ghc'));
  assert.ok(['nixos-runtime (x86_64-linux)', 'nixos-runtime (aarch64-linux)'].every((n) => tiers.informational.includes(n)), 'both per-system nixos-runtime jobs are informational');
});

test('[QA-004.AC02] the local final gates (pre-push, release check, loop profile) select the new gates', () => {
  assert.match(read(join(ROOT, 'scripts', 'pre-push-gate.mjs')), /bench:language-support:check/);
  assert.match(read(join(ROOT, 'scripts', 'release-check.mjs')), /bench:language-support:check/);
  const profile = JSON.parse(read(join(ROOT, 'scripts', 'loop-engineering', 'profiles', 'haskell-nix.json')));
  const finals = profile.finalGates.map((g) => `${g.args.join(' ')}`);
  for (const want of ['run bench:language-support:check', 'run test:language-stress', 'test']) assert.ok(finals.includes(want), `the final gate list lacks "${want}"`);
});

test('[QA-004.AC03] Node >=24 and the tool versions are recorded, and the record agrees with what the repository pins', () => {
  assert.equal(pkg.engines.node, TOOLCHAIN.runtime.node.required);
  assert.ok(Number(process.versions.node.split('.')[0]) >= 24, `running on node ${process.versions.node}`);
  assert.match(CI, new RegExp(`node-version: '${TOOLCHAIN.runtime.node.ci}'`));
  assert.match(CI, new RegExp(`ghc-version: '${TOOLCHAIN.optionalTools.ghc['ci pin'].ghc.replace(/\./g, '\\.')}'`), 'CI installs the GHC the record names');
  assert.match(CI, new RegExp(`cabal-version: '${TOOLCHAIN.optionalTools.ghc['ci pin'].cabal.replace(/\./g, '\\.')}'`));
  assert.match(CI, new RegExp(`nix-${TOOLCHAIN.optionalTools.nix['ci pin'].nix.replace(/\./g, '\\.')}/install`), 'CI installs the Nix the record names');
  const holds = JSON.parse(read(join(ROOT, '.dependency-holds.json')));
  const ts = holds.holds.find((h) => h.package === 'web-tree-sitter');
  assert.equal(ts && ts.heldAt, TOOLCHAIN.parsers.existing['web-tree-sitter'].pinned, 'the existing optional parser pin is unchanged');
  assert.ok(pkg.dependencies && !Object.keys(pkg.dependencies).some((d) => /haskell|nix/i.test(d)), 'Haskell and Nix support added no runtime dependency');
});

// ── built artifact ──────────────────────────────────────────────────────────────────────────────
const DIST = join(SCANNER, 'dist', 'agentic-security.mjs');

test('[QA-004.AC01] the committed bundle matches its checksum sidecar', () => {
  const sidecar = read(`${DIST}.sha256`).trim().split(/\s+/)[0];
  assert.equal(createHash('sha256').update(readFileSync(DIST)).digest('hex'), sidecar, 'dist/agentic-security.mjs differs from its .sha256: rebuild with npm run build');
});

test('[QA-004.AC01] the package-contents gate passes and the tarball carries every runtime asset the language analyzers read', () => {
  const gate = spawnSync(process.execPath, [join(ROOT, 'scripts', 'package-contents-check.mjs')], { encoding: 'utf8', timeout: 180000 });
  assert.equal(gate.status, 0, `${gate.stdout}${gate.stderr}`.slice(-600));
  const pack = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: SCANNER, encoding: 'utf8', timeout: 180000 });
  assert.equal(pack.status, 0, pack.stderr.slice(-300));
  const files = JSON.parse(pack.stdout)[0].files.map((f) => f.path);
  const need = ['src/language/haskell-grammar.js', 'src/language/nix-grammar.js', 'src/language/haskell-parser.js', 'src/language/nix-parser.js', 'src/language/nixos-option-catalog.js',
    'src/language/resolved-pass.js', 'src/language/engine-pass.js', 'src/language/fix-lifecycle.js', 'dist/agentic-security.mjs', 'dist/agentic-security.mjs.sha256'];
  for (const f of need) assert.ok(files.includes(f), `the tarball lacks ${f}`);
  // every static import of a language module resolves to a packed file (no missing runtime asset)
  const missing = [];
  for (const f of files.filter((p) => /^src\/language\/.*\.js$/.test(p))) {
    for (const m of read(join(SCANNER, f)).matchAll(/from\s+'(\.[^']+)'/g)) {
      const target = join(dirname(f), m[1]).replace(/\\/g, '/');
      if (!files.includes(target)) missing.push(`${f} -> ${m[1]}`);
    }
  }
  assert.deepEqual(missing, [], 'a language module imports a file the tarball does not carry');
  assert.ok(!files.some((p) => /^test\/|(^|\/)\.agentic-security\/|\.log$/.test(p)), 'no test, state or log file is packed');
});

test('[QA-004.AC01] an installed tarball scans the Haskell and Nix examples exactly as the source does', () => {
  const work = mkdtempSync(join(tmpdir(), 'pkg-'));
  try {
    const packed = spawnSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', work], { cwd: SCANNER, encoding: 'utf8', timeout: 240000 });
    assert.equal(packed.status, 0, packed.stderr.slice(-300));
    const tgz = join(work, JSON.parse(packed.stdout)[0].filename);
    const x = spawnSync('tar', ['-xzf', tgz, '-C', work], { encoding: 'utf8' });
    assert.equal(x.status, 0, x.stderr);
    const installed = join(work, 'package', 'dist', 'agentic-security.mjs');
    assert.ok(existsSync(installed), 'the packed bundle exists');
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT; env.HOME = work;
    const ids = (bin, dir) => {
      const r = spawnSync(process.execPath, [bin, 'scan', dir, '--format', 'json', '--no-state'], { encoding: 'utf8', env, timeout: 240000, maxBuffer: 64 << 20 });
      assert.ok([0, 1, 2, 3].includes(r.status), `scan exit ${r.status}: ${r.stderr.slice(-300)}`);
      return JSON.parse(r.stdout).findings.filter((f) => /\.(hs|nix)$/.test(f.file)).map((f) => `${f.family}|${f.file}|${f.line}|${f.severity}`).sort();
    };
    for (const ex of ['haskell-app/vulnerable', 'haskell-app/partial', 'nixos-host/vulnerable', 'nixos-host/fixed', 'haskell-on-nix/vulnerable']) {
      const dir = join(work, ex.replace('/', '-')); cpSync(join(ROOT, 'examples', ex), dir, { recursive: true });
      const fromSrc = ids(join(SCANNER, 'bin', 'agentic-security.js'), dir);
      const fromPkg = ids(installed, dir);
      assert.deepEqual(fromPkg, fromSrc, `${ex}: the installed package and the source disagree (a stale bundle?)`);
      if (/vulnerable/.test(ex)) assert.ok(fromPkg.length >= 2, `${ex}: the installed package found nothing`);
    }
  } finally { rmSync(work, { recursive: true, force: true }); }
});

test('[QA-004.AC03] the tool-dependent parts degrade to a stated condition, not a crash, when the tools are absent', () => {
  const empty = mkdtempSync(join(tmpdir(), 'nopath-'));
  try {
    const dir = mkdtempSync(join(tmpdir(), 'pkg-ex-')); cpSync(join(ROOT, 'examples', 'haskell-app', 'fixed'), dir, { recursive: true });
    const env = { ...process.env, PATH: empty, HOME: dir }; delete env.NODE_TEST_CONTEXT;
    const r = spawnSync(process.execPath, [join(SCANNER, 'bin', 'agentic-security.js'), 'scan', dir, '--format', 'json', '--no-state'], { encoding: 'utf8', env, timeout: 240000, maxBuffer: 64 << 20 });
    assert.ok([0, 1, 2, 3].includes(r.status), r.stderr.slice(-300));
    const j = JSON.parse(r.stdout);
    assert.ok(j.scanHealth.languageCoverage.totals.analyzed >= 1, 'with no ghc, nix or python on PATH the static analysis still runs');
    rmSync(dir, { recursive: true, force: true });
  } finally { rmSync(empty, { recursive: true, force: true }); }
});
