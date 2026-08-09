// Package-contents release gate — unit tests for the pure decision logic.
//
// See scripts/package-contents-check.mjs for the full design rationale. Same
// shape as test/dependency-currency.test.js: the I/O path (npm pack
// --dry-run --json, git ls-files) is proven by hand, both directions, with
// captured exit codes, in the change report; these tests pin the decision
// logic on constructed inputs so a refactor cannot quietly loosen the check —
// in particular so the exact-vs-tolerance split (directories and forbidden
// patterns exact, file count toleranced) cannot blur.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  globToRegExp,
  pathsMatchingPattern,
  evaluatePackageContents,
} from '../../scripts/package-contents-check.mjs';

const EXPECTED = {
  topLevelDirectories: ['bin', 'dist', 'src'],
  forbiddenPatterns: [
    '**/.agentic-security/**',
    '**/*.log',
    '**/node_modules/**',
    '**/.env*',
    '**/.superpowers/**',
    '**/.claude/**',
  ],
  requiredFiles: ['dist/agentic-security.mjs', 'dist/agentic-security.mjs.sha256'],
  fileCount: { expected: 461, tolerance: 50 },
};

function entries(paths) {
  return paths.map(path => ({ path, size: 1 }));
}

function baselinePaths(n = 461) {
  const out = ['bin/agentic-security.js', 'dist/agentic-security.mjs', 'dist/agentic-security.mjs.sha256'];
  for (let i = out.length; i < n; i++) out.push(`src/module-${i}.js`);
  return out;
}

function facts(overrides = {}) {
  return {
    manifestEntries: entries(baselinePaths()),
    manifestError: null,
    expected: EXPECTED,
    expectedError: null,
    trackedSourceFiles: baselinePaths().filter(p => p.startsWith('src/') || p.startsWith('bin/')),
    ...overrides,
  };
}

// ------------------------------------------------------------- glob matching
test('package-contents — globToRegExp matches a nested state directory', () => {
  const re = globToRegExp('**/.agentic-security/**');
  assert.ok(re.test('src/.agentic-security/last-scan.json'));
  assert.ok(re.test('.agentic-security/foo'));
  assert.ok(!re.test('src/agentic-security-notes.md'));
});

test('package-contents — globToRegExp matches a suffix pattern anywhere', () => {
  const re = globToRegExp('**/*.log');
  assert.ok(re.test('dist/build.log'));
  assert.ok(re.test('build.log'));
  assert.ok(!re.test('dist/build.log.txt'));
});

test('package-contents — globToRegExp matches a dotfile-prefix pattern', () => {
  const re = globToRegExp('**/.env*');
  assert.ok(re.test('.env'));
  assert.ok(re.test('config/.env.production'));
  assert.ok(!re.test('config/environment.js'));
});

test('package-contents — pathsMatchingPattern returns only the matches', () => {
  const paths = ['src/a.js', 'src/x.log', 'dist/node_modules/y.js', 'src/b.js'];
  assert.deepEqual(pathsMatchingPattern(paths, '**/*.log'), ['src/x.log']);
  assert.deepEqual(pathsMatchingPattern(paths, '**/node_modules/**'), ['dist/node_modules/y.js']);
});

// --------------------------------------------------------------- unrunnable
test('package-contents — manifest generation failure is a hard failure, never a skip', () => {
  const r = evaluatePackageContents(facts({ manifestEntries: null, manifestError: 'npm pack exited 1' }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /npm pack exited 1/.test(e)));
});

test('package-contents — an empty manifest is a failure', () => {
  const r = evaluatePackageContents(facts({ manifestEntries: [] }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /no files/i.test(e)));
});

test('package-contents — an unreadable expectation file is a failure', () => {
  const r = evaluatePackageContents(facts({ expected: null, expectedError: 'ENOENT' }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /expected-package-manifest\.json/.test(e) && /ENOENT/.test(e)));
});

// ------------------------------------------------------------------ passing
test('package-contents — a clean, expected manifest passes', () => {
  const r = evaluatePackageContents(facts());
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
});

test('package-contents — one ordinary added source file passes (within tolerance)', () => {
  const paths = [...baselinePaths(), 'src/new-detector.js'];
  const r = evaluatePackageContents(facts({
    manifestEntries: entries(paths),
    trackedSourceFiles: paths.filter(p => p.startsWith('src/') || p.startsWith('bin/')),
  }));
  assert.equal(r.ok, true);
});

// -------------------------------------------------------------- directories
test('package-contents — a new top-level directory fails and is named', () => {
  const paths = [...baselinePaths(), 'extra/whatever.js'];
  const r = evaluatePackageContents(facts({ manifestEntries: entries(paths) }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /added: extra/.test(e)));
});

test('package-contents — removing dist/ from the package fails and names it as removed', () => {
  const paths = baselinePaths().filter(p => !p.startsWith('dist/'));
  const r = evaluatePackageContents(facts({
    manifestEntries: entries(paths),
    trackedSourceFiles: paths.filter(p => p.startsWith('src/') || p.startsWith('bin/')),
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /removed: dist/.test(e)));
  // The required-files check fires independently and names the exact files.
  assert.ok(r.errors.some(e => /Required file\(s\) missing/.test(e) && /dist\/agentic-security\.mjs/.test(e)));
});

// ---------------------------------------------------------- forbidden paths
test('package-contents — a stray .agentic-security file under src/ fails and names the path', () => {
  const paths = [...baselinePaths(), 'src/.agentic-security/stray.json'];
  const r = evaluatePackageContents(facts({
    manifestEntries: entries(paths),
    trackedSourceFiles: paths.filter(p => p.startsWith('src/') || p.startsWith('bin/')),
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e =>
    /forbidden pattern `\*\*\/\.agentic-security\/\*\*`/.test(e) &&
    /src\/\.agentic-security\/stray\.json/.test(e)));
});

test('package-contents — a stray log file fails independently of directory/count checks', () => {
  const paths = [...baselinePaths(), 'src/debug.log'];
  const r = evaluatePackageContents(facts({
    manifestEntries: entries(paths),
    trackedSourceFiles: paths.filter(p => p.startsWith('src/') || p.startsWith('bin/')),
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /\*\*\/\*\.log/.test(e) && /src\/debug\.log/.test(e)));
});

// -------------------------------------------------------------- file count
test('package-contents — 200 added files exceeds tolerance, fails, and names the added paths', () => {
  const added = Array.from({ length: 200 }, (_, i) => `src/junk-${i}.js`);
  const paths = [...baselinePaths(), ...added];
  const r = evaluatePackageContents(facts({
    manifestEntries: entries(paths),
    // trackedSourceFiles deliberately does NOT include the 200 new files —
    // they are untracked, exactly like a stray batch of generated files
    // would be before anyone commits them.
    trackedSourceFiles: baselinePaths().filter(p => p.startsWith('src/') || p.startsWith('bin/')),
  }));
  assert.equal(r.ok, false);
  const countError = r.errors.find(e => /Package file count is/.test(e));
  assert.ok(countError, 'expected a file-count error');
  assert.ok(/src\/junk-0\.js/.test(countError), 'the count error should name at least one added path');
  assert.ok(/dist\/ is generated/.test(countError));
});

test('package-contents — a file-count breach still fails when git tracking info is unavailable', () => {
  const added = Array.from({ length: 200 }, (_, i) => `src/junk-${i}.js`);
  const paths = [...baselinePaths(), ...added];
  const r = evaluatePackageContents(facts({ manifestEntries: entries(paths), trackedSourceFiles: null }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /Package file count is/.test(e)));
});

test('package-contents — missing fileCount config in the expectation file fails', () => {
  const r = evaluatePackageContents(facts({ expected: { ...EXPECTED, fileCount: {} } }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /no usable fileCount/.test(e)));
});

// ------------------------------------------------------------ multi-failure
test('package-contents — independent violations are all reported, not just the first', () => {
  const paths = [
    ...baselinePaths().filter(p => !p.startsWith('dist/')), // drop required files + a directory
    'src/.agentic-security/stray.json', // forbidden pattern
  ];
  const r = evaluatePackageContents(facts({
    manifestEntries: entries(paths),
    trackedSourceFiles: paths.filter(p => p.startsWith('src/') || p.startsWith('bin/')),
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /removed: dist/.test(e)));
  assert.ok(r.errors.some(e => /Required file\(s\) missing/.test(e)));
  assert.ok(r.errors.some(e => /forbidden pattern/.test(e)));
});
