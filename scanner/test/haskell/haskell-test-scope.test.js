// Test-component scope (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md, lever 1): a Haskell finding in a file that the package
// manifest assigns ONLY to a test-suite or benchmark component is lowered to `info`, with the stanza named. Decided from the manifest's
// `hs-source-dirs` (cabal) or `source-dirs` (hpack), never from a path name. Nine of the thirty fresh-set false positives are hspec suites
// whose in-process test applications echo a request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { testComponentIndex } from '../../src/language/haskell-manifests.js';
import { applyTestComponentScope } from '../../src/language/haskell-trust.js';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

const CABAL = `cabal-version: 2.4
name: echo
version: 0.1

common shared
    default-language: Haskell2010

library
    import: shared
    exposed-modules: Echo.Lib
    hs-source-dirs: src
    build-depends: base

executable echo
    main-is: Main.hs
    hs-source-dirs: app
    build-depends: base, echo

test-suite spec
    type: exitcode-stdio-1.0
    main-is: Spec.hs
    hs-source-dirs: Test
    build-depends: base, echo, hspec

benchmark bench
    type: exitcode-stdio-1.0
    main-is: Bench.hs
    hs-source-dirs: bench
    build-depends: base, echo
`;

test('testComponentIndex: the test-suite and benchmark directories a runtime component does not list are test-only', () => {
  const idx = testComponentIndex({ 'pkg/echo.cabal': CABAL });
  assert.equal(idx.reason, null);
  assert.deepEqual(idx.dirs.map((d) => d.dir).sort(), ['pkg/Test', 'pkg/bench']);
  assert.equal(idx.ownerOf('pkg/Test/Echo/ServerSpec.hs').component, 'spec');
  assert.equal(idx.ownerOf('pkg/Test/Echo/ServerSpec.hs').kind, 'test-suite');
  assert.equal(idx.ownerOf('pkg/bench/Bench.hs').kind, 'benchmark');
  assert.equal(idx.ownerOf('pkg/src/Echo/Lib.hs'), null);
  assert.equal(idx.ownerOf('pkg/app/Main.hs'), null);
  assert.equal(idx.ownerOf('other/Test/Spec.hs'), null, 'another package tree is not covered by this manifest');
});

test('a directory the library also lists is not test-only, and the root directory is never test-only', () => {
  const shared = CABAL.replace('hs-source-dirs: Test', 'hs-source-dirs: src');
  assert.equal(testComponentIndex({ 'pkg/echo.cabal': shared }).ownerOf('pkg/src/Spec.hs'), null);
  const root = CABAL.replace('hs-source-dirs: Test', 'hs-source-dirs: .');
  assert.equal(testComponentIndex({ 'pkg/echo.cabal': root }).ownerOf('pkg/Spec.hs'), null);
});

test('a library whose source directory is an ancestor of the test directory and whose module list is unknown keeps the file as runtime', () => {
  // hpack: a library with no exposed-modules exposes EVERY module under its source-dirs, including test/ when source-dirs is `.`
  const hpack = `name: echo\nlibrary:\n  source-dirs: .\n  dependencies: [base]\ntests:\n  spec:\n    main: Spec.hs\n    source-dirs: test\n    dependencies: [base, echo]\n`;
  assert.equal(testComponentIndex({ 'pkg/package.yaml': hpack }).ownerOf('pkg/test/Spec.hs'), null);
  // the same layout with the library's modules fully declared (hpack infers other-modules from the directory unless it is given): test/ holds
  // none of them, so it is test-only
  const declared = hpack.replace('  source-dirs: .\n', '  source-dirs: .\n  exposed-modules: [Echo.Lib]\n  other-modules: []\n');
  assert.equal(testComponentIndex({ 'pkg/package.yaml': declared }).ownerOf('pkg/test/Spec.hs').component, 'spec');
});

test('hpack tests: source-dirs as a string or a list, read into the component', () => {
  const hpack = `name: echo\nlibrary:\n  source-dirs: src\n  exposed-modules: [Echo.Lib]\ntests:\n  spec:\n    main: Spec.hs\n    source-dirs: [test, test-common]\n`;
  const idx = testComponentIndex({ 'pkg/package.yaml': hpack });
  assert.deepEqual(idx.dirs.map((d) => d.dir).sort(), ['pkg/test', 'pkg/test-common']);
});

test('a common stanza imported by the test-suite contributes its directories to the test-suite', () => {
  const withCommon = CABAL.replace('common shared\n    default-language: Haskell2010', 'common shared\n    default-language: Haskell2010\n    hs-source-dirs: shared-test').replace('test-suite spec\n', 'test-suite spec\n    import: shared\n');
  const idx = testComponentIndex({ 'pkg/echo.cabal': withCommon });
  // the library imports `shared` too, so shared-test is also a runtime directory: not test-only
  assert.equal(idx.ownerOf('pkg/shared-test/Helper.hs'), null);
  const onlyTest = withCommon.replace('library\n    import: shared\n', 'library\n');
  assert.equal(testComponentIndex({ 'pkg/echo.cabal': onlyTest }).ownerOf('pkg/shared-test/Helper.hs').component, 'spec');
});

test('a manifest that does not parse contributes nothing and says so', () => {
  const idx = testComponentIndex({ 'pkg/package.yaml': 'tests:\n  spec: [\n    source-dirs: t\n' });
  assert.deepEqual(idx.dirs, []);
  assert.notEqual(idx.reason, null);
  assert.equal(idx.ownerOf('pkg/t/Spec.hs'), null);
  const none = testComponentIndex({});
  assert.deepEqual(none.dirs, []); assert.equal(none.reason, 'no-manifest'); assert.equal(none.ownerOf('pkg/t/Spec.hs'), null);
});

test('applyTestComponentScope lowers a Haskell finding in a test-only directory to info and names the stanza; everything else is untouched', () => {
  const manifests = { 'pkg/echo.cabal': CABAL };
  const inTest = { file: 'pkg/Test/Echo/ServerSpec.hs', line: 14, severity: 'high', parser: 'IR-TAINT', cwe: 'CWE-79', vuln: 'Cross-Site Scripting' };
  const ruleInTest = { file: 'pkg/Test/Echo/TlsSpec.hs', line: 3, severity: 'high', parser: 'HS-RULES', cwe: 'CWE-295', vuln: 'TLS certificate validation is disabled' };
  const runtime = { file: 'pkg/src/Echo/Lib.hs', line: 9, severity: 'high', parser: 'IR-TAINT', cwe: 'CWE-79', vuln: 'Cross-Site Scripting' };
  const js = { file: 'pkg/Test/fixture.js', line: 1, severity: 'high', parser: 'SAST', cwe: 'CWE-79', vuln: 'XSS' };
  const already = { file: 'pkg/Test/Echo/Info.hs', line: 2, severity: 'info', parser: 'HS-RULES', cwe: 'CWE-676', vuln: 'Unsafe boundary' };
  const stats = applyTestComponentScope([inTest, ruleInTest, runtime, js, already], manifests);
  assert.equal(stats.lowered, 2);
  for (const f of [inTest, ruleInTest]) {
    assert.equal(f.severity, 'info');
    assert.equal(f.originalSeverity, 'high');
    assert.equal(f.guardNote.kind, 'test-component');
    assert.match(f.guardNote.reason, /test-suite 'spec'/);
    assert.match(f.guardNote.reason, /pkg\/echo\.cabal/);
    assert.deepEqual(f.componentScope, { kind: 'test-suite', component: 'spec', manifest: 'pkg/echo.cabal', dir: 'pkg/Test' });
    assert.ok(f.controls.some((c) => c.kind === 'test-component'));
  }
  assert.equal(runtime.severity, 'high'); assert.equal(runtime.componentScope, undefined);
  assert.equal(js.severity, 'high');
  assert.equal(already.severity, 'info'); assert.equal(already.originalSeverity, undefined, 'a finding already at info is not re-stamped');
  // idempotent: a second pass changes nothing
  assert.equal(applyTestComponentScope([inTest, ruleInTest, runtime], manifests).lowered, 0);
});

test('end to end: the same request echo is high in src/ and info in the manifest-declared test directory', async () => {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('hs-test-scope'), 'p-'));
  const ECHO = (mod) => `module ${mod} where
import Web.Scotty
import qualified Data.Text.Lazy as TL

app :: ScottyM ()
app = get "/hello" $ do
    name <- param "name"
    html (TL.concat ["<h1>", name, "</h1>"])
`;
  const files = {
    'echo.cabal': CABAL.replace('exposed-modules: Echo.Lib', 'exposed-modules: Echo.Lib, Echo.Web'),
    'src/Echo/Lib.hs': 'module Echo.Lib where\nlib :: Int\nlib = 1\n',
    'src/Echo/Web.hs': ECHO('Echo.Web'),
    'Test/Echo/ServerSpec.hs': ECHO('Echo.ServerSpec'),
    'app/Main.hs': 'module Main where\nimport Echo.Web (app)\nimport Web.Scotty\nmain :: IO ()\nmain = scotty 3000 app\n',
  };
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir);
  const xss = scan.findings.filter((f) => /\.hs$/.test(f.file) && f.cwe === 'CWE-79');
  const src = xss.filter((f) => f.file.startsWith('src/'));
  const tst = xss.filter((f) => f.file.startsWith('Test/'));
  assert.ok(src.length >= 1, JSON.stringify(xss.map((f) => [f.file, f.line, f.severity])));
  assert.ok(src.every((f) => f.severity !== 'info'), 'the shipped handler keeps its severity');
  assert.ok(tst.length >= 1, 'the test copy is still reported');
  assert.ok(tst.every((f) => f.severity === 'info' && f.guardNote && f.guardNote.kind === 'test-component'), JSON.stringify(tst.map((f) => [f.line, f.severity, f.guardNote])));
});
