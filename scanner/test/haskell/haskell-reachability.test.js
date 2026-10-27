// Caller-aware reachability for Haskell, pinned in BOTH directions. Every case is a pair that differs by one fact, because a verdict that is right only
// on one side is a coincidence. The sources are written for this file; none is copied from a corpus case or a project.
//
// The rule under test (haskell-ir.js `projectReachability`): a function gets `unreachable-in-project` only when the scan is complete, the call graph has
// no hole, an entry point exists, a manifest says which modules the package exposes, the function's module is not one of them, it is not an instance
// method, and nothing reachable from a root reaches it. Anything less is `unknown`, with the reason named. A negative verdict lowers a finding to `info`
// only when the finding rests on a caller-supplied parameter (the premise a missing caller withdraws); it never drops one.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runScan } from '../../src/runScan.js';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { mkTestTmp } from '../helpers/tmp.js';

const hs = (header, imports, body) => `${header}\n\n${imports.join('\n')}\n\n${body}\n`;

// A package with a library and an executable. `Svc.unpackIt` builds a command around a caller-supplied parameter and nothing calls it.
const SVC_BODY = (m) => hs(`module ${m} (unpackIt) where`, ['import System.Process'], 'unpackIt :: String -> IO ()\nunpackIt name = callCommand ("tar xf " ++ name ++ " -C /srv/data")');
const MAIN = hs('module Main (main) where', ['import Svc ()'], 'main :: IO ()\nmain = putStrLn "ready"');
const OTHER = 'module Other (other) where\n\nother :: Int\nother = 1\n';
const cabal = (exposed, extra = '') => `cabal-version: 2.4
name: p
version: 0.1.0.0
build-type: Simple

library
  exposed-modules: ${exposed}
  other-modules: Svc
  hs-source-dirs: src
  build-depends: base, process
  default-language: Haskell2010
${extra}
executable p
  main-is: Main.hs
  hs-source-dirs: app
  build-depends: base, p
  default-language: Haskell2010
`;

async function scanAll(files, opts = {}) {
  const dir = mkTestTmp('hs-reach-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true, ...opts });
  return [...(r.scan.findings || [])];
}
const taint = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && (!cwe || f.cwe === cwe));
// a finding a default scan would flag: not lowered to info
const flagged = (fs, cwe) => taint(fs, cwe).filter((f) => f.severity !== 'info');
const one = (fs, cwe) => { const t = taint(fs, cwe); assert.equal(t.length, 1, JSON.stringify(t.map((f) => [f.file, f.line, f.severity, f.reachability && f.reachability.status]))); return t[0]; };

// ── 1. the verdict, and the one word of manifest text that flips it ──────────

test('verdict: the same uncalled function is external-api when its module is exposed and unreachable-in-project when it is not', async () => {
  const exposed = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN, 'p.cabal': cabal('Svc') });
  const e = one(exposed, 'CWE-78');
  assert.equal(e.reachability.status, 'external-api');
  assert.notEqual(e.severity, 'info', 'a public API\'s callers are outside the analysed code: the finding stays');
  assert.equal(e.originalSeverity, undefined);

  const hidden = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN, 'p.cabal': cabal('Other') });
  const h = one(hidden, 'CWE-78');
  assert.equal(h.reachability.status, 'unreachable-in-project');
  assert.equal(h.reachability.premise, 'caller-controlled-parameter');
  assert.equal(h.severity, 'info', 'the only premise (a caller supplies the parameter) is withdrawn: nothing in the project can call it');
  assert.ok(['critical', 'high'].includes(h.originalSeverity), `the severity it would have had is kept: ${h.originalSeverity}`);
  assert.ok((h.controls || []).some((c) => c.kind === 'no-caller-in-project'), JSON.stringify(h.controls));
  assert.equal(h._reachLowered, true);
});

test('verdict: a reached function is entrypoint-reachable and keeps its severity; the same function with its only call removed is not', async () => {
  const calls = hs('module Main (main) where', ['import Svc (unpackIt)'], 'main :: IO ()\nmain = unpackIt "x.tar"');
  const called = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': calls, 'p.cabal': cabal('Other') });
  // `main` hands the function a constant, so the call chain is what the taint engine follows; the function itself is reached
  const ir = buildHaskellIR({ 'src/Svc.hs': SVC_BODY('Svc'), 'app/Main.hs': calls }, { manifests: { 'p.cabal': cabal('Other') }, completeScan: true });
  const fn = [...ir.callGraph.functions.values()].find((f) => f.name === 'Svc.unpackIt');
  assert.equal(fn.hs.reachability.status, 'entrypoint-reachable');
  assert.equal(fn.hs.reachedBy, 'call');
  assert.ok(fn.hs.paramEntry.every((p) => p.reach === 'called-in-project'));
  assert.equal(taint(called, 'CWE-78').filter((f) => f.reachability && f.reachability.status === 'unreachable-in-project').length, 0);
});

// ── 2. a library is never zeroed ─────────────────────────────────────────────

test('library: no entry point, or no manifest, is unknown (never unreachable), and the finding is untouched', async () => {
  const noMain = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'p.cabal': cabal('Other') });
  const a = one(noMain, 'CWE-78');
  assert.equal(a.reachability.status, 'unknown');
  assert.equal(a.reachability.holeReason, 'no-entrypoint');
  assert.notEqual(a.severity, 'info');
  assert.equal(a.originalSeverity, undefined);

  const noCabal = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'app/Main.hs': MAIN });
  const b = one(noCabal, 'CWE-78');
  assert.equal(b.reachability.status, 'unknown');
  assert.equal(b.reachability.holeReason, 'no-manifest');
  assert.notEqual(b.severity, 'info');

  const neither = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc') });
  const c = one(neither, 'CWE-78');
  assert.equal(c.reachability.status, 'unknown');
  assert.equal(c.reachability.holeReason, 'no-entrypoint');
  assert.notEqual(c.severity, 'info');
});

// ── 3. a reachable request handler is attacker-reachable and flagged ─────────

test('reachable: a Scotty route that hands a request parameter to removeFile is entrypoint-reachable, attacker-reachable and flagged', async () => {
  const app = hs('module Main (main) where', ['{-# LANGUAGE OverloadedStrings #-}', 'import Web.Scotty', 'import System.Directory', 'import Control.Monad.IO.Class (liftIO)'], 'main :: IO ()\nmain = scotty 3000 $ post "/purge/:f" $ do\n  f <- param "f"\n  liftIO (removeFile f)\n  text "ok"');
  const cb = `cabal-version: 2.4
name: p
version: 0.1.0.0
executable p
  main-is: Main.hs
  hs-source-dirs: app
  build-depends: base, scotty, directory
`;
  const fs = await scanAll({ 'app/Main.hs': app, 'p.cabal': cb });
  const f = flagged(fs, 'CWE-22');
  assert.equal(f.length, 1, JSON.stringify(taint(fs).map((x) => [x.cwe, x.severity, x.reachability])));
  assert.equal(f[0].reachability.status, 'entrypoint-reachable');
  assert.equal(f[0].trustBoundary.verdict, 'attacker-reachable');
  assert.equal(f[0].reachability.premise, 'recorded-read');
});

// ── 4. a hole is unknown, never unreachable ──────────────────────────────────

const status = (files, opts = {}, name = 'Svc.unpackIt') => {
  const ir = buildHaskellIR(files, { completeScan: true, ...opts });
  const fn = [...ir.callGraph.functions.values()].find((f) => f.name === name);
  assert.ok(fn, `${name} is lowered`);
  return { ir, r: fn.hs.reachability };
};
const manifests = (exposed = 'Other') => ({ 'p.cabal': cabal(exposed) });

test('holes: the control (no hole) is unreachable-in-project, so each of the cases below changes exactly one thing', () => {
  const { r, ir } = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN }, { manifests: manifests() });
  assert.equal(r.status, 'unreachable-in-project');
  assert.equal(ir.haskellReachability.graphComplete, true);
  assert.deepEqual(ir.haskellReachability.holes, []);
  assert.equal(ir.haskellReachability.entrypointCount, 1);
  assert.deepEqual(ir.haskellReachability.exposedModules, ['Other']);
});

test('holes: partial-scan. A subset of the project proves nothing about callers (changed-file, pull-request, caller-supplied scans)', async () => {
  const files = { 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN };
  const { r } = status(files, { manifests: manifests(), completeScan: false });
  assert.equal(r.status, 'unknown');
  assert.equal(r.holeReason, 'partial-scan');
  // and through the real entry point: a caller-supplied file list is a subset by construction
  const dir = mkTestTmp('hs-reach-partial-');
  writeFileSync(join(dir, 'package.json'), '{}');
  const run = await runScan(dir, { deep: true, fileContents: files, depFileContents: { 'p.cabal': cabal('Other') } });
  const f = taint(run.scan.findings || [], 'CWE-78');
  assert.equal(f.length, 1);
  assert.equal(f[0].reachability.status, 'unknown');
  assert.equal(f[0].reachability.holeReason, 'partial-scan');
  assert.notEqual(f[0].severity, 'info', 'a partial scan must never mass-demote');
});

test('holes: unresolved-call. A name nothing defines or imports on a reached path could be a definition the IR never saw', () => {
  const mystery = hs('module Main (main) where', ['import Svc ()'], 'main :: IO ()\nmain = mysteryAction 3');
  const { r, ir } = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': mystery }, { manifests: manifests() });
  assert.equal(r.status, 'unknown');
  assert.equal(r.holeReason, 'unresolved-call');
  assert.equal(ir.haskellReachability.graphComplete, false);
  // a call through a function VALUE is not a hole: its callee must have been named somewhere, and every such mention is a reference the walk follows
  const viaValue = hs('module Main (main) where', ['import Svc ()'], 'apply :: (Int -> IO ()) -> IO ()\napply f = f 3\n\nmain :: IO ()\nmain = apply print');
  assert.equal(status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': viaValue }, { manifests: manifests() }).r.status, 'unreachable-in-project');
});

test('holes: function-cap. Functions past the per-file cap are not in the graph', () => {
  const many = `module Many (m0) where\n\n${Array.from({ length: 5003 }, (_, i) => `m${i} :: Int\nm${i} = ${i}`).join('\n')}\n`;
  const { r, ir } = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Many.hs': many, 'app/Main.hs': MAIN }, { manifests: manifests('Many') });
  assert.equal(ir.haskellReachability.holes.some((h) => h.reason === 'function-cap'), true);
  assert.equal(r.status, 'unknown');
  assert.equal(r.holeReason, 'function-cap');
});

test('holes: opaque-boundary. A Template Haskell splice, or a foreign export, can call anything', () => {
  const th = `{-# LANGUAGE TemplateHaskell #-}\nmodule Gen (gen) where\n\nimport Language.Haskell.TH\n\ngen :: Int\ngen = 1\n\n$(return [])\n`;
  const t = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Gen.hs': th, 'app/Main.hs': MAIN }, { manifests: manifests('Gen') });
  assert.equal(t.r.status, 'unknown');
  assert.equal(t.r.holeReason, 'opaque-boundary');
  const ffi = `{-# LANGUAGE ForeignFunctionInterface #-}\nmodule Ffi (entry) where\n\nentry :: Int -> Int\nentry x = x + 1\n\nforeign export ccall "hs_entry" entry :: Int -> Int\n`;
  const f = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Ffi.hs': ffi, 'app/Main.hs': MAIN }, { manifests: manifests('Other') });
  assert.equal(f.r.status, 'unknown');
  assert.equal(f.r.holeReason, 'opaque-boundary');
  assert.equal(f.ir.haskellReachability.rootKinds['foreign-export'], 1, 'the exported function is a root');
  // the same TH-free project is not
  assert.equal(status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Gen.hs': th.replace('$(return [])\n', ''), 'app/Main.hs': MAIN }, { manifests: manifests('Gen') }).r.status, 'unreachable-in-project');
});

test('holes: code the parser withheld can only call what its own module can see, so that neighbourhood is reached and the rest is still judged', () => {
  const broken = hs('module Broken (go) where', ['import Svc'], 'go :: Int\ngo = 1\n\n@@@ this line is not Haskell @@@');
  const s = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Broken.hs': broken, 'src/Other.hs': OTHER, 'app/Main.hs': MAIN }, { manifests: manifests() });
  assert.equal(s.r.status, 'entrypoint-reachable', 'Svc is imported by the module whose code was withheld: it may be called from there');
  assert.equal(s.r.rootKind, 'withheld-caller');
  // a function the broken module cannot see is judged as before
  const lone = hs('module Lone (lone) where', [], 'lone :: String -> IO ()\nlone s = putStrLn s');
  const t = status({ 'src/Lone.hs': lone, 'src/Broken.hs': broken, 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN }, { manifests: manifests() }, 'Lone.lone');
  assert.equal(t.r.status, 'unreachable-in-project');
});

test('holes: a class default method body is not lowered, so what it calls is not judged dead; the same class without the default body is judged', () => {
  const withDefault = hs('module Render (Render(..)) where', [], 'class Render a where\n  render :: a -> String\n  render _ = helper "x"\n\nhelper :: String -> String\nhelper s = s');
  const without = hs('module Render (Render(..)) where', [], 'class Render a where\n  render :: a -> String\n\nhelper :: String -> String\nhelper s = s');
  const files = (src) => ({ 'src/Render.hs': src, 'src/Other.hs': OTHER, 'app/Main.hs': hs('module Main (main) where', ['import Render ()'], 'main :: IO ()\nmain = putStrLn "x"') });
  const a = status(files(withDefault), { manifests: manifests() }, 'Render.helper');
  assert.equal(a.r.status, 'entrypoint-reachable');
  assert.equal(a.r.rootKind, 'withheld-caller');
  assert.equal(status(files(without), { manifests: manifests() }, 'Render.helper').r.status, 'unreachable-in-project');
});

test('holes: a function reached only through a higher-order chain is reached, never unreachable', () => {
  const chain = hs('module Main (main) where', ['import Svc (unpackIt)'], 'twice :: (String -> IO ()) -> String -> IO ()\ntwice f x = f x >> f x\n\nrunAll :: [String -> IO ()] -> IO ()\nrunAll fs = mapM_ (\\f -> twice f "a.tar") fs\n\nmain :: IO ()\nmain = runAll [unpackIt]');
  const s = status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': chain }, { manifests: manifests() });
  assert.equal(s.r.status, 'entrypoint-reachable');
  const unused = hs('module Main (main) where', ['import Svc (unpackIt)'], 'twice :: (String -> IO ()) -> String -> IO ()\ntwice f x = f x >> f x\n\nrunAll :: [String -> IO ()] -> IO ()\nrunAll fs = mapM_ (\\f -> twice f "a.tar") fs\n\nmain :: IO ()\nmain = runAll []');
  assert.equal(status({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': unused }, { manifests: manifests() }).r.status, 'unreachable-in-project', 'the same shape without the reference is judged');
});

// ── 5. platform variants stay reached ────────────────────────────────────────

test('platform variants: both modules an undecided import could mean are referenced, so neither is unreachable', () => {
  const body = (m) => hs(`module ${m} (readLog) where`, ['import System.Directory'], 'readLog :: FilePath -> IO String\nreadLog name = readFile ("/var/log/tool/" ++ name)');
  const files = {
    'src/Plat/Posix.hs': body('Plat.Posix'),
    'src/Plat/Windows.hs': body('Plat.Windows'),
    'src/Plat.hs': '{-# LANGUAGE CPP #-}\nmodule Plat (readLog) where\n\n#if defined(PLATFORM_IS_WINDOWS)\nimport Plat.Windows\n#else\nimport Plat.Posix\n#endif\n',
    'app/Main.hs': hs('module Main (main) where', ['import Plat'], 'main :: IO ()\nmain = readLog "today.log" >>= putStr'),
  };
  const ir = buildHaskellIR(files, { manifests: { 'p.cabal': 'name: p\nexecutable p\n  main-is: Main.hs\n  hs-source-dirs: app\n  build-depends: base\n' }, completeScan: true });
  for (const m of ['Plat.Posix.readLog', 'Plat.Windows.readLog']) {
    const fn = [...ir.callGraph.functions.values()].find((f) => f.name === m);
    assert.notEqual(fn.hs.reachability.status, 'unreachable-in-project', m);
    assert.equal(fn.hs.reachedBy, 'reference', m);
    assert.ok(fn.hs.paramEntry === undefined || fn.hs.paramEntry.every((p) => p.reach === 'referenced-only'), m);
  }
  // the bookkeeping keeps the record the removal destroyed, and the removal itself is unchanged: a reached function has no source annotations
  const posix = [...ir.callGraph.functions.values()].find((f) => f.name === 'Plat.Posix.readLog');
  assert.equal(posix.paramAnnotations, undefined);
  assert.ok(Array.isArray(posix.hs.paramEntry) && posix.hs.paramEntry[0].name === 'name');
  // the same function with nothing referencing it is an entry point whose callers are unknown
  const orphan = buildHaskellIR({ 'src/Plat/Posix.hs': body('Plat.Posix') });
  const o = [...orphan.callGraph.functions.values()].find((f) => f.name === 'Plat.Posix.readLog');
  assert.equal(o.hs.reachedBy, null);
  assert.equal(o.hs.paramEntry[0].reach, 'entry');
  assert.ok(Array.isArray(o.paramAnnotations) && o.paramAnnotations.length === 1);
});

// ── 6. instance methods ──────────────────────────────────────────────────────

test('instance methods: callable by anything that can see the type, so unknown/instance-method; an ordinary function beside one is judged', () => {
  const lib = hs('module Render (Shape(..), describe, helper) where', [], 'class Render a where\n  render :: a -> String\n\ndata Shape = Shape String\n\ninstance Render Shape where\n  render (Shape s) = helper s\n\nhelper :: String -> String\nhelper s = s\n\ndescribe :: String -> String\ndescribe s = s ++ "!"');
  const s = status({ 'src/Render.hs': lib, 'src/Other.hs': OTHER, 'app/Main.hs': hs('module Main (main) where', ['import Render ()'], 'main :: IO ()\nmain = putStrLn "x"') }, { manifests: manifests() }, 'Render.$inst.Render.render');
  assert.equal(s.r.status, 'unknown');
  assert.equal(s.r.holeReason, 'instance-method');
  const ordinary = [...s.ir.callGraph.functions.values()].find((f) => f.name === 'Render.describe');
  assert.equal(ordinary.hs.reachability.status, 'unreachable-in-project');
  // what an instance method calls is reached (it is a root), so the helper is not judged dead
  const helper = [...s.ir.callGraph.functions.values()].find((f) => f.name === 'Render.helper');
  assert.equal(helper.hs.reachability.status, 'entrypoint-reachable');
});

// ── 7. nothing here reads a name, a path or a comment ────────────────────────

test('no answer-key signal: renaming the module and its directory changes nothing; a commented-out manifest line is not a declaration', async () => {
  const plain = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN, 'p.cabal': cabal('Other') });
  const renamed = await scanAll({ 'lib/vulnerable/Vulnerable.hs': SVC_BODY('Vulnerable'), 'lib/vulnerable/Other.hs': OTHER, 'app/Main.hs': MAIN.replace('import Svc ()', 'import Vulnerable ()'), 'p.cabal': cabal('Other').replace('hs-source-dirs: src', 'hs-source-dirs: lib/vulnerable').replace('other-modules: Svc', 'other-modules: Vulnerable') });
  const a = one(plain, 'CWE-78'); const b = one(renamed, 'CWE-78');
  assert.deepEqual([b.reachability.status, b.reachability.premise, b.reachability.holeReason, b.severity, b.originalSeverity], [a.reachability.status, a.reachability.premise, a.reachability.holeReason, a.severity, a.originalSeverity]);
  assert.equal(b.reachability.status, 'unreachable-in-project');
  // `-- exposed-modules: Svc` is a comment: the verdict is the not-exposed one. The same text as a real field is the exposed one.
  const commented = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN, 'p.cabal': cabal('Other', '  -- exposed-modules: Svc\n') });
  assert.equal(one(commented, 'CWE-78').reachability.status, 'unreachable-in-project');
  const real = await scanAll({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN, 'p.cabal': cabal('Other, Svc') });
  assert.equal(one(real, 'CWE-78').reachability.status, 'external-api');
});

test('manifests: exposed-modules is read per component, a build that overrides the entry point or generates code is unknown, an hpack library that exposes every module is unknown', () => {
  const run = (cb, extra = {}) => buildHaskellIR({ 'src/Svc.hs': SVC_BODY('Svc'), 'src/Other.hs': OTHER, 'app/Main.hs': MAIN }, { manifests: { 'p.cabal': cb, ...extra }, completeScan: true }).haskellReachability;
  assert.deepEqual(run(cabal('Other')).exposedModules, ['Other']);
  assert.deepEqual(run(cabal('Other\n    Svc')).exposedModules, ['Other', 'Svc'], 'one name per line');
  assert.equal(run(cabal('Other').replace('build-depends: base, p', 'build-depends: base, p\n  ghc-options: -main-is Main.run')).exposedModules, null, 'an entry-point override: the roots are not the ones the IR found');
  assert.equal(run(cabal('Other').replace('hs-source-dirs: src', 'hs-source-dirs: src\n  build-tool-depends: alex:alex')).exposedModules, null, 'a build step that generates modules');
  const hpackAll = buildHaskellIR({ 'src/Svc.hs': SVC_BODY('Svc'), 'app/Main.hs': MAIN }, { manifests: { 'package.yaml': 'name: p\nlibrary:\n  source-dirs: src\nexecutables:\n  p:\n    main: Main.hs\n    source-dirs: app\n' }, completeScan: true }).haskellReachability;
  assert.equal(hpackAll.exposedModules, null, 'an hpack library with no exposed-modules exposes everything under its source dirs');
  const hpackListed = buildHaskellIR({ 'src/Svc.hs': SVC_BODY('Svc'), 'app/Main.hs': MAIN }, { manifests: { 'package.yaml': 'name: p\nlibrary:\n  source-dirs: src\n  exposed-modules:\n    - Other\nexecutables:\n  p:\n    main: Main.hs\n    source-dirs: app\n' }, completeScan: true }).haskellReachability;
  assert.deepEqual(hpackListed.exposedModules, ['Other']);
  // an executable-only package exposes nothing, which is an answer and not a gap
  assert.deepEqual(run('name: p\nexecutable p\n  main-is: Main.hs\n  hs-source-dirs: app\n  build-depends: base\n').exposedModules, []);
});

test('re-exports: a module the package exposes carries the modules it re-exports with it', () => {
  const files = {
    'src/Svc.hs': SVC_BODY('Svc'),
    'src/Facade.hs': 'module Facade (module Svc) where\n\nimport Svc\n',
    'src/Other.hs': OTHER,
    'app/Main.hs': MAIN,
  };
  const via = buildHaskellIR(files, { manifests: manifests('Facade'), completeScan: true });
  const fn = [...via.callGraph.functions.values()].find((f) => f.name === 'Svc.unpackIt');
  assert.equal(fn.hs.reachability.status, 'external-api', 'Svc is not listed, but Facade re-exports it');
  const direct = buildHaskellIR(files, { manifests: manifests('Other'), completeScan: true });
  assert.equal([...direct.callGraph.functions.values()].find((f) => f.name === 'Svc.unpackIt').hs.reachability.status, 'unreachable-in-project');
});

test('framework handlers are roots even when the route table is in a file the IR never sees', () => {
  const handler = hs('module Handlers (getFooR) where', ['import Yesod'], 'getFooR :: Handler Text\ngetFooR = return "foo"');
  const ir = buildHaskellIR({ 'src/Handlers.hs': handler, 'app/Main.hs': MAIN }, { manifests: { 'p.cabal': 'name: p\nexecutable p\n  main-is: Main.hs\n  hs-source-dirs: app\n  build-depends: base\n' }, completeScan: true });
  const fn = [...ir.callGraph.functions.values()].find((f) => f.name === 'Handlers.getFooR');
  assert.equal(fn.hs.reachability.status, 'entrypoint-reachable');
  assert.equal(fn.hs.reachability.rootKind, 'framework-handler');
});
