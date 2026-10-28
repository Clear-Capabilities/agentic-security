// Haskell in the proof fabric (PRD 1): the toolchain probe, reproducer generation from a finding (what it builds, what it refuses by
// name), and, with a working GHC and the sandbox, that a generated reproducer is CONFIRMED on vulnerable code and NOT confirmed on the
// fixed twin by the unchanged proof machinery, plus a hand-written reproducer judged by the same oracle. Execution tests skip, loudly,
// when ghc is absent or cannot run in this host's sandbox; they never pass vacuously.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { generateReproducer } from '../../src/posture/proof-fabric/generate.js';
import { generateHaskellReproducer, bootModuleSet } from '../../src/posture/proof-fabric/generate-haskell.js';
import { proveFinding } from '../../src/posture/proof-fabric/orchestrator.js';
import { validateReproducer, substitute, LANGUAGES } from '../../src/posture/proof-fabric/reproducer.js';
import { hostTools, languageSupport, selectEnvironment, runAttempt } from '../../src/posture/proof-fabric/runner.js';
import { CONTAINER_TOOLS } from '../../src/posture/proof-fabric/container.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { skipUnlessRuns } from '../helpers/toolchain-probe.js';

const tools = hostTools();
const skipNoGhc = tools.ghc && tools.runghc ? false : 'ghc/runghc are not installed on this host (execution and import-classification tests are skipped, not passed)';
const skipExec = skipNoGhc || (!sandboxAvailable() ? 'no confinement backend on this host' : skipUnlessRuns('haskell'));
const repo = (files) => { const d = mkTestTmp('gen-hs-'); for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), c); } return d; };
const F = (over = {}) => ({ id: 'H1', stableId: 'H1', cwe: 'CWE-78', file: 'Main.hs', line: 13, parser: 'IR-TAINT', ...over });
const prove = (finding, dir, reproducer) => proveFinding({ finding, reproducer, sourceRoot: dir, policy: { timeoutMs: 30000 } });
const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/proof-fabric');
const fixture = (cls, side) => fs.readFileSync(path.join(FIX, cls, side, 'Main.hs'), 'utf8');

// sources (line numbers are what the engine reports: the sink line)
const FN_VULN = 'module Label (makeLabel) where\n\nimport System.Process (callCommand)\n\nmakeLabel :: String -> IO ()\nmakeLabel name = callCommand ("echo label " ++ name)\n';
const FN_SAFE = 'module Label (makeLabel) where\n\nimport System.Process (callProcess)\n\nmakeLabel :: String -> IO ()\nmakeLabel name = callProcess "echo" ["label", name]\n';
const WRITE_VULN = 'module Store (save) where\n\nimport System.Directory (createDirectoryIfMissing)\n\nsave :: FilePath -> IO ()\nsave name = do\n  createDirectoryIfMissing True "public"\n  writeFile ("public/" ++ name) "x"\n';
const WRITE_SAFE = 'module Store (save) where\n\nimport System.Directory (createDirectoryIfMissing)\nimport System.FilePath (takeFileName)\n\nsave :: FilePath -> IO ()\nsave name = do\n  createDirectoryIfMissing True "public"\n  writeFile ("public/" ++ takeFileName name) "x"\n';

// ---------------------------------------------------------------------------------------------------------------- toolchain

test('haskell is a language of the fabric and needs ghc and runghc', () => {
  assert.ok(LANGUAGES.includes('haskell'));
  assert.deepEqual(validateReproducer({ schema: 'agentic-security/reproducer', version: 1, findingId: 'x', lang: 'haskell', files: { 'Main.hs': 'main = pure ()' }, run: ['{{GHC}}', '-e', 'main', 'Main.hs'], oracle: { type: 'command_execution', params: { canary: 'command' } } }), []);
  assert.deepEqual(languageSupport('haskell', { ghc: '/x/ghc', runghc: '/x/runghc' }), { supported: true, reason: null });
  assert.deepEqual(languageSupport('haskell', { ghc: null, runghc: '/x/runghc' }), { supported: false, reason: 'missing toolchain: ghc' });
  assert.deepEqual(languageSupport('haskell', {}), { supported: false, reason: 'missing toolchain: ghc, runghc' });
});

test('{{GHC}} and {{RUNGHC}} are substituted from the toolchain, left alone when it is missing', () => {
  const ctx = (t) => ({ tools: t, nonce: 'n', root: '/r', canary: () => 'c', secret: () => 's' });
  assert.equal(substitute('{{GHC}} {{RUNGHC}}', ctx({ ghc: '/g', runghc: '/rg' })), '/g /rg');
  assert.equal(substitute('{{GHC}}', ctx({})), '{{GHC}}');
});

test('a launcher that exists is not a toolchain that works: a stub ghc that fails its version probe is ignored', () => {
  const dir = mkTestTmp('stub-ghc-');
  for (const n of ['ghc', 'runghc']) { fs.writeFileSync(path.join(dir, n), '#!/bin/sh\necho "install the Haskell toolchain" >&2\nexit 1\n'); fs.chmodSync(path.join(dir, n), 0o755); }
  const saved = process.env.PATH;
  process.env.PATH = dir;
  try {
    const t = hostTools();
    assert.equal(t.ghc, null); assert.equal(t.runghc, null);
    assert.equal(languageSupport('haskell', t).supported, false);
  } finally { process.env.PATH = saved; }
});

test('the container side: the image is a local-only name, the tools are the image\'s own names', () => {
  assert.equal(CONTAINER_TOOLS.ghc, 'ghc'); assert.equal(CONTAINER_TOOLS.runghc, 'runghc');
  const e = selectEnvironment({ lang: 'haskell', docker: { bin: '/nonexistent/docker', probe: (_bin, image) => ({ ok: image === 'haskell:9', imageId: `sha256:${'a'.repeat(64)}` }) } });
  assert.equal(e.mode, 'container'); assert.equal(e.image, 'haskell:9');
});

// ---------------------------------------------------------------------------------------------------------------- refusals

test('class and file refusals need no GHC: SSRF is refused for Haskell with its reason, other classes by name, reads and hazards by reason', () => {
  const refuse = (files, finding, re) => { const r = generateReproducer({ finding: F(finding), root: repo(files) }); assert.equal(r.ok, false, JSON.stringify(r)); assert.match(r.reason, re); };
  refuse({ 'Main.hs': fixture('command-injection-haskell', 'vulnerable') }, { cwe: 'CWE-918' }, /no HTTP client ships with GHC/);
  refuse({ 'Main.hs': fixture('command-injection-haskell', 'vulnerable') }, { cwe: 'CWE-89' }, /sql-injection: the flagged line `callCommand \("echo hello " \+\+ name\)`.*GHC ships no database binding/);
  refuse({ 'Main.hs': fixture('command-injection-haskell', 'vulnerable') }, { cwe: 'CWE-88' }, /argument-injection: the flagged line is not a call to callProcess/);
  refuse({ 'Main.hs': 'module Main (main) where\nmain :: IO ()\nmain = readFile "x" >>= putStrLn\n' }, { cwe: 'CWE-22', line: 3 }, /base directory is not a relative literal/);
  refuse({ 'Main.hs': 'module Main (main) where\nimport System.Directory (removeFile)\nmain :: IO ()\nmain = removeFile "x"\n' }, { cwe: 'CWE-22', line: 4 }, /is not a write \(writeFile.*or a read \(readFile.*removeFile, createDirectory/);
  refuse({ 'Main.hs': '{-# LANGUAGE TemplateHaskell #-}\nmodule Main (main) where\nimport System.Process (callCommand)\nmain :: IO ()\nmain = callCommand "ls"\n' }, { line: 5 }, /Template Haskell, quasi-quotes, CPP or the foreign function interface/);
  refuse({ 'Main.hs': '{-# OPTIONS_GHC -fplugin=Evil #-}\nmodule Main (main) where\nmain :: IO ()\nmain = pure ()\n' }, { line: 4 }, /OPTIONS_GHC pragma names a plugin/);
  refuse({ 'Main.hs': 'module Main (main) where\nforeign import ccall "sin" c_sin :: Double -> Double\nmain :: IO ()\nmain = pure ()\n' }, { line: 3 }, /foreign function interface/);
  refuse({ 'Main.hs': 'x' }, { file: 'Missing.hs' }, /missing, outside the repository/);
  refuse({ 'Main.hs': 'x' }, { line: undefined }, /no line number/);
});

test('imports outside the packages that ship with GHC are refused with the package named', { skip: skipNoGhc }, () => {
  const refuse = (src, re, finding = {}) => { const r = generateReproducer({ finding: F({ line: 4, ...finding }), root: repo({ 'Main.hs': src }) }); assert.equal(r.ok, false, JSON.stringify(r)); assert.match(r.reason, re); return r; };
  // the engine's own Haskell example: a Scotty handler over a SQLite binding
  const r = refuse('module Main (main) where\nimport Web.Scotty\nimport Database.SQLite.Simple\nmakeLabel :: String -> IO ()\nmakeLabel n = pure ()\n', /needs scotty, sqlite-simple, which is not available/);
  assert.deepEqual(r.missing.sort(), ['scotty', 'sqlite-simple']);
  refuse('module Main (main) where\nimport Data.Aeson\nmain :: IO ()\nmain = pure ()\n', /needs aeson/);
  refuse('module Main (main) where\nimport Some.Unknown.Thing\nmain :: IO ()\nmain = pure ()\n', /needs Some\.Unknown\.Thing/);
  refuse('module Main (main) where\nimport "scotty" Web.Scotty\nmain :: IO ()\nmain = pure ()\n', /needs scotty/);
  // the same SSRF-shaped program: the class is refused before any package question
  assert.match(generateReproducer({ finding: F({ cwe: 'CWE-918', line: 4 }), root: repo({ 'Main.hs': 'module Main (main) where\nimport Network.HTTP.Simple\nmain :: IO ()\nmain = pure ()\n' }) }).reason, /no HTTP client ships with GHC/);
});

test('function-shape refusals name the reason: not in a function, no signature, not IO, a parameter that cannot be filled, constrained, no parameters', { skip: skipNoGhc }, () => {
  const sig = (s, body = 'f x = callCommand x\n') => `module Main (main) where\nimport System.Process (callCommand)\nmain :: IO ()\nmain = pure ()\n${s}${body}`;
  const refuse = (src, line, re) => { const r = generateReproducer({ finding: F({ line }), root: repo({ 'Main.hs': src }) }); assert.equal(r.ok, false, JSON.stringify(r)); assert.match(r.reason, re); };
  refuse('module Main (main) where\nimport System.Process (callCommand)\nmain :: IO ()\nmain = callCommand "ls"\n', 4, /not inside a top-level function/);
  refuse(sig('', 'f x = callCommand x\n'), 5, /f has no type signature/);
  refuse(sig('f :: String -> String\n', 'f x = x\n'), 6, /returns String, not IO/);
  refuse(sig('f :: Int -> IO ()\n', 'f _ = callCommand "ls"\n'), 6, /parameter of type Int/);
  refuse(sig('f :: Show a => a -> IO ()\n', 'f a = callCommand (show a)\n'), 6, /polymorphic or constrained/);
  refuse(sig('f :: IO ()\n', 'f = callCommand "ls"\n'), 6, /takes no parameters/);
  refuse(sig('f :: (String -> String) -> IO ()\n', 'f g = callCommand (g "a")\n'), 6, /parameter of type \(String -> String\)/);
});

// ---------------------------------------------------------------------------------------------------------------- generation

test('the boot module set is read from the installed GHC and holds the modules a stdlib-only program imports', { skip: skipNoGhc }, () => {
  const set = bootModuleSet(tools.ghc);
  for (const m of ['Prelude', 'System.Process', 'System.Directory', 'System.FilePath', 'Data.Map', 'Data.ByteString', 'Data.Text', 'Control.Monad.State']) assert.ok(set.has(m), m);
  for (const m of ['Web.Scotty', 'Data.Aeson', 'System.Random', 'Database.SQLite.Simple']) assert.ok(!set.has(m), `${m} must not be in a stock GHC`);
});

test('script shape: a program that reads getArgs is run with the payload as its argument', { skip: skipNoGhc }, () => {
  const dir = repo({ 'Main.hs': fixture('command-injection-haskell', 'vulnerable') });
  const r = generateReproducer({ finding: F({ line: 13 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'script'); assert.equal(r.basis.class, 'command-injection'); assert.equal(r.reproducer.lang, 'haskell');
  assert.deepEqual(validateReproducer(r.reproducer), []);
  assert.deepEqual(r.reproducer.sources, { 'Main.hs': 'Main.hs' });
  assert.deepEqual(r.reproducer.run, ['{{GHC}}', '-ignore-dot-ghci', '-e', ':main "x; touch {{CANARY:command}}"', 'Main.hs']);
  assert.equal(r.reproducer.oracle.type, 'command_execution');
  assert.equal(r.reproducer.network, 'none');
});

test('function shape: a top-level String -> IO function is called with the payload; it need not be exported', { skip: skipNoGhc }, () => {
  const dir = repo({ 'Label.hs': FN_VULN.replace('(makeLabel)', '()') });
  const r = generateReproducer({ finding: F({ file: 'Label.hs', line: 6 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'function'); assert.equal(r.basis.function, 'makeLabel(1 String)');
  assert.deepEqual(r.reproducer.sources, { 'Label.hs': 'Label.hs' });
  assert.equal(r.reproducer.run[3], 'makeLabel "x; touch {{CANARY:command}}" >>= \\_ -> return ()');
  assert.ok(r.basis.assumptions.some((a) => /every parameter/.test(a)));
  assert.deepEqual(validateReproducer(r.reproducer), []);
});

test('path traversal is generated for write sinks only, with the watch and the one-directory-below assumption', { skip: skipNoGhc }, () => {
  const r = generateReproducer({ finding: F({ cwe: 'CWE-22', file: 'Store.hs', line: 8 }), root: repo({ 'Store.hs': WRITE_VULN }) });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.class, 'path-traversal'); assert.deepEqual(r.reproducer.watch, { fs: 'escaped.txt' }); assert.equal(r.reproducer.oracle.type, 'filesystem_mutation');
  assert.ok(r.basis.assumptions.some((a) => /one directory below/.test(a)));
  assert.equal(r.reproducer.run[3], 'save "../escaped.txt" >>= \\_ -> return ()');
});

test('a sibling module in the repository is carried into the workspace at its module path; a stdlib-only import is fine', { skip: skipNoGhc }, () => {
  const dir = repo({
    'app/Main.hs': 'module Main (main) where\nimport Util.Cmd (run)\nimport System.Environment (getArgs)\nimport qualified Data.Map as M\nmain :: IO ()\nmain = do\n  a <- getArgs\n  run (head a)\n',
    'src/Util/Cmd.hs': 'module Util.Cmd (run) where\nimport System.Process (callCommand)\nrun :: String -> IO ()\nrun s = callCommand ("echo " ++ s)\n',
  });
  const r = generateReproducer({ finding: F({ file: 'app/Main.hs', line: 8 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.reproducer.sources, { 'Util/Cmd.hs': 'src/Util/Cmd.hs', 'Main.hs': 'app/Main.hs' });
});

// ---------------------------------------------------------------------------------------------------------------- execution

test('generated script reproducer: CONFIRMED on the vulnerable program, not on the program that avoids the shell', { skip: skipExec }, async () => {
  const dir = repo({ 'Main.hs': fixture('command-injection-haskell', 'vulnerable') });
  const g = generateReproducer({ finding: F({ line: 13 }), root: dir });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(F({ line: 13 }), dir, g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
  assert.equal(v.attempts.successes, 3); assert.equal(v.independentReplay.status, 'confirmed');
  const safe = repo({ 'Main.hs': fixture('command-injection-haskell', 'mitigated') });
  const s = await prove(F({ line: 13 }), safe, g.reproducer);
  assert.notEqual(s.state, 'EXPLOIT_CONFIRMED'); assert.equal(s.attempts.successes, 0);
});

test('generated function reproducer: CONFIRMED on callCommand, not on callProcess', { skip: skipExec }, async () => {
  const finding = F({ file: 'Label.hs', line: 6 });
  const g = generateReproducer({ finding, root: repo({ 'Label.hs': FN_VULN }) });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, repo({ 'Label.hs': FN_VULN }), g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
  assert.equal(v.attempts.successes, 3);
  const s = await prove(finding, repo({ 'Label.hs': FN_SAFE }), g.reproducer);
  assert.notEqual(s.state, 'EXPLOIT_CONFIRMED');
});

test('generated path-traversal reproducer: CONFIRMED when the write escapes, not when the file name is confined', { skip: skipExec }, async () => {
  const finding = F({ cwe: 'CWE-22', file: 'Store.hs', line: 8 });
  const g = generateReproducer({ finding, root: repo({ 'Store.hs': WRITE_VULN }) });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, repo({ 'Store.hs': WRITE_VULN }), g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
  const s = await prove(finding, repo({ 'Store.hs': WRITE_SAFE }), g.reproducer);
  assert.notEqual(s.state, 'EXPLOIT_CONFIRMED');
});

test('a sibling module reaches the interpreter: the proof runs the cross-module program', { skip: skipExec }, async () => {
  const files = {
    'app/Main.hs': 'module Main (main) where\nimport Util.Cmd (run)\nimport System.Environment (getArgs)\nmain :: IO ()\nmain = do\n  a <- getArgs\n  run (head a)\n',
    'src/Util/Cmd.hs': 'module Util.Cmd (run) where\nimport System.Process (callCommand)\nrun :: String -> IO ()\nrun s = callCommand ("echo " ++ s)\n',
  };
  const dir = repo(files); const finding = F({ file: 'app/Main.hs', line: 7 });
  const g = generateReproducer({ finding, root: dir });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, dir, g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
});

test('a user-supplied reproducer for Haskell runs under the same oracle: interpreted, run via runghc, and compiled with a build step', { skip: skipExec }, async () => {
  const vuln = fixture('command-injection-haskell', 'vulnerable'); const safe = fixture('command-injection-haskell', 'mitigated');
  const oracle = { type: 'command_execution', params: { canary: 'command' } };
  const base = { schema: 'agentic-security/reproducer', version: 1, findingId: 'user', lang: 'haskell', oracle, network: 'none' };
  const variants = {
    runghc: { run: ['{{RUNGHC}}', 'Main.hs', 'x; touch {{CANARY:command}}'] },
    compiled: { build: ['{{GHC}}', '-O0', '-o', 'app', 'Main.hs'], run: ['./app', 'x; touch {{CANARY:command}}'] },
  };
  for (const [name, v] of Object.entries(variants)) {
    const hit = await runAttempt({ ...base, ...v, files: { 'Main.hs': vuln } });
    assert.equal(hit.status, 'completed', `${name}: ${hit.status} ${hit.reasons}`); assert.equal(hit.oracle.fired, true, name);
    const miss = await runAttempt({ ...base, ...v, files: { 'Main.hs': safe } });
    assert.equal(miss.status, 'completed', `${name}: ${miss.status} ${miss.reasons}`); assert.equal(miss.oracle.fired, false, name);
  }
});

test('a broken program is incomplete evidence, not a negative: a build that fails to compile is build-failed', { skip: skipExec }, async () => {
  const r = await runAttempt({ schema: 'agentic-security/reproducer', version: 1, findingId: 'u', lang: 'haskell', files: { 'Main.hs': 'main = this is not haskell' }, build: ['{{GHC}}', '-O0', '-o', 'app', 'Main.hs'], run: ['./app'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none' });
  assert.equal(r.status, 'build-failed');
  const i = await runAttempt({ schema: 'agentic-security/reproducer', version: 1, findingId: 'u', lang: 'haskell', files: { 'Main.hs': 'main = this is not haskell' }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', 'main', 'Main.hs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none' });
  assert.equal(i.status, 'completed'); assert.equal(i.oracle.fired, false); // a load error exits non-zero and creates no canary: not a confirmation
});

test('a hung Haskell program is stopped at the timeout and reported as timed out, never as a negative', { skip: skipExec }, async () => {
  const r = await runAttempt({ schema: 'agentic-security/reproducer', version: 1, findingId: 'u', lang: 'haskell', files: { 'Main.hs': 'import Control.Concurrent (threadDelay)\nmain :: IO ()\nmain = threadDelay 60000000\n' }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', 'main', 'Main.hs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none' }, { limits: { timeoutMs: 2500 } });
  assert.ok(r.degraded.includes('timed-out') || r.status !== 'completed', JSON.stringify({ s: r.status, d: r.degraded }));
  assert.notEqual(r.oracle?.fired, true);
});

test('the confinement holds for Haskell: a write outside the proof workspace does not land', { skip: skipExec }, async () => {
  const outside = path.join(mkTestTmp('hs-outside-'), 'escaped-outside.txt');
  const r = await runAttempt({ schema: 'agentic-security/reproducer', version: 1, findingId: 'u', lang: 'haskell', files: { 'Main.hs': `main :: IO ()\nmain = writeFile ${JSON.stringify(outside)} "x"\n` }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', 'main', 'Main.hs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none' });
  assert.equal(fs.existsSync(outside), false, 'the sandbox must refuse a write outside the workspace');
  assert.equal(r.status, 'completed');
});

// ---------------------------------------------------------------------------------------------------------------- container plumbing (fake engine)

test('through the stand-in container engine a Haskell proof is labelled `container`, uses the ghc image and the image\'s tool names', { skip: skipExec }, async () => {
  const engineDir = path.join(FIX, 'fake-engine');
  const log = path.join(mkTestTmp('fake-engine-'), 'calls.log');
  const saved = { PATH: process.env.PATH, AS_FAKE_DOCKER_LOG: process.env.AS_FAKE_DOCKER_LOG };
  process.env.PATH = `${engineDir}${path.delimiter}${process.env.PATH}`; process.env.AS_FAKE_DOCKER_LOG = log;
  try {
    const vuln = fixture('command-injection-haskell', 'vulnerable');
    const r = await runAttempt({ schema: 'agentic-security/reproducer', version: 1, findingId: 'c', lang: 'haskell', files: { 'Main.hs': vuln }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', ':main "x; touch {{CANARY:command}}"', 'Main.hs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none' });
    assert.equal(r.status, 'completed', `${r.status} ${r.reasons}`);
    assert.equal(r.environment.mode, 'container'); assert.equal(r.environment.image, 'haskell:9');
    assert.equal(r.oracle.fired, true);
    const calls = fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const run = calls.find((c) => c[0] === 'run');
    assert.ok(run.includes('haskell:9'));
    // the versioned GHC directory is put on PATH by a fixed wrapper, then the image's own ghc (not the host path) is run unchanged
    const after = run.slice(run.indexOf('haskell:9') + 1);
    assert.deepEqual(after.slice(0, 2), ['sh', '-c']); assert.equal(after[4], 'ghc', 'the image\'s own ghc, not the host path');
    assert.ok(run.includes('--network') && run[run.indexOf('--network') + 1] === 'none');
  } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
});
