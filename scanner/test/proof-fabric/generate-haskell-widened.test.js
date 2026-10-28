// The widened Haskell classes of the proof fabric: path-traversal READS (a per-run secret planted one directory up appears in the output),
// argument injection (a stand-in program acts on a planted option in FIRST position), richer parameter types, precise refusals, and hardening of
// the Haskell path (timeout, output cap, load-time and foreign code, the container command line). Generation tests need only the installed
// GHC's package list; execution tests need GHC and the sandbox and skip, loudly, without them. They never pass vacuously: each negative checks
// that the program ran to completion, and each confinement probe checks that the probe itself ran.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { generateReproducer } from '../../src/posture/proof-fabric/generate.js';
import { generateHaskellReproducer } from '../../src/posture/proof-fabric/generate-haskell.js';
import { proveFinding } from '../../src/posture/proof-fabric/orchestrator.js';
import { validateReproducer } from '../../src/posture/proof-fabric/reproducer.js';
import { hostTools, runAttempt, DEFAULT_LIMITS } from '../../src/posture/proof-fabric/runner.js';
import { containerArgs } from '../../src/posture/proof-fabric/container.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { skipUnlessRuns } from '../helpers/toolchain-probe.js';

const tools = hostTools();
const skipNoGhc = tools.ghc && tools.runghc ? false : 'ghc/runghc are not installed on this host (execution and import-classification tests are skipped, not passed)';
const skipExec = skipNoGhc || (!sandboxAvailable() ? 'no confinement backend on this host' : skipUnlessRuns('haskell'));
const repo = (files) => { const d = mkTestTmp('gen-hs-w-'); for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), c); } return d; };
const F = (over = {}) => ({ id: 'H1', stableId: 'H1', cwe: 'CWE-78', file: 'Main.hs', line: 13, parser: 'IR-TAINT', ...over });
const prove = (finding, dir, reproducer) => proveFinding({ finding, reproducer, sourceRoot: dir, policy: { timeoutMs: 30000 } });
const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/proof-fabric');
const fixture = (cls, side) => fs.readFileSync(path.join(FIX, cls, side, 'Main.hs'), 'utf8');

const HS_BASE = { schema: 'agentic-security/reproducer', version: 1, findingId: 'u', lang: 'haskell', network: 'none' };
const NOTES_STR = 'module Notes where\nimport System.FilePath ((</>))\n\nreadNote :: FilePath -> IO String\nreadNote name = do\n  readFile ("uploads" </> name)\n';
const NOTES_SAFE = 'module Notes where\nimport System.FilePath ((</>), splitDirectories, isAbsolute)\n\nreadNote :: FilePath -> IO String\nreadNote name\n  | ".." `elem` splitDirectories name || isAbsolute name = pure "refused"\n  | otherwise = readFile ("uploads" </> name)\n';
const NOTES_TEXT = 'module Notes where\nimport qualified Data.Text as T\nimport qualified Data.Text.IO as TIO\nimport Data.Text (Text)\n\nreadNote :: Text -> IO Text\nreadNote name = TIO.readFile ("notes/" ++ T.unpack name)\n';
const ARG_EL = 'module Run where\nimport System.Process\n\nrunIt :: String -> String -> IO ()\nrunIt a b = callProcess "archive-tool" [a, b]\n';
const ARG_EL_DASHES = 'module Run where\nimport System.Process\n\nrunIt :: String -> String -> IO ()\nrunIt a b = callProcess "archive-tool" ("--" : [a, b])\n';
const ARG_LIST = 'module Run where\nimport System.Process\n\nrunIt :: [String] -> IO String\nrunIt xs = readProcess "archive-tool" xs ""\n';
const argFinding = (over = {}) => F({ cwe: 'CWE-88', file: 'Run.hs', line: 5, ...over });
const readFinding = (over = {}) => F({ cwe: 'CWE-22', file: 'Notes.hs', line: 6, ...over });
const gen = (finding, files) => generateReproducer({ finding, root: repo(files) });
const refused = (finding, files, re) => { const r = gen(finding, files); assert.equal(r.ok, false, JSON.stringify(r.reproducer ?? r)); assert.match(r.reason, re); return r; };

// ---------------------------------------------------------------------------------------------------------------- reads, generation

test('path-traversal READ: the secret file and the base directory are planted, the oracle is file_disclosure, the result is printed', { skip: skipNoGhc }, () => {
  const r = gen(readFinding(), { 'Notes.hs': NOTES_STR });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.class, 'path-traversal-read'); assert.equal(r.reproducer.oracle.type, 'file_disclosure');
  assert.deepEqual(Object.keys(r.reproducer.files).sort(), ['agentic-proof-secret.txt', 'uploads/.keep']);
  assert.equal(r.reproducer.files['agentic-proof-secret.txt'], '{{SECRET:file}}');
  assert.equal(r.reproducer.watch, undefined);
  assert.equal(r.reproducer.run[3], 'readNote "../agentic-proof-secret.txt" >>= print');
  assert.ok(r.basis.assumptions.some((a) => /reaches the program's output/.test(a)));
  assert.deepEqual(validateReproducer(r.reproducer), []);
});

test('path-traversal READ: a Text parameter and result are filled under OverloadedStrings set for the call only', { skip: skipNoGhc }, () => {
  const r = gen(readFinding({ line: 7 }), { 'Notes.hs': NOTES_TEXT });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.reproducer.run.slice(0, 6), ['{{GHC}}', '-ignore-dot-ghci', '-e', ':set -XOverloadedStrings', '-e', 'readNote "../agentic-proof-secret.txt" >>= print']);
  assert.equal(r.reproducer.files['notes/.keep'], '');
  assert.ok(r.basis.assumptions.some((a) => /OverloadedStrings, set for the call only/.test(a)));
});

test('path-traversal READ: a script that prints what it reads is run with the payload as its argument', { skip: skipNoGhc }, () => {
  const r = gen(F({ cwe: 'CWE-22', line: 12 }), { 'Main.hs': fixture('path-traversal-read-haskell', 'vulnerable') });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'script'); assert.equal(r.reproducer.oracle.type, 'file_disclosure');
  assert.equal(r.reproducer.run[3], ':main "../agentic-proof-secret.txt"');
  assert.ok(Object.hasOwn(r.reproducer.files, 'public/.keep'));
});

test('path-traversal READ refusals name the construct: a base directory the file does not state, a result the proof cannot print, other file operations', { skip: skipNoGhc }, () => {
  refused(readFinding({ line: 5 }), { 'Notes.hs': 'module Notes where\n\nreadNote :: FilePath -> IO String\nreadNote name = do\n  readFile name\n' }, /reads a path whose base directory is not a relative literal/);
  refused(readFinding({ line: 5 }), { 'Notes.hs': 'module Notes where\n\nreadNote :: FilePath -> IO String\nreadNote name = do\n  readFile ("/srv/data/" ++ name)\n' }, /base directory is not a relative literal/);
  refused(readFinding({ line: 5 }), { 'Notes.hs': 'module Notes where\n\nsize :: FilePath -> IO Int\nsize name = do\n  c <- readFile ("uploads/" ++ name)\n  pure (length c)\n' }, /returns IO Int, whose content the proof cannot print/);
  refused(readFinding({ line: 5 }), { 'Notes.hs': 'module Notes where\nimport System.Directory\n\nlist :: FilePath -> IO [FilePath]\nlist d = listDirectory ("uploads/" ++ d)\n' }, /is not a write \(writeFile.*or a read \(readFile.*listDirectory, doesFileExist/);
});

// ---------------------------------------------------------------------------------------------------------------- argument injection, generation

test('argument injection: the stand-in, its permission, its PATH and a payload in the first parameter only', { skip: skipNoGhc }, () => {
  const r = gen(argFinding(), { 'Run.hs': ARG_EL });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.class, 'argument-injection'); assert.equal(r.reproducer.oracle.type, 'argument_injection');
  assert.deepEqual(Object.keys(r.reproducer.files), ['bin/archive-tool']);
  assert.match(r.reproducer.files['bin/archive-tool'], /^#!\/bin\/sh\n/); assert.match(r.reproducer.files['bin/archive-tool'], /--agentic-proof-write=\*\) : > /);
  assert.deepEqual(r.reproducer.build, ['/bin/chmod', '755', 'bin/archive-tool']);
  assert.match(r.reproducer.env.PATH, /^\{\{ROOT\}\}\/bin:/);
  assert.equal(r.reproducer.run[3], 'runIt "--agentic-proof-write={{CANARY:arg}}" "benign" >>= \\_ -> return ()');
  assert.ok(r.basis.assumptions.some((a) => /not that the real archive-tool has a dangerous option/.test(a)));
  assert.deepEqual(validateReproducer(r.reproducer), []);
});

test('argument injection: a whole argument list ([String] parameter) and a getArgs list are accepted; a script needs `args <- getArgs`', { skip: skipNoGhc }, () => {
  const l = gen(argFinding(), { 'Run.hs': ARG_LIST });
  assert.equal(l.ok, true, l.reason);
  assert.equal(l.reproducer.run[3], 'runIt ["--agentic-proof-write={{CANARY:arg}}"] >>= \\_ -> return ()');
  const s = gen(F({ cwe: 'CWE-88', line: 10 }), { 'Main.hs': fixture('argument-injection-haskell', 'vulnerable') });
  assert.equal(s.ok, true, s.reason);
  assert.equal(s.basis.shape, 'script'); assert.equal(s.reproducer.run[3], ':main "--agentic-proof-write={{CANARY:arg}}"');
});

test('argument injection refusals say what the proof cannot place: later positions, fixed first argument, shells, expressions, patterns, non-parameters', { skip: skipNoGhc }, () => {
  const sig = (body, ty = 'String -> IO ()') => `module Run where\nimport System.Process\n\nrunIt :: ${ty}\n${body}\n`;
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "archive-tool" ["-x", a]') }, /first argument of the call to archive-tool is a fixed string.*FIRST position.*takes the next word as its value/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "archive-tool" ("--" : [a])') }, /is a fixed string|an expression the proof cannot read/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "sh" [a]') }, /the program is `sh`, which the proof does not stand in for.*command injection, CWE-78/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "ghc" [a]') }, /does not stand in for/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "archive-tool" [map id a]') }, /an expression the proof cannot read as a plain parameter/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "archive-tool" [other]\n  where other = a') }, /`other`, which is not a parameter of runIt/);
  refused(argFinding(), { 'Run.hs': sig('runIt (a) = callProcess "archive-tool" [a]') }, /patterns or the definition is point-free/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess prog [a]') }, /not a call to callProcess.*with the program named by a string literal/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "archive-tool" [a]', 'Int -> IO ()') }, /parameter of type Int/);
  refused(argFinding(), { 'Run.hs': sig('runIt xs = callProcess "archive-tool" xs', 'String -> IO ()') }, /whole argument vector but has type String/);
  refused(argFinding(), { 'Run.hs': sig('runIt a = callProcess "archive-tool" [a]', '[String] -> IO ()') }, /is a list but stands as one element/);
  // a script whose first argument is not the straight getArgs list
  refused(F({ cwe: 'CWE-88', line: 8 }), { 'Main.hs': 'module Main (main) where\nimport System.Environment (getArgs)\nimport System.Process (callProcess)\nmain :: IO ()\nmain = do\n  args <- getArgs\n  let more = args\n  callProcess "archive-tool" (head args : more)\n' }, /argument vector comes straight from getArgs|an expression the proof cannot read|a parameter/);
});

// ---------------------------------------------------------------------------------------------------------------- parameter types

test('parameter types: Text, ByteString, [String], Maybe String and a plain type alias are filled; a local Text, a foreign qualifier and a newtype are not', { skip: skipNoGhc }, () => {
  const make = (ty, extra = '') => {
    const n = ty.split('->').length - 1;
    const src = `module Main where\nimport qualified Data.Text as T\nimport qualified Data.ByteString.Char8 as B\nimport System.Process\n${extra}\nrun :: ${ty}\nrun ${Array.from({ length: n }, (_, i) => `p${i}`).join(' ')} = callCommand "echo"\n`;
    return { src, line: src.split('\n').findIndex((x) => x.startsWith('run p')) + 1 };
  };
  const ok = (ty, extra, expected) => { const { src, line } = make(ty, extra); const r = gen(F({ line }), { 'Main.hs': src }); assert.equal(r.ok, true, `${ty}: ${r.reason}`); assert.match(r.reproducer.run[r.reproducer.run.length - 2], expected, ty); return r; };
  ok('T.Text -> IO ()', '', /^run "x; touch \{\{CANARY:command\}\}" >>= /);
  ok('B.ByteString -> IO ()', '', /^run "x; touch/);
  ok('[String] -> IO ()', '', /^run \["x; touch \{\{CANARY:command\}\}"\] >>= /);
  ok('Maybe String -> IO ()', '', /^run \(Just "x; touch/);
  ok('String -> Maybe T.Text -> [FilePath] -> IO ()', '', /^run "x; touch[^"]*" \(Just "x; touch[^"]*"\) \["x; touch/);
  ok('Name -> IO ()', 'type Name = String\n', /^run "x; touch/);
  const r = ok('Label -> IO ()', 'type Label = Name\ntype Name = T.Text\n', /^run "x; touch/);
  assert.equal(r.reproducer.run[2], '-e'); assert.equal(r.reproducer.run[3], ':set -XOverloadedStrings');
  const wrong = (ty, extra, re) => { const { src, line } = make(ty, extra); const g = gen(F({ line }), { 'Main.hs': src }); assert.equal(g.ok, false, ty); assert.match(g.reason, re, ty); };
  wrong('Q.Text -> IO ()', '', /parameter of type Q\.Text/);
  wrong('Secret -> IO ()', 'newtype Secret = Secret String\n', /parameter of type Secret/);
  wrong('Maybe (Maybe String) -> IO ()', '', /parameter of type Maybe \(Maybe String\)/);
  const local = 'module Main where\nimport System.Process\ndata Text = Text String\nrun :: Text -> IO ()\nrun p0 = callCommand "echo"\n';
  const g = gen(F({ line: 5 }), { 'Main.hs': local });
  assert.equal(g.ok, false); assert.match(g.reason, /parameter of type Text/);
});

test('a source that already contains proof placeholder syntax is refused: the runner would substitute it inside the program', { skip: skipNoGhc }, () => {
  refused(F({ line: 5 }), { 'Main.hs': 'module Main where\nimport System.Process\nrun :: String -> IO ()\n-- {{SECRET:file}}\nrun x = callCommand x\n' }, /shaped like a proof placeholder/);
});

// ---------------------------------------------------------------------------------------------------------------- refusal messages (no GHC needed)

test('every unsupported Haskell class is refused with the flagged construct, the reason and how to supply a reproducer', () => {
  const files = { 'Db.hs': 'module Db where\nimport Database.SQLite.Simple\nfind :: String -> IO ()\nfind n = query_ conn ("select * from t where n = \'" ++ n ++ "\'")\n' };
  const ask = (cwe) => { const r = generateReproducer({ finding: F({ cwe, file: 'Db.hs', line: 4 }), root: repo(files) }); assert.equal(r.ok, false); return r.reason; };
  for (const [cwe, re] of [['CWE-89', /^sql-injection: the flagged line `find n = query_ conn/], ['CWE-502', /^deserialization: /], ['CWE-79', /^cross-site scripting: /], ['CWE-94', /^code injection: /], ['CWE-918', /^ssrf: /], ['CWE-1427', /^prompt injection: /], ['CWE-327', /^CWE-327: no payload and oracle exist for CWE-327 in Haskell/]]) {
    const reason = ask(cwe);
    assert.match(reason, re, cwe);
    assert.match(reason, /write a reproducer for lang "haskell"/, cwe);
    assert.match(reason, /--reproducer <file>/, cwe);
    assert.match(reason, /Nothing was executed\.$/, cwe);
  }
  // other languages keep their own wording
  assert.match(generateReproducer({ finding: F({ cwe: 'CWE-89', file: 'a.js', line: 1 }), root: repo({ 'a.js': 'x' }) }).reason, /no payload and oracle exist for CWE-89; supported: CWE-78, CWE-22, CWE-918/);
});

test('every generation refusal for a Haskell file carries the hand-written reproducer hint exactly once', { skip: skipNoGhc }, () => {
  const r = refused(F({ line: 5 }), { 'Main.hs': 'module Main (main) where\nimport Web.Scotty\nmain :: IO ()\nmain = pure ()\nf = 1\n' }, /needs scotty/);
  assert.match(r.reason, /write a reproducer for lang "haskell".*Nothing was executed\.$/);
  assert.equal(r.reason.split('Nothing was executed.').length, 2);
  assert.doesNotMatch(r.reason, /\.\. /);
});

// ---------------------------------------------------------------------------------------------------------------- execution: reads

test('generated READ reproducer (function): CONFIRMED when the traversal reaches the planted file, not when the name is confined', { skip: skipExec }, async () => {
  const finding = readFinding();
  const g = gen(finding, { 'Notes.hs': NOTES_STR });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, repo({ 'Notes.hs': NOTES_STR }), g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
  assert.equal(v.attempts.successes, 3); assert.equal(v.oracle, 'file_disclosure');
  assert.ok(!/SECRET-[0-9a-f]{24}/.test(JSON.stringify(v)), 'the raw per-run secret must not be persisted in the proof record');
  const s = await prove(finding, repo({ 'Notes.hs': NOTES_SAFE }), g.reproducer);
  assert.notEqual(s.state, 'EXPLOIT_CONFIRMED');
  assert.equal(s.outcome, 'not-reproduced'); assert.equal(s.attempts.incomplete, 0, 'the mitigated program ran to completion: this is a negative, not a failure to run');
});

test('generated READ reproducer (Text in, Text out) and (script): CONFIRMED on the vulnerable program, not on the mitigated twin', { skip: skipExec }, async () => {
  const tf = readFinding({ line: 7 });
  const tg = gen(tf, { 'Notes.hs': NOTES_TEXT });
  assert.equal(tg.ok, true, tg.reason);
  const tv = await prove(tf, repo({ 'Notes.hs': NOTES_TEXT }), tg.reproducer);
  assert.equal(tv.state, 'EXPLOIT_CONFIRMED', `${tv.outcome}; ${tv.degradation.join(',')}`);
  const sf = F({ cwe: 'CWE-22', line: 12 });
  const sg = gen(sf, { 'Main.hs': fixture('path-traversal-read-haskell', 'vulnerable') });
  assert.equal(sg.ok, true, sg.reason);
  const sv = await prove(sf, repo({ 'Main.hs': fixture('path-traversal-read-haskell', 'vulnerable') }), sg.reproducer);
  assert.equal(sv.state, 'EXPLOIT_CONFIRMED', `${sv.outcome}; ${sv.degradation.join(',')}`);
  const sm = await prove(sf, repo({ 'Main.hs': fixture('path-traversal-read-haskell', 'mitigated') }), sg.reproducer);
  assert.notEqual(sm.state, 'EXPLOIT_CONFIRMED'); assert.equal(sm.outcome, 'not-reproduced'); assert.equal(sm.attempts.incomplete, 0);
});

test('a read whose content never reaches the output is not confirmed: unproven, never reported safe', { skip: skipExec }, async () => {
  const quiet = 'module Notes where\nimport System.FilePath ((</>))\n\nreadNote :: FilePath -> IO ()\nreadNote name = do\n  c <- readFile ("uploads" </> name)\n  length c `seq` pure ()\n';
  const finding = readFinding({ line: 6 });
  const g = gen(finding, { 'Notes.hs': quiet });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, repo({ 'Notes.hs': quiet }), g.reproducer);
  assert.notEqual(v.state, 'EXPLOIT_CONFIRMED'); assert.equal(v.outcome, 'not-reproduced');
  assert.match(v.note, /not proof of safety/);
});

test('the READ oracle is not fooled by a program that only echoes the requested name', { skip: skipExec }, async () => {
  const finding = readFinding();
  const g = gen(finding, { 'Notes.hs': NOTES_STR });
  const echoes = 'module Notes where\nimport System.FilePath ((</>))\n\nreadNote :: FilePath -> IO String\nreadNote name = do\n  putStrLn ("asked for " ++ name)\n  pure ("uploads" </> name)\n';
  const v = await prove(finding, repo({ 'Notes.hs': echoes }), g.reproducer);
  assert.notEqual(v.state, 'EXPLOIT_CONFIRMED'); assert.equal(v.attempts.successes, 0);
});

// ---------------------------------------------------------------------------------------------------------------- execution: argument injection

test('generated ARGUMENT INJECTION reproducer (function): CONFIRMED when attacker data is the first argument, not behind `--`, a dash check or a prefix', { skip: skipExec }, async () => {
  const finding = argFinding();
  const g = gen(finding, { 'Run.hs': ARG_EL });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, repo({ 'Run.hs': ARG_EL }), g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
  assert.equal(v.attempts.successes, 3); assert.equal(v.independentReplay.status, 'confirmed'); assert.equal(v.oracle, 'argument_injection');
  const rejects = 'module Run where\nimport System.Process\nimport Data.List (isPrefixOf)\n\nrunIt :: String -> String -> IO ()\nrunIt a b = if "-" `isPrefixOf` a then pure () else callProcess "archive-tool" [a, b]\n';
  const prefixes = 'module Run where\nimport System.Process\n\nrunIt :: String -> String -> IO ()\nrunIt a b = callProcess "archive-tool" ["./" ++ a, b]\n';
  for (const [name, src] of Object.entries({ dashes: ARG_EL_DASHES, rejects, prefixes })) {
    const s = await prove(finding, repo({ 'Run.hs': src }), g.reproducer);
    assert.notEqual(s.state, 'EXPLOIT_CONFIRMED', name);
    assert.equal(s.outcome, 'not-reproduced', name); assert.equal(s.attempts.incomplete, 0, `${name}: the program ran to completion`);
  }
});

test('generated ARGUMENT INJECTION reproducer (whole [String] list, and a getArgs script): CONFIRMED; the `--` twin is not', { skip: skipExec }, async () => {
  const lf = argFinding();
  const lg = gen(lf, { 'Run.hs': ARG_LIST });
  assert.equal(lg.ok, true, lg.reason);
  const lv = await prove(lf, repo({ 'Run.hs': ARG_LIST }), lg.reproducer);
  assert.equal(lv.state, 'EXPLOIT_CONFIRMED', `${lv.outcome}; ${lv.degradation.join(',')}`);
  const sf = F({ cwe: 'CWE-88', line: 10 });
  const sg = gen(sf, { 'Main.hs': fixture('argument-injection-haskell', 'vulnerable') });
  assert.equal(sg.ok, true, sg.reason);
  const sv = await prove(sf, repo({ 'Main.hs': fixture('argument-injection-haskell', 'vulnerable') }), sg.reproducer);
  assert.equal(sv.state, 'EXPLOIT_CONFIRMED', `${sv.outcome}; ${sv.degradation.join(',')}`);
  const sm = await prove(sf, repo({ 'Main.hs': fixture('argument-injection-haskell', 'mitigated') }), sg.reproducer);
  assert.notEqual(sm.state, 'EXPLOIT_CONFIRMED'); assert.equal(sm.outcome, 'not-reproduced');
});

test('the stand-in acts only on the planted option in FIRST position: the option as a later argument, or any other option, creates nothing', { skip: skipExec }, async () => {
  const gen0 = generateHaskellReproducer({ finding: argFinding(), root: repo({ 'Run.hs': ARG_EL }), cls: { name: 'argument-injection', payload: 'p', oracle: { type: 'argument_injection', params: { canary: 'arg' } } } });
  assert.equal(gen0.ok, true, gen0.reason);
  const standIn = gen0.reproducer.files['bin/archive-tool'].replaceAll('archive-tool', 'tool');
  const mk = (a, b) => ({ ...HS_BASE, oracle: { type: 'argument_injection', params: { canary: 'arg' } },
    files: { 'bin/tool': standIn, 'Main.hs': `import System.Process\nmain :: IO ()\nmain = callProcess "tool" [${a}, ${b}]\n` },
    build: ['/bin/chmod', '755', 'bin/tool'], env: { PATH: '{{ROOT}}/bin:/usr/bin:/bin:/usr/sbin:/sbin' }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', 'main', 'Main.hs'] });
  const planted = '"--agentic-proof-write={{CANARY:arg}}"';
  const first = await runAttempt(mk(planted, '"x"')); assert.equal(first.oracle?.fired, true, `${first.status} ${first.reasons}`);
  const later = await runAttempt(mk('"x"', planted)); assert.equal(later.status, 'completed'); assert.equal(later.oracle.fired, false, 'the same text in second position must not fire');
  const other = await runAttempt(mk('"--something-else={{CANARY:arg}}"', '"x"')); assert.equal(other.status, 'completed'); assert.equal(other.oracle.fired, false);
});

// ---------------------------------------------------------------------------------------------------------------- execution: richer types

test('generated reproducers fill Text, Maybe String and [String] parameters: command injection CONFIRMED through a Text parameter, not through callProcess', { skip: skipExec }, async () => {
  const src = 'module Label where\nimport qualified Data.Text as T\nimport System.Process (callCommand)\n\nmakeLabel :: T.Text -> Maybe String -> [String] -> IO ()\nmakeLabel name _ _ = callCommand ("echo label " ++ T.unpack name)\n';
  const safe = 'module Label where\nimport qualified Data.Text as T\nimport System.Process (callProcess)\n\nmakeLabel :: T.Text -> Maybe String -> [String] -> IO ()\nmakeLabel name _ _ = callProcess "echo" ["label", T.unpack name]\n';
  const finding = F({ file: 'Label.hs', line: 6 });
  const g = gen(finding, { 'Label.hs': src });
  assert.equal(g.ok, true, g.reason);
  assert.equal(g.reproducer.run[5], 'makeLabel "x; touch {{CANARY:command}}" (Just "x; touch {{CANARY:command}}") ["x; touch {{CANARY:command}}"] >>= \\_ -> return ()');
  const v = await prove(finding, repo({ 'Label.hs': src }), g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
  const s = await prove(finding, repo({ 'Label.hs': safe }), g.reproducer);
  assert.notEqual(s.state, 'EXPLOIT_CONFIRMED'); assert.equal(s.outcome, 'not-reproduced');
});

test('OverloadedStrings is set for the call only: a program that is ambiguous under it still loads and is proven', { skip: skipExec }, async () => {
  // `length "abc"` is ambiguous when OverloadedStrings applies to the module; loading would fail if the extension leaked in
  const src = 'module Label where\nimport qualified Data.Text as T\nimport System.Process (callCommand)\n\nmakeLabel :: T.Text -> IO ()\nmakeLabel name = callCommand ("echo " ++ show (length "abc") ++ " " ++ T.unpack name)\n';
  const finding = F({ file: 'Label.hs', line: 6 });
  const g = gen(finding, { 'Label.hs': src });
  assert.equal(g.ok, true, g.reason);
  const v = await prove(finding, repo({ 'Label.hs': src }), g.reproducer);
  assert.equal(v.state, 'EXPLOIT_CONFIRMED', `${v.outcome}; ${v.degradation.join(',')}`);
});

// ---------------------------------------------------------------------------------------------------------------- hardening: timeout and output cap

const asHs = (main, over = {}) => ({ ...HS_BASE, files: { 'Main.hs': main }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', 'main', 'Main.hs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, ...over });

test('through the full proof a hung Haskell program is INCONCLUSIVE with timed-out evidence, never not-reproduced and never confirmed', { skip: skipExec }, async () => {
  const hang = asHs('import Control.Concurrent (threadDelay)\nmain :: IO ()\nmain = threadDelay 600000000\n');
  const t0 = Date.now();
  const v = await proveFinding({ finding: { id: 'u', stableId: 'u', parser: 'IR-TAINT' }, reproducer: hang, policy: { timeoutMs: 2000, attempts: 2, required: 2 }, sourceRoot: repo({ x: 'x' }) });
  assert.notEqual(v.state, 'EXPLOIT_CONFIRMED'); assert.equal(v.outcome, 'inconclusive'); assert.equal(v.completeness, 'INCOMPLETE');
  assert.ok(v.degradation.includes('timed-out'), v.degradation.join(','));
  assert.ok(Date.now() - t0 < 60000, 'the supervisor ended the runs instead of waiting for the program');
});

test('a Haskell program that floods its output is cut at the cap, reported output-capped, and the oracle does not fire', { skip: skipExec }, async () => {
  const main = 'main :: IO ()\nmain = mapM_ putStrLn (repeat (replicate 400 (toEnum 97)))\n';
  const flood = asHs(main, { oracle: { type: 'file_disclosure', params: { secret: 'file' } }, files: { 'Main.hs': main, 'secret.txt': '{{SECRET:file}}' } });
  const t0 = Date.now();
  const r = await runAttempt(flood, { limits: { timeoutMs: 15000, maxOutputBytes: 8192 } });
  assert.ok(r.degraded.includes('output-capped'), JSON.stringify({ s: r.status, d: r.degraded }));
  assert.ok(r.observation.stdout.length <= 8192 + 64, `stdout kept ${r.observation.stdout.length} bytes`);
  assert.notEqual(r.oracle?.fired, true);
  assert.ok(Date.now() - t0 < 30000);
});

// ---------------------------------------------------------------------------------------------------------------- hardening: load-time and foreign code cannot leave the workspace

// Each probe writes inside the workspace (allowed) and tries to write outside it (denied) through a different load-time or foreign route. The
// inside write is watched, so the oracle firing proves the probe really ran; the outside directory must stay empty. The generator refuses all of
// these routes for a generated reproducer (next test); here a hand-written reproducer uses them on purpose. The userspace backend does not
// confine READS (src/sandbox/CLAUDE.md), so only writes and child processes are probed.
test('Template Haskell, a foreign import and unsafePerformIO cannot write outside the proof workspace (and the probes demonstrably ran)', { skip: skipExec }, async () => {
  const outsideDir = mkTestTmp('hs-escape-');
  const o = (n) => JSON.stringify(path.join(outsideDir, n));
  const inside = 'writeFile "inside.txt" "ran"';
  const probes = {
    templateHaskell: `{-# LANGUAGE TemplateHaskell #-}\nimport Language.Haskell.TH\nimport Language.Haskell.TH.Syntax (runIO)\nimport System.Process (callCommand)\nmain :: IO ()\nmain = print $(runIO (writeFile "inside.txt" "ran" >> writeFile ${o('th-write')} "x" >> callCommand ("touch " ++ ${o('th-child')})) >> [| 1 :: Int |])\n`,
    foreignImport: `{-# LANGUAGE ForeignFunctionInterface #-}\nimport Foreign.C.String (CString, withCString)\nimport Foreign.C.Types (CInt(..))\nforeign import ccall "system" c_system :: CString -> IO CInt\nmain :: IO ()\nmain = do\n  ${inside}\n  _ <- withCString ("touch " ++ ${o('ffi-child')}) c_system\n  pure ()\n`,
    unsafePerformIO: `import System.IO.Unsafe (unsafePerformIO)\nimport System.Process (callCommand)\nleak :: ()\nleak = unsafePerformIO (writeFile ${o('upio-write')} "x" >> callCommand ("touch " ++ ${o('upio-child')}))\n{-# NOINLINE leak #-}\nmain :: IO ()\nmain = do\n  ${inside}\n  leak \`seq\` pure ()\n`,
  };
  for (const [name, src] of Object.entries(probes)) {
    const r = await runAttempt(asHs(src, { watch: { in: 'inside.txt' }, oracle: { type: 'filesystem_mutation', params: { canary: 'in' } } }));
    assert.equal(r.status, 'completed', `${name}: ${r.status} ${r.reasons}`);
    assert.equal(r.oracle.fired, true, `${name}: the probe must have run (its inside write is allowed) or this test proves nothing; stderr: ${String(r.observation?.stderr).slice(0, 300)}`);
  }
  assert.deepEqual(fs.readdirSync(outsideDir), [], `nothing may land outside the workspace: found ${fs.readdirSync(outsideDir).join(', ')}`);
  // control: the same probe, run WITHOUT the sandbox, does write outside its directory, so an empty outside directory above is the sandbox's doing
  const free = mkTestTmp('hs-free-');
  fs.writeFileSync(path.join(free, 'Main.hs'), probes.unsafePerformIO.replaceAll(path.join(outsideDir, 'upio-'), path.join(free, 'FREE-')));
  spawnSync(tools.ghc, ['-ignore-dot-ghci', '-e', 'main', 'Main.hs'], { cwd: free, timeout: 60000, stdio: 'ignore' });
  assert.ok(fs.existsSync(path.join(free, 'FREE-write')) && fs.existsSync(path.join(free, 'FREE-child')), 'the control probe must be able to write when nothing confines it');
});

test('the generator refuses those routes by name for a generated reproducer, in the flagged file and in a module it imports', { skip: skipNoGhc }, () => {
  const call = 'main :: IO ()\nmain = callCommand "ls"\n';
  refused(F({ line: 7 }), { 'Main.hs': `{-# LANGUAGE TemplateHaskell #-}\nmodule Main (main) where\nimport System.Process (callCommand)\n\n${call}` }, /Template Haskell, quasi-quotes, CPP or the foreign function interface/);
  refused(F({ line: 7 }), { 'Main.hs': `{-# LANGUAGE QuasiQuotes #-}\nmodule Main (main) where\nimport System.Process (callCommand)\n\n${call}` }, /Template Haskell, quasi-quotes/);
  refused(F({ line: 5 }), { 'Main.hs': `module Main (main) where\nimport System.Process (callCommand)\nforeign import ccall "system" c_system :: Int -> IO Int\n${call}` }, /foreign function interface/);
  refused(F({ line: 5, file: 'app/Main.hs' }), { 'app/Main.hs': 'module Main (main) where\nimport Helper\nimport System.Process (callCommand)\nmain :: IO ()\nmain = callCommand "ls"\n', 'app/Helper.hs': '{-# LANGUAGE TemplateHaskell #-}\nmodule Helper where\nx = 1\n' }, /the module Helper is refused: it enables Template Haskell/);
});

// ---------------------------------------------------------------------------------------------------------------- container command line (no real engine is run)

test('the container command line for a Haskell proof: fixed hardening flags, the image\'s ghc, a non-root user, one bind mount, and the stand-in PATH last', () => {
  const run = ['ghc', '-ignore-dot-ghci', '-e', ':main "x"', 'Main.hs'];
  const args = containerArgs({ image: 'haskell:9', name: 'proof-abc-run', hostRoot: '/tmp/proof/root', argv: run, env: { PATH: '/work/bin:/opt/ghc/bin:/usr/bin:/bin', LANG: 'C.UTF-8' }, limits: DEFAULT_LIMITS, user: '1000:1000' });
  const val = (flag) => args[args.indexOf(flag) + 1];
  assert.equal(args[0], 'run'); assert.equal(val('--network'), 'none'); assert.ok(args.includes('--read-only'));
  assert.equal(val('--cap-drop'), 'ALL'); assert.equal(val('--security-opt'), 'no-new-privileges'); assert.equal(val('--pull'), 'never');
  assert.equal(val('--user'), '1000:1000'); assert.equal(val('--workdir'), '/work');
  assert.equal(args.filter((a) => a === '-v').length, 1); assert.equal(val('-v'), '/tmp/proof/root:/work:rw');
  assert.ok(!args.includes('--privileged'));
  // GHC sits in /opt/ghc/<version>/bin and the version floats with the tag (the first real-engine run found `ghc: not found` with /opt/ghc/bin), so a
  // fixed wrapper puts every /opt/ghc/*/bin on PATH inside the container and then runs the argument vector unchanged.
  const tail = args.slice(args.indexOf('haskell:9'));
  assert.deepEqual(tail.slice(0, 3), ['haskell:9', 'sh', '-c']);
  assert.match(tail[3], /for d in \/opt\/ghc\/\*\/bin; do PATH="\$d:\$PATH"; done; export PATH; exec "\$@"$/);
  assert.deepEqual(tail.slice(4), ['sh', ...run], 'the argument vector follows the wrapper unchanged, as separate arguments');
  // the reproducer's PATH comes after the default one, so it wins; it keeps the toolchain directory so ghc is still found
  const paths = args.filter((a, k) => args[k - 1] === '-e' && a.startsWith('PATH='));
  assert.equal(paths.length, 2); assert.match(paths[1], /^PATH=\/work\/bin:\/opt\/ghc\/bin:/);
});

test('through the stand-in engine an ARGUMENT INJECTION proof finds its stand-in under /work and a READ proof sees its planted file there (command line and plumbing only: this is not a container)', { skip: skipExec }, async () => {
  const engineDir = path.join(FIX, 'fake-engine');
  const log = path.join(mkTestTmp('fake-engine-'), 'calls.log');
  const saved = { PATH: process.env.PATH, AS_FAKE_DOCKER_LOG: process.env.AS_FAKE_DOCKER_LOG };
  process.env.PATH = `${engineDir}${path.delimiter}${process.env.PATH}`; process.env.AS_FAKE_DOCKER_LOG = log;
  try {
    for (const [cls, name] of [['argument-injection-haskell', 'argument injection'], ['path-traversal-read-haskell', 'read']]) {
      const rep = JSON.parse(fs.readFileSync(path.join(FIX, cls, 'reproducer.json'), 'utf8'));
      const withSource = (side) => { const { sources, ...rest } = rep; void sources; return { ...rest, files: { ...rest.files, 'Main.hs': fixture(cls, side) } }; };
      const hit = await runAttempt(withSource('vulnerable'));
      assert.equal(hit.status, 'completed', `${name}: ${hit.status} ${hit.reasons}`);
      assert.equal(hit.environment.mode, 'container', name); assert.equal(hit.oracle.fired, true, name);
      const miss = await runAttempt(withSource('mitigated'));
      assert.equal(miss.status, 'completed'); assert.equal(miss.oracle.fired, false, name);
    }
    const calls = fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)).filter((c) => c[0] === 'run');
    assert.ok(calls.length >= 4);
    // the command after the image, past the fixed wrapper that puts the versioned GHC directory on PATH
    const cmdOf = (c) => { const rest = c.slice(c.indexOf('haskell:9') + 1); return rest[0] === 'sh' && rest[1] === '-c' ? rest.slice(4) : rest; };
    for (const c of calls) { assert.equal(cmdOf(c)[0] === 'ghc' || cmdOf(c)[0] === '/bin/chmod', true); assert.ok(c.includes('--read-only')); assert.equal(c[c.indexOf('--network') + 1], 'none'); }
    assert.ok(calls.some((c) => c.includes('PATH=/work/bin:/opt/ghc/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin')));
    assert.ok(calls.some((c) => cmdOf(c)[0] === '/bin/chmod'), 'the build step (chmod of the stand-in) goes through the engine, not the host');
  } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
});
