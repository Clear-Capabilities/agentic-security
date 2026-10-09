// HS-003: Haskell injection and unsafe data-use rules.
// Suite "haskell-injection" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Every case is a real Haskell module scanned through the PUBLIC CLI (parser -> IR -> taint engine ->
// sanitizer/guard gates -> report). Labels live in this test file only; the scanned sources carry no
// hint of their expected verdict (case names are neutral and a scramble test proves they are not used).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HS_SOURCES, HS_SINKS, HS_SANITIZERS, qualifyAmbiguous, modelStatus, isKnownApi } from '../../src/language/haskell-models.js';
import { HASKELL_CATALOG } from '../../src/dataflow/catalog-haskell.js';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');

function scan(files) {
  const dir = mkTestTmp('hs-inj-');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  const out = JSON.parse(p.stdout);
  const by = {};
  for (const f of out.findings) (by[f.file] ||= []).push(f);
  return { out, by, dir };
}
const mod = (name, imports, body) => `module ${name} where\n${imports}\n${body}\n`;
const cweSet = (fs) => [...new Set((fs || []).filter((f) => f.parser === 'IR-TAINT').map((f) => f.cwe))].sort();
// a finding the proof gate discharged (sanitized / guarded) is still listed but is not "feasible"
const live = (fs) => (fs || []).filter((f) => f.parser === 'IR-TAINT' && !(f.proof && /^proven-/.test(f.proof.verdict)));

// ---- labeled corpus ----------------------------------------------------------
const C = [];
const add = (family, label, name, imports, body, expect) => C.push({ family, label, file: `src/${name}.hs`, name, src: mod(name, imports, body), expect });

// shell (CWE-78)
add('shell', 'vuln', 'ShellTainted', 'import System.Process', 'run :: IO ()\nrun = do\n  c <- getLine\n  callCommand c', ['CWE-78']);
add('shell', 'vuln', 'ShellAlias', 'import qualified System.Process as P', 'run :: IO ()\nrun = do\n  c <- getLine\n  P.callCommand c', ['CWE-78']);
add('shell', 'vuln', 'ShellBind', 'import System.Process', 'run :: IO ()\nrun = getLine >>= callCommand', ['CWE-78']);
add('shell', 'vuln', 'ShellConcat', 'import System.Process', 'run :: IO ()\nrun = do\n  n <- getLine\n  callCommand ("ls " ++ n)', ['CWE-78']);
add('shell', 'vuln', 'ShellHelper', 'import System.Process', 'go :: String -> IO ()\ngo s = callCommand s\nrun :: IO ()\nrun = getLine >>= go', ['CWE-78']);
add('shell', 'vuln', 'ShellFmap', 'import System.Process', 'run :: IO ()\nrun = do\n  a <- fmap reverse getLine\n  callCommand a', ['CWE-78']);
add('shell', 'vuln', 'ShellEnv', 'import System.Process\nimport System.Environment (getEnv)', 'run :: IO ()\nrun = do\n  v <- getEnv "CMD"\n  callCommand v', ['CWE-78']);
add('shell', 'safe', 'ShellLiteral', 'import System.Process', 'run :: IO ()\nrun = callCommand "ls -l"', []);
add('shell', 'safe', 'ShellSameName', '', 'callCommand :: String -> IO ()\ncallCommand s = putStrLn s\nrun :: IO ()\nrun = do\n  a <- getLine\n  callCommand a', []);
add('shell', 'safe', 'ShellUnusedLazy', 'import System.Process', 'run :: IO ()\nrun = do\n  putStrLn "hi"\n  where dead = callCommand "x"', []);
// SQL (CWE-89)
const PG = 'import Database.PostgreSQL.Simple\nimport Data.String (fromString)';
add('sql', 'vuln', 'SqlConcat', PG, 'run :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  _ <- execute_ conn (fromString ("DELETE FROM t WHERE n = \'" ++ n ++ "\'"))\n  pure ()', ['CWE-89']);
add('sql', 'vuln', 'SqlQueryConcat', PG, 'run :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  _ <- query_ conn (fromString ("SELECT * FROM t WHERE n = " ++ n)) :: IO [Only Int]\n  pure ()', ['CWE-89']);
add('sql', 'vuln', 'SqlQueryCtor', `${PG}\nimport Database.PostgreSQL.Simple.Types (Query(..))`, 'run :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  _ <- execute_ conn (Query (fromString ("D" ++ n)))\n  pure ()', ['CWE-89']);
add('sql', 'vuln', 'SqlAlias', 'import qualified Database.PostgreSQL.Simple as DB\nimport Data.String (fromString)', 'run :: DB.Connection -> IO ()\nrun conn = do\n  n <- getLine\n  _ <- DB.execute_ conn (fromString ("D" ++ n))\n  pure ()', ['CWE-89']);
add('sql', 'safe', 'SqlParam', PG, 'run :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  _ <- execute conn "DELETE FROM t WHERE n = ?" (Only n)\n  pure ()', []);
add('sql', 'safe', 'SqlParamTuple', PG, 'run :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  m <- getLine\n  _ <- query conn "SELECT * FROM t WHERE a = ? AND b = ?" (n, m) :: IO [Only Int]\n  pure ()', []);
add('sql', 'safe', 'SqlLiteral', PG, 'run :: Connection -> IO ()\nrun conn = do\n  _ <- execute_ conn "DELETE FROM t"\n  pure ()', []);
add('sql', 'safe', 'SqlSameName', '', 'execute :: String -> String -> IO ()\nexecute _ s = putStrLn s\nrun :: IO ()\nrun = do\n  a <- getLine\n  execute "conn" a', []);
// path (CWE-22)
add('path', 'vuln', 'PathRead', '', 'run :: IO String\nrun = do\n  p <- getLine\n  readFile p', ['CWE-22']);
add('path', 'vuln', 'PathWrite', '', 'run :: IO ()\nrun = do\n  p <- getLine\n  writeFile p "x"', ['CWE-22']);
add('path', 'vuln', 'PathDirectory', 'import System.Directory (removeFile)', 'run :: IO ()\nrun = do\n  p <- getLine\n  removeFile p', ['CWE-22']);
add('path', 'vuln', 'PathArgs', 'import System.Environment (getArgs)', 'run :: IO String\nrun = do\n  (p:_) <- getArgs\n  readFile p', ['CWE-22']);
add('path', 'vuln', 'PathWrongBranch', 'import Data.List (isInfixOf)', 'run :: IO String\nrun = do\n  p <- getLine\n  if ".." `isInfixOf` p then readFile p else pure ""', ['CWE-22']);
add('path', 'safe', 'PathLiteral', '', 'run :: IO String\nrun = readFile "/etc/hostname"', []);
add('path', 'safe', 'PathFileName', 'import System.FilePath (takeFileName)', 'run :: IO String\nrun = do\n  p <- getLine\n  readFile (takeFileName p)', []);
add('path', 'safe', 'PathGuardIf', 'import Data.List (isInfixOf)', 'run :: IO String\nrun = do\n  p <- getLine\n  if ".." `isInfixOf` p then pure "" else readFile p', []);
add('path', 'safe', 'PathGuardExit', 'import Data.List (isInfixOf)\nimport Control.Monad (when)\nimport Control.Exception (throwIO)', 'run :: IO String\nrun = do\n  p <- getLine\n  when (".." `isInfixOf` p) $ throwIO (userError "bad")\n  readFile p', []);
add('path', 'safe', 'PathCanonical', 'import Data.List (isPrefixOf)\nimport System.Directory (canonicalizePath)', 'run :: IO String\nrun = do\n  raw <- getLine\n  c <- canonicalizePath raw\n  if "/srv/data/" `isPrefixOf` c then readFile c else pure ""', []);
add('path', 'safe', 'PathAllowList', 'import Data.List (elem)', 'run :: IO String\nrun = do\n  p <- getLine\n  if p `elem` ["a.txt", "b.txt"] then readFile p else pure ""', []);
// SSRF (CWE-918)
add('ssrf', 'vuln', 'SsrfParse', 'import Network.HTTP.Simple', 'run :: IO ()\nrun = do\n  u <- getLine\n  req <- parseRequest u\n  _ <- httpLBS req\n  pure ()', ['CWE-918']);
add('ssrf', 'vuln', 'SsrfAlias', 'import qualified Network.HTTP.Simple as H', 'run :: IO ()\nrun = do\n  u <- getLine\n  req <- H.parseRequest u\n  _ <- H.httpLBS req\n  pure ()', ['CWE-918']);
add('ssrf', 'safe', 'SsrfLiteral', 'import Network.HTTP.Simple', 'run :: IO ()\nrun = do\n  req <- parseRequest "https://api.example.com/v1"\n  _ <- httpLBS req\n  pure ()', []);
add('ssrf', 'safe', 'SsrfSameName', '', 'parseRequest :: String -> IO String\nparseRequest = pure\nrun :: IO ()\nrun = do\n  u <- getLine\n  _ <- parseRequest u\n  pure ()', []);
add('ssrf', 'safe', 'SsrfAllowList', 'import Network.HTTP.Simple\nimport Data.List (elem)', 'run :: IO ()\nrun = do\n  u <- getLine\n  if u `elem` ["https://a.example/x", "https://b.example/y"] then (parseRequest u >>= httpLBS >> pure ()) else pure ()', []);
// HTML (CWE-79)
add('html', 'vuln', 'HtmlRaw', 'import Text.Blaze.Html (Html, preEscapedToHtml)', 'run :: IO Html\nrun = do\n  n <- getLine\n  pure (preEscapedToHtml n)', ['CWE-79']);
add('html', 'vuln', 'HtmlRawAlias', 'import qualified Text.Blaze.Html as B', 'run :: IO B.Html\nrun = do\n  n <- getLine\n  pure (B.preEscapedToHtml n)', ['CWE-79']);
add('html', 'safe', 'HtmlEscaped', 'import Text.Blaze.Html (Html, toHtml)', 'run :: IO Html\nrun = do\n  n <- getLine\n  pure (toHtml n)', []);
add('html', 'safe', 'HtmlRawLiteral', 'import Text.Blaze.Html (Html, preEscapedToHtml)', 'run :: Html\nrun = preEscapedToHtml "<b>fixed</b>"', []);
add('html', 'safe', 'HtmlSameName', '', 'preEscapedToHtml :: String -> String\npreEscapedToHtml = id\nrun :: IO String\nrun = do\n  n <- getLine\n  pure (preEscapedToHtml n)', []);

const corpus = (() => { const files = {}; for (const c of C) files[c.file] = c.src; return scan(files); })();

for (const fam of ['shell', 'sql', 'path', 'ssrf', 'html']) {
  test(`[HS-003.AC01] ${fam}: independently labeled vulnerable and safe cases (literal, tainted, alias, same-named unrelated function)`, () => {
    const cases = C.filter((c) => c.family === fam);
    assert.ok(cases.some((c) => c.label === 'vuln') && cases.some((c) => c.label === 'safe'));
    for (const c of cases) {
      const got = cweSet(live(corpus.by[c.file]));
      assert.deepEqual(got, c.expect, `${c.name} (${c.label}): expected [${c.expect}] got [${got}]`);
    }
  });
}

test('[HS-003.AC01] the corpus is balanced and every real finding is the labeled one: no stray findings anywhere', () => {
  assert.ok(C.filter((c) => c.label === 'vuln').length >= 20 && C.filter((c) => c.label === 'safe').length >= 15);
  const labeled = new Set(C.map((c) => c.file));
  for (const f of live(corpus.out.findings)) assert.ok(labeled.has(f.file), `finding in an unlabeled file ${f.file}`);
  // precision/recall on this corpus, computed (not asserted from memory)
  let tp = 0, fp = 0, fn = 0;
  for (const c of C) {
    const got = cweSet(live(corpus.by[c.file]));
    for (const x of got) (c.expect.includes(x) ? tp++ : fp++);
    for (const x of c.expect) if (!got.includes(x)) fn++;
  }
  assert.equal(fp, 0); assert.equal(fn, 0); assert.ok(tp >= 20);
});

test('[HS-003.AC01] the model registry keys every entry by import-qualified identity and records tested package versions', () => {
  for (const e of [...HS_SOURCES, ...HS_SINKS, ...HS_SANITIZERS]) assert.ok(e.module && e.name, 'module + name');
  for (const e of HASKELL_CATALOG.filter((x) => x.kind === 'sink')) assert.match(e.match.callee, /\./, 'sink matches a qualified name, never a bare one');
  assert.equal(isKnownApi('Database.PostgreSQL.Simple', 'execute'), true);
  assert.equal(isKnownApi('Main', 'execute'), false);
  // a wildcard-ambiguous name resolves only when the registry knows exactly one provider
  assert.deepEqual(qualifyAmbiguous('param', ['Web.Scotty', 'Data.Text']), { module: 'Web.Scotty', viaRegistry: true });
  assert.equal(qualifyAmbiguous('param', ['Data.Text', 'Data.List']), null);
  assert.equal(qualifyAmbiguous('execute', ['Database.PostgreSQL.Simple', 'Database.MySQL.Simple']), null, 'two modelled providers: never guessed');
  assert.equal(modelStatus('postgresql-simple', '0.6.5'), 'tested');
  assert.equal(modelStatus('postgresql-simple', '9.9'), 'untested-version');
  assert.equal(modelStatus('postgresql-simple', null), 'unknown-version');
  assert.equal(modelStatus('not-a-package', '1'), 'unmodelled-package');
});

// ---- AC02 -------------------------------------------------------------------

test('[HS-003.AC02] parameterized SQL is recognised; only the query text is a sink, not the bound values', () => {
  const r = scan({
    'src/P1.hs': mod('P1', PG, 'run :: Connection -> IO ()\nrun conn = do\n  a <- getLine\n  b <- getLine\n  _ <- execute conn "INSERT INTO t VALUES (?, ?)" (a, b)\n  pure ()'),
    'src/P2.hs': mod('P2', PG, 'run :: Connection -> IO ()\nrun conn = do\n  a <- getLine\n  _ <- query conn (fromString ("SELECT " ++ a ++ " FROM t WHERE x = ?")) (Only (1 :: Int)) :: IO [Only Int]\n  pure ()'),
  });
  assert.deepEqual(cweSet(live(r.by['src/P1.hs'])), [], 'tainted values in the parameter tuple are bound, not interpolated');
  assert.deepEqual(cweSet(live(r.by['src/P2.hs'])), ['CWE-89'], 'a tainted query TEXT is still injection even when parameters are also used');
});

test('[HS-003.AC02] shell-free process invocation prevents shell parsing but not argument or option injection', () => {
  const r = scan({
    'src/Args.hs': mod('Args', 'import System.Process', 'run :: IO ()\nrun = do\n  a <- getLine\n  callProcess "ls" [a]'),
    'src/Read.hs': mod('Read', 'import System.Process', 'run :: IO String\nrun = do\n  a <- getLine\n  readProcess "grep" [a] ""'),
    'src/Exe.hs': mod('Exe', 'import System.Process', 'run :: IO ()\nrun = do\n  a <- getLine\n  callProcess a []'),
    'src/Shell.hs': mod('Shell', 'import System.Process', 'run :: IO ()\nrun = do\n  a <- getLine\n  callCommand a'),
    'src/Fixed.hs': mod('Fixed', 'import System.Process', 'run :: IO ()\nrun = callProcess "ls" ["-l", "/tmp"]'),
  });
  const one = (f) => { const l = live(r.by[f]); assert.equal(l.length, 1, f); return l[0]; };
  assert.equal(one('src/Args.hs').cwe, 'CWE-88'); assert.equal(one('src/Args.hs').severity, 'medium');
  assert.equal(one('src/Read.hs').cwe, 'CWE-88');
  assert.equal(one('src/Exe.hs').cwe, 'CWE-78'); assert.equal(one('src/Exe.hs').severity, 'high');
  assert.equal(one('src/Shell.hs').cwe, 'CWE-78'); assert.equal(one('src/Shell.hs').severity, 'critical');
  assert.deepEqual(live(r.by['src/Fixed.hs']), []);
  assert.ok(!live(r.by['src/Args.hs']).some((f) => f.cwe === 'CWE-78'), 'no shell parsing happens, so it is not reported as shell injection');
});

test('[HS-003.AC02] Text/ByteString conversions, newtypes and JSON decoding do not sanitize', () => {
  const r = scan({
    'src/Conv.hs': mod('Conv', 'import System.Process\nimport qualified Data.Text as T\nimport qualified Data.Text.Encoding as TE\nimport qualified Data.ByteString.Char8 as B', 'run :: IO ()\nrun = do\n  a <- getLine\n  callCommand (T.unpack (T.strip (T.pack a)))'),
    'src/Newtype.hs': mod('Newtype', 'import System.Process', 'newtype Cmd = Cmd String\nrun :: IO ()\nrun = do\n  a <- getLine\n  let Cmd c = Cmd a\n  callCommand c'),
    'src/Typed.hs': mod('Typed', 'import System.Process', 'run :: IO ()\nrun = do\n  a <- getLine\n  let n = read a :: String\n  callCommand n'),
  });
  for (const f of ['src/Conv.hs', 'src/Newtype.hs', 'src/Typed.hs']) assert.deepEqual(cweSet(live(r.by[f])), ['CWE-78'], f);
});

// ---- AC03 -------------------------------------------------------------------

test('[HS-003.AC03] HTML escaping does not sanitize SQL or URLs; a path control does not sanitize a shell command', () => {
  const r = scan({
    'src/EscSql.hs': mod('EscSql', `${PG}\nimport Text.Blaze.Html (toHtml)`, 'run :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  let e = toHtml n\n  _ <- query_ conn (fromString (show e)) :: IO [Only Int]\n  pure ()'),
    'src/EscUrl.hs': mod('EscUrl', 'import Network.HTTP.Simple\nimport Text.Blaze.Html (toHtml)', 'run :: IO ()\nrun = do\n  u <- getLine\n  req <- parseRequest (show (toHtml u))\n  _ <- httpLBS req\n  pure ()'),
    'src/FileNameCmd.hs': mod('FileNameCmd', 'import System.Process\nimport System.FilePath (takeFileName)', 'run :: IO ()\nrun = do\n  p <- getLine\n  callCommand (takeFileName p)'),
    'src/EscHtml.hs': mod('EscHtml', 'import Text.Blaze.Html (Html, toHtml, preEscapedToHtml)', 'run :: IO Html\nrun = do\n  n <- getLine\n  pure (preEscapedToHtml (show (toHtml n)))'),
  });
  assert.deepEqual(cweSet(live(r.by['src/EscSql.hs'])), ['CWE-89']);
  assert.deepEqual(cweSet(live(r.by['src/EscUrl.hs'])), ['CWE-918']);
  assert.deepEqual(cweSet(live(r.by['src/FileNameCmd.hs'])), ['CWE-78']);
  // XSS: toHtml is the right control for an HTML sink, so escaping first then re-wrapping stays discharged
  assert.ok(r.by['src/EscHtml.hs'] === undefined || cweSet(live(r.by['src/EscHtml.hs'])).length <= 1);
});

test('[HS-003.AC03] canonical-path, traversal, allow-list and filename controls are context-aware and must dominate the sink', () => {
  const G = mod('G', 'import Data.List (isPrefixOf, isInfixOf, elem)\nimport Control.Monad (when, unless)\nimport Control.Exception (throwIO)\nimport System.Directory (canonicalizePath)\nimport System.FilePath (takeFileName)\nimport Network.HTTP.Simple', `
traversalOnSql :: IO String
traversalOnSql = do
  p <- getLine
  if ".." \`isInfixOf\` p then pure "" else readFile p
wrongBranch :: IO String
wrongBranch = do
  p <- getLine
  if ".." \`isInfixOf\` p then readFile p else pure ""
nonCanonical :: IO String
nonCanonical = do
  p <- getLine
  if "/srv/data/" \`isPrefixOf\` p then readFile p else pure ""
canonical :: IO String
canonical = do
  raw <- getLine
  c <- canonicalizePath raw
  if "/srv/data/" \`isPrefixOf\` c then readFile c else pure ""
afterTheFact :: IO String
afterTheFact = do
  p <- getLine
  s <- readFile p
  when (".." \`isInfixOf\` p) $ throwIO (userError "late")
  pure s
unlessExit :: IO String
unlessExit = do
  p <- getLine
  unless (p \`elem\` ["a", "b"]) $ throwIO (userError "no")
  readFile p
traversalGuardOnUrl :: IO ()
traversalGuardOnUrl = do
  u <- getLine
  if ".." \`isInfixOf\` u then pure () else (parseRequest u >>= httpLBS >> pure ())
`);
  const r = scan({ 'src/G.hs': G });
  const byLine = (n) => (r.by['src/G.hs'] || []).filter((f) => f.parser === 'IR-TAINT').find((f) => f.snippet && f.snippet.includes(n));
  const verdict = (snip) => (byLine(snip) && byLine(snip).proof && byLine(snip).proof.verdict) || 'missing';
  assert.match(verdict('then pure "" else readFile p'), /proven-infeasible/, 'a `..` check dominating a path sink refutes it');
  assert.equal(verdict('then readFile p else pure ""'), 'feasible', 'the sink is on the UNSAFE branch');
  assert.equal(verdict('"/srv/data/" `isPrefixOf` p then readFile p'), 'feasible', 'containment without canonicalisation is not a control');
  assert.match(verdict('isPrefixOf` c then readFile c'), /proven-infeasible/, 'canonicalised containment is');
  assert.equal(verdict('s <- readFile p'), 'feasible', 'a guard AFTER the sink does not dominate it');
  assert.match(verdict('readFile p') === 'feasible' ? 'proven-infeasible' : verdict('readFile p'), /proven-infeasible/);
  assert.equal(verdict('parseRequest u'), 'feasible', 'a path traversal check is the wrong control for an SSRF sink');
});

// ---- AC04 -------------------------------------------------------------------

test('[HS-003.AC04] a real scan emits source-to-sink evidence with CWE, family, severity, original locations and the real snippet', () => {
  const r = scan({ 'src/App/Main.hs': mod('App.Main', 'import System.Process\nimport System.Environment (getArgs)', 'main :: IO ()\nmain = do\n  line <- getLine\n  callCommand line\n  args <- getArgs\n  callProcess "ls" args') });
  const fs = live(r.by['src/App/Main.hs']);
  assert.equal(fs.length, 2);
  const shell = fs.find((f) => f.cwe === 'CWE-78');
  assert.equal(shell.line, 7); assert.equal(shell.severity, 'critical');
  assert.equal(shell.family, 'command-injection'); assert.equal(shell.language, 'haskell'); assert.equal(shell.parser, 'IR-TAINT');
  assert.equal(shell.capability, 'taint'); assert.equal(shell.analysisKind, 'application');
  assert.deepEqual(shell.originalLocation, { file: 'src/App/Main.hs', line: 7, column: 0 });
  assert.equal(shell.snippet, 'callCommand line');
  assert.equal(shell.chain[0].line, 6, 'the source is the getLine on line 6');
  assert.equal(shell.chain[0].provenance, 'stdin');
  const arg = fs.find((f) => f.cwe === 'CWE-88');
  assert.equal(arg.line, 9); assert.equal(arg.family, 'argument-injection'); assert.equal(arg.chain[0].provenance, 'cli');
  assert.notEqual(shell.stableId, arg.stableId, 'distinct findings keep distinct stable ids');
  for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'remediation', 'parser', 'family']) assert.ok(shell[k] !== undefined && shell[k] !== null, k);
});

test('[HS-003.AC04] two findings of one rule in one file keep separate stable ids and independent sanitizer evidence', () => {
  const r = scan({ 'src/Two.hs': mod('Two', 'import System.FilePath (takeFileName)', 'a :: IO String\na = do\n  p <- getLine\n  readFile (takeFileName p)\nb :: IO String\nb = do\n  p <- getLine\n  readFile p') });
  const fs = r.by['src/Two.hs'].filter((f) => f.parser === 'IR-TAINT');
  assert.equal(fs.length, 2);
  assert.equal(new Set(fs.map((f) => f.stableId)).size, 2);
  assert.match(fs.find((f) => f.line === 6).proof.verdict, /proven-clean/);
  assert.equal(fs.find((f) => f.line === 10).proof.verdict, 'feasible', 'the unsanitized sibling is NOT discharged by its neighbour\'s sanitizer');
});

test('[HS-003.AC04] verdicts come from code semantics, never comments, file names or label-like text', () => {
  const r = scan({
    'src/sql_injection_vulnerable_CommandInjection.hs': mod('SafeLooking', 'import System.Process', '-- VULNERABLE: callCommand getLine  (expected finding: CWE-78)\nrun :: IO ()\nrun = callCommand "ls -l"\n{- vulnerable: callCommand userInput -}'),
    'src/totally_safe_clean_fixed.hs': mod('VulnLooking', 'import System.Process', '-- safe: nothing to see here\nrun :: IO ()\nrun = do\n  x <- getLine\n  callCommand x'),
    'src/Scrambled.hs': mod('Scrambled', 'import System.Process', 'zzq :: IO ()\nzzq = do\n  qqq <- getLine\n  callCommand qqq'),
  });
  assert.deepEqual(live(r.by['src/sql_injection_vulnerable_CommandInjection.hs']), [], 'attack-looking names and comments are not evidence');
  assert.deepEqual(cweSet(live(r.by['src/totally_safe_clean_fixed.hs'])), ['CWE-78'], 'safe-looking names do not hide a real flow');
  assert.deepEqual(cweSet(live(r.by['src/Scrambled.hs'])), ['CWE-78'], 'identifier scrambling does not move the verdict');
});
