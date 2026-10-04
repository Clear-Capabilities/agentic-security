// HS-001: Haskell parser and original source locations.
// Suite "haskell-parser" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseHaskell, spanText, DEFAULT_PARSE_BUDGETS } from '../../src/language/haskell-parser.js';
import { loadHaskellGrammar, GRAMMAR_DATA, HASKELL_GRAMMAR_SHA256, grammarChecksum } from '../../src/language/haskell-grammar.js';
import { createHaskellAdapter } from '../../src/language/haskell-adapter.js';
import {
  registerLanguageProducer, isRegisteredLanguageProducer, runLanguageAnalysis, reconcileLanguageLedger, languageHealth,
} from '../../src/language/contracts.js';
import { computeScanHealth } from '../../src/pipeline/scan-health.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const scannerRoot = path.join(here, '../..');

// Asserts a span reads back as `expected` from the ORIGINAL source three ways:
// by byte range, by line/column, and (for single-line spans) by line text.
function assertSpan(src, span, expected, label = expected) {
  assert.equal(spanText(src, span), expected, `${label}: byte range`);
  const lines = src.split('\n');
  if (span.startLine === span.endLine) {
    assert.equal(lines[span.startLine - 1].slice(span.startColumn, span.endColumn), expected, `${label}: line/column`);
  } else {
    assert.ok(lines[span.startLine - 1].slice(span.startColumn).length > 0, `${label}: start column`);
    assert.ok(span.endLine > span.startLine, `${label}: multi-line`);
  }
}
const callTexts = (r) => r.calls.map((c) => c.callee);

const VALID = `{-# LANGUAGE OverloadedStrings #-}
module Demo.Main (main, run) where

import qualified Data.Map.Strict as M
import Data.List (sortBy, nub)
import System.Process (callCommand)

-- | Greets, with ünïcode in a comment.
data User = User { userName :: String, userAge :: Int } deriving (Show)

banner :: String
banner = "héllo → wörld"

run :: User -> IO ()
run u
  | userAge u > 18 = putStrLn (userName u)
  | otherwise = callCommand "ls"
  where helper = M.empty

main :: IO ()
main = do
  let u = User { userName = "bob", userAge = 3 }
  r <- readFile "x"
  run u
  print $ length (nub [1, 2, 3])
`;

test('[HS-001.AC01] valid files parse with function, import, call and expression spans mapped to original line, column and bytes', () => {
  const r = parseHaskell(VALID, { file: 'src/Demo/Main.hs' });
  assert.equal(r.status, 'parsed');
  assert.deepEqual(r.errors, []);
  assert.equal(r.module.name, 'Demo.Main');
  assert.deepEqual(r.module.exports, ['main', 'run']);

  // imports
  assert.equal(r.imports.length, 3);
  const [mapImp, listImp, procImp] = r.imports;
  assert.equal(mapImp.module, 'Data.Map.Strict');
  assert.equal(mapImp.qualified, true);
  assert.equal(mapImp.as, 'M');
  assert.deepEqual(listImp.items, ['sortBy', 'nub']);
  assert.equal(procImp.module, 'System.Process');
  assertSpan(VALID, mapImp.span, 'import qualified Data.Map.Strict as M');
  assertSpan(VALID, listImp.span, 'import Data.List (sortBy, nub)');
  assertSpan(VALID, procImp.moduleSpan, 'System.Process');

  // functions: names, clauses, guards, nested where binding, signature-less records
  const byName = Object.fromEntries(r.functions.map((f) => [f.name, f]));
  assert.ok(byName.run && byName.main && byName.banner && byName.helper);
  assert.equal(byName.run.arity, 1);
  assert.equal(byName.run.guardCount, 2);
  assert.equal(byName.run.scope, 'top');
  assert.equal(byName.helper.scope, 'where');
  assert.equal(byName.helper.parent, 'run');
  assert.ok(spanText(VALID, byName.run.span).startsWith('run u\n'));
  assert.ok(spanText(VALID, byName.run.span).endsWith('M.empty'));
  assert.equal(byName.run.span.startLine, VALID.split('\n').findIndex((l) => l.startsWith('run u')) + 1);
  assert.ok(r.signatures.some((s) => s.names.includes('main')));

  // calls
  const want = [
    ['putStrLn', 'putStrLn (userName u)'],
    ['callCommand', 'callCommand "ls"'],
    ['readFile', 'readFile "x"'],
    ['run', 'run u'],
    ['length', 'length (nub [1, 2, 3])'],
    ['nub', 'nub [1, 2, 3]'],
  ];
  for (const [callee, text] of want) {
    const c = r.calls.find((x) => x.callee === callee);
    assert.ok(c, `call ${callee} found`);
    assertSpan(VALID, c.span, text);
    assertSpan(VALID, c.calleeSpan, callee);
  }
  assert.equal(r.calls.find((x) => x.callee === 'callCommand').argCount, 1);
  // Names that are only patterns or definitions are not calls.
  assert.ok(!callTexts(r).includes('userName') || r.calls.filter((c) => c.callee === 'userName').every((c) => c.argCount >= 1));
  assert.ok(!callTexts(r).includes('u'));

  // Non-ASCII: byte offsets diverge from UTF-16 columns, and both stay right.
  const bannerFn = byName.banner;
  assertSpan(VALID, bannerFn.span, 'banner = "héllo → wörld"');
  assert.ok(bannerFn.span.endByte - bannerFn.span.startByte > bannerFn.span.endColumn - bannerFn.span.startColumn);
  assert.equal(r.calls.find((x) => x.callee === 'callCommand').span.startByte,
    Buffer.byteLength(VALID.slice(0, VALID.indexOf('callCommand "ls"')), 'utf8'));

  // expressions, records and do blocks
  assert.equal(r.doBlocks.length, 1);
  assert.equal(r.doBlocks[0].statements, 4);
  assert.equal(r.doBlocks[0].binds, 1);
  assert.ok(spanText(VALID, r.doBlocks[0].span).startsWith('do\n'));
  assert.ok(r.expressions.some((e) => e.kind === 'clause-body'));
  const construction = r.records.find((x) => x.kind === 'construction');
  assert.equal(construction.name, 'User');
  assert.deepEqual(construction.fields.map((f) => f.name), ['userName', 'userAge']);
  assertSpan(VALID, construction.span, 'User { userName = "bob", userAge = 3 }');
  const decl = r.records.find((x) => x.kind === 'declaration');
  assert.deepEqual(decl.fields.map((f) => f.name), ['userName', 'userAge']);
});

test('[HS-001.AC01] Bird and LaTeX literate files keep original line, column and byte mappings', () => {
  const bird = [
    'This prose mentions system "rm -rf /" and callCommand "no".',
    '',
    '> module Bird where',
    '> import System.Process (callCommand)',
    '> go :: IO ()',
    '> go = callCommand "echo hi"',
    '',
    'More prose with putStrLn "nope".',
    '',
  ].join('\n');
  const rb = parseHaskell(bird, { file: 'Bird.lhs' });
  assert.equal(rb.dialect, 'literate-bird');
  assert.equal(rb.status, 'parsed');
  assert.deepEqual(callTexts(rb), ['callCommand']);
  const bc = rb.calls[0];
  assert.equal(bc.span.startLine, 6);
  assert.equal(bc.span.startColumn, 7); // `> go = ` keeps the `>` marker column
  assertSpan(bird, bc.span, 'callCommand "echo hi"');
  assert.equal(rb.module.name, 'Bird');
  assert.equal(rb.imports[0].module, 'System.Process');
  assertSpan(bird, rb.imports[0].span, 'import System.Process (callCommand)');

  const latex = [
    '\\documentclass{article}',
    '\\begin{document}',
    'Text with putStrLn "no" here and system "rm".',
    '\\begin{code}',
    'module Lat where',
    'go = putStrLn "yes"',
    '\\end{code}',
    'more text foo bar',
    '\\begin{code}',
    'later = print 1',
    '\\end{code}',
    '\\end{document}',
    '',
  ].join('\n');
  const rl = parseHaskell(latex, { file: 'Lat.lhs' });
  assert.equal(rl.dialect, 'literate-latex');
  assert.equal(rl.status, 'parsed');
  assert.deepEqual(callTexts(rl), ['putStrLn', 'print']);
  assert.equal(rl.calls[0].span.startLine, 6);
  assert.equal(rl.calls[1].span.startLine, 10);
  assertSpan(latex, rl.calls[0].span, 'putStrLn "yes"');
  assertSpan(latex, rl.calls[1].span, 'print 1');
});

test('[HS-001.AC02] nested comments and attack-looking strings never become calls and stay visible as comments', () => {
  const src = `module Hostile where

{- outer {- inner callCommand "x" -} still comment: system "rm -rf /" -}

-- callCommand "line comment"
payload :: String
payload = "system (rm -rf /); callCommand \\"x\\" {- not a comment -}"

gapped :: String
gapped = "abc\\
         \\def system \\"y\\""

quote :: Char
quote = '"'

arrow a b = a --> b
  where (-->) x y = x

ok = putStrLn "fine"
`;
  const r = parseHaskell(src, { file: 'Hostile.hs' });
  assert.equal(r.status, 'parsed');
  assert.deepEqual(r.errors, []);
  assert.deepEqual(callTexts(r), ['putStrLn']);
  const nested = r.comments.find((c) => c.kind === 'block');
  assert.ok(nested, 'nested comment is recorded, not dropped');
  assert.ok(spanText(src, nested.span).startsWith('{- outer {- inner'));
  assert.ok(spanText(src, nested.span).endsWith('-}'));
  assert.ok(r.comments.some((c) => c.kind === 'line' && spanText(src, c.span) === '-- callCommand "line comment"'));
  const fnNames = r.functions.map((f) => f.name);
  assert.ok(fnNames.includes('payload') && fnNames.includes('gapped') && fnNames.includes('quote') && fnNames.includes('ok'));
});

test('[HS-001.AC02] CPP branches are both parsed, flagged conditional and disclosed; directive text is never code', () => {
  const src = `{-# LANGUAGE CPP #-}
module C where
#define EVIL callCommand "evil"
#if defined(mingw32_HOST_OS)
run = system "dir"
#else
run = system "ls"
#endif

after = putStrLn "x"
`;
  const r = parseHaskell(src, { file: 'C.hs' });
  assert.equal(r.status, 'parsed');
  const systemCalls = r.calls.filter((c) => c.callee === 'system');
  assert.equal(systemCalls.length, 2);
  assert.ok(systemCalls.every((c) => c.conditional));
  assert.deepEqual(systemCalls.map((c) => c.span.startLine), [5, 7]);
  assertSpan(src, systemCalls[0].span, 'system "dir"');
  assert.ok(!callTexts(r).includes('callCommand'));
  assert.equal(r.calls.find((c) => c.callee === 'putStrLn').conditional, false);
  const cpp = r.boundaries.find((b) => b.kind === 'cpp');
  assert.ok(cpp && cpp.count === 4);
  assert.ok(r.uncertainty.some((u) => u.kind === 'preprocessed'));
});

test('[HS-001.AC02] hsc, Template Haskell, quasi-quotes, FFI and generated sources are disclosed, not executed or guessed', () => {
  const th = `{-# LANGUAGE TemplateHaskell, QuasiQuotes #-}
module T where
import Foreign.C.Types
foreign import ccall "math.h sin" c_sin :: CDouble -> CDouble
$(deriveStuff ''Foo)
page = [html|<script>system "boom"</script>|]
q = [| callCommand "inside quote" |]
ok = putStrLn "x"
`;
  const r = parseHaskell(th, { file: 'T.hs' });
  const kinds = new Set(r.boundaries.map((b) => b.kind));
  for (const k of ['ffi', 'th-splice', 'th-name-quote', 'quasiquote', 'th-quote']) assert.ok(kinds.has(k), `boundary ${k}`);
  assert.ok(!callTexts(r).includes('system'), 'quasi-quote body is opaque');
  assert.ok(!callTexts(r).includes('callCommand'), 'quote body is opaque');
  assert.ok(callTexts(r).includes('putStrLn'));
  assert.equal(r.declarations.find((d) => d.kind === 'foreign').name, 'c_sin');
  assert.ok(r.uncertainty.some((u) => u.kind === 'generated-source'));
  assert.equal(r.complete, false);
  const qq = r.boundaries.find((b) => b.kind === 'quasiquote');
  assert.ok(spanText(th, qq.span).startsWith('[html|'));

  const hsc = `#include <stdio.h>
module H where
x = #{size struct stat} + 1
go = callCommand "a"
`;
  const rh = parseHaskell(hsc, { file: 'H.hsc' });
  assert.ok(rh.boundaries.some((b) => b.kind === 'hsc'));
  assert.deepEqual(callTexts(rh), ['callCommand']);
  assert.equal(rh.calls[0].span.startLine, 4);

  const gen = parseHaskell('-- Generated by happy; DO NOT EDIT\nmodule G where\nf = g 1\n', { file: 'G.hs' });
  assert.ok(gen.boundaries.some((b) => b.kind === 'generated'));
  assert.ok(parseHaskell('module Paths_foo where\nversion = mk 1\n', { file: 'Paths_foo.hs' }).boundaries.some((b) => b.kind === 'generated'));
});

test('[HS-001.AC02] syntax errors are recorded with locations and withhold the calls they would fabricate', () => {
  const src = `module Broken where

broken = system (readFile "x"

ok = putStrLn "fine"

bad = callCommand "oops

good = print 1
`;
  const r = parseHaskell(src, { file: 'Broken.hs' });
  assert.equal(r.status, 'parsed_with_errors');
  assert.equal(r.ok, true);
  const kinds = r.errors.map((e) => e.kind);
  assert.ok(kinds.includes('unclosed-bracket'));
  assert.ok(kinds.includes('unterminated-string'));
  const unclosed = r.errors.find((e) => e.kind === 'unclosed-bracket');
  assert.equal(unclosed.span.startLine, 3);
  assertSpan(src, unclosed.span, '(');
  assert.ok(unclosed.withheldCalls >= 1, 'the erroneous declaration reports the calls it withheld');
  assert.ok(r.errors.find((e) => e.kind === 'unterminated-string').withheldCalls >= 1);
  assert.deepEqual(callTexts(r).sort(), ['print', 'putStrLn']);
  assert.ok(r.uncertainty.some((u) => u.kind === 'partial-parse'));
  assert.equal(r.complete, false);
  assert.ok(r.functions.find((f) => f.name === 'broken').partial);

  const rc = parseHaskell('module C where\nf = g 1\n{- never closed\nh = system "x"\n', { file: 'C.hs' });
  assert.ok(rc.errors.some((e) => e.kind === 'unterminated-comment'));
  assert.deepEqual(callTexts(rc), ['g']);

  const stray = parseHaskell('module S where\nf = g 1)\nh = k 2\n', { file: 'S.hs' });
  assert.ok(stray.errors.some((e) => e.kind === 'unmatched-bracket'));
  assert.ok(callTexts(stray).includes('k'));
});

test('[HS-001.AC03] the shipped grammar loads offline with no GHC, checksum-verified and with licence provenance', () => {
  const g = loadHaskellGrammar();
  assert.equal(g.available, true);
  assert.equal(g.checksum, HASKELL_GRAMMAR_SHA256);
  assert.equal(grammarChecksum(GRAMMAR_DATA), HASKELL_GRAMMAR_SHA256);
  assert.match(g.grammar.license, /PolyForm/);
  assert.ok(g.grammar.origin && g.grammar.version);

  // Parse in a child process whose PATH holds nothing: no ghc, cabal, stack or nix can be found.
  const code = `
    import { parseHaskell } from ${JSON.stringify(path.join(scannerRoot, 'src/language/haskell-parser.js'))};
    const r = parseHaskell('module M where\\nmain = putStrLn "hi"\\n', { file: 'M.hs' });
    console.log(JSON.stringify({ status: r.status, calls: r.calls.map((c) => c.callee), gaps: r.gaps }));
  `;
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', code], { env: { PATH: '' }, encoding: 'utf8', timeout: 30_000 });
  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(JSON.parse(out.stdout), { status: 'parsed', calls: ['putStrLn'], gaps: [] });

  // It ships in the published package and never spawns a process.
  const pkg = JSON.parse(fs.readFileSync(path.join(scannerRoot, 'package.json'), 'utf8'));
  assert.ok(pkg.files.includes('src/'));
  for (const f of ['haskell-parser.js', 'haskell-grammar.js']) {
    const text = fs.readFileSync(path.join(scannerRoot, 'src/language', f), 'utf8');
    assert.doesNotMatch(text, /child_process|execSync|spawn/, `${f} must not execute anything`);
  }
});

test('[HS-001.AC03] absent or corrupt grammar and unavailable optional modes are explicit capability gaps that preserve other findings', async () => {
  const src = 'module M where\nmain = putStrLn "hi"\n';

  const absent = parseHaskell(src, { file: 'M.hs', grammarSource: () => null });
  assert.equal(absent.status, 'missing_grammar');
  assert.equal(absent.gaps[0].kind, 'missing-grammar');
  assert.deepEqual(absent.calls, []);
  const unreadable = parseHaskell(src, { file: 'M.hs', grammarSource: () => { throw new Error('EACCES'); } });
  assert.equal(unreadable.gaps[0].kind, 'missing-grammar');

  const tampered = { ...GRAMMAR_DATA, keywords: [...GRAMMAR_DATA.keywords, 'system'] };
  const corrupt = parseHaskell(src, { file: 'M.hs', grammarSource: () => tampered });
  assert.equal(corrupt.status, 'missing_grammar');
  assert.equal(corrupt.gaps[0].kind, 'corrupt-grammar');
  assert.equal(loadHaskellGrammar({ grammarSource: () => ({ ...GRAMMAR_DATA, keywords: 'nope' }) }).gap.kind, 'corrupt-grammar');

  // Optional GHC mode: reported as a gap, never run, and the shipped grammar still parses.
  const ghc = parseHaskell(src, { file: 'M.hs', mode: 'ghc' });
  assert.equal(ghc.status, 'parsed');
  assert.ok(ghc.gaps.some((g) => g.kind === 'optional-mode-unavailable' && g.mode === 'ghc'));
  assert.deepEqual(callTexts(ghc), ['putStrLn']);

  // Through the pipeline: the Haskell file is missing_grammar, the Nix finding survives, health is partial.
  if (!isRegisteredLanguageProducer('language:nix-test')) registerLanguageProducer({ id: 'language:nix-test', language: 'nix', capability: 'sast' });
  const nixFinding = { id: 'NIX-1', severity: 'low', file: 'flake.nix', line: 1, vuln: 'v', cwe: 'CWE-1', description: 'd', remediation: 'r', parser: 'REGEX', family: 'f' };
  const files = { 'src/A.hs': src, 'default.nix': '{ }', 'src/B.hs': src };
  const nixAdapter = { id: 'language:nix-test', language: 'nix', analyze: () => ({ findings: [nixFinding] }) };
  const run = await runLanguageAnalysis({ files, adapters: [createHaskellAdapter({ grammarSource: () => null }), nixAdapter] });
  assert.equal(run.ledger.byFile['src/A.hs']['language:haskell-parse'], 'missing_grammar');
  assert.equal(run.ledger.byFile['src/B.hs']['language:haskell-parse'], 'missing_grammar');
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].id, 'NIX-1');
  assert.deepEqual(reconcileLanguageLedger(run.ledger, files), { ok: true, errors: [] });
  const health = computeScanHealth({ scanMeta: { filesScanned: 3 }, languageCoverage: languageHealth(run) });
  assert.equal(health.status, 'partial');
  assert.ok(health.conditions.some((c) => /grammar/.test(c)));
});

test('[HS-001.AC03] syntax errors and opaque boundaries reach scan health through the pipeline adapter', async () => {
  const parses = {};
  const adapter = createHaskellAdapter({ onParse: (f, p) => { parses[f] = p; } });
  const files = {
    'src/Good.hs': 'module Good where\nmain = putStrLn "hi"\n',
    'src/Bad.hs': 'module Bad where\nf = g (1\n',
    'src/Th.hs': '{-# LANGUAGE QuasiQuotes #-}\nmodule Th where\nx = [sql|select 1|]\n',
  };
  const run = await runLanguageAnalysis({ files, adapters: [adapter] });
  assert.equal(run.ledger.byFile['src/Good.hs']['language:haskell-parse'], 'analyzed');
  assert.equal(run.ledger.byFile['src/Bad.hs']['language:haskell-parse'], 'unresolved');
  assert.equal(run.ledger.byFile['src/Th.hs']['language:haskell-parse'], 'unresolved');
  assert.ok(run.outcomes.some((o) => o.kind === 'unresolved-branch' && /syntax-error/.test(o.detail) && o.file === 'src/Bad.hs'));
  assert.ok(run.outcomes.some((o) => /opaque-boundary: quasiquote/.test(o.detail)));
  assert.equal(parses['src/Good.hs'].calls.length, 1);
  assert.equal(computeScanHealth({ languageCoverage: languageHealth(run) }).status, 'partial');
});

test('[HS-001.AC04] pathological nesting, malformed input and oversize files stop at named budgets without throwing', () => {
  const t0 = Date.now();
  const deepParens = parseHaskell(`f = ${'('.repeat(60_000)}x${')'.repeat(60_000)}\n`, { file: 'Deep.hs' });
  assert.equal(deepParens.status, 'budget_exceeded');
  assert.equal(deepParens.budget.name, 'maxDepth');
  assert.deepEqual(deepParens.calls, []);
  assert.equal(deepParens.complete, false);
  assert.ok(deepParens.errors.some((e) => e.kind === 'budget-exceeded'));

  const deepComments = parseHaskell(`${'{-'.repeat(50_000)}\nmain = x\n`, { file: 'C.hs' });
  assert.equal(deepComments.status, 'budget_exceeded');
  assert.equal(deepComments.budget.name, 'maxCommentNesting');

  const deepDo = parseHaskell(`f = ${'do '.repeat(5000)}x\n`, { file: 'Do.hs' });
  assert.equal(deepDo.status, 'budget_exceeded');

  const big = Array.from({ length: 1200 }, (_, i) => `fn${i} x = helper${i} x\n`).join('');
  assert.equal(parseHaskell(big, { file: 'Big.hs', budgets: { maxBytes: 1000 } }).budget.name, 'maxBytes');
  assert.equal(parseHaskell(big, { file: 'Big.hs', budgets: { maxTokens: 100 } }).budget.name, 'maxTokens');
  assert.equal(parseHaskell(big, { file: 'Big.hs', budgets: { maxSteps: 500 } }).budget.name, 'maxSteps');
  assert.equal(parseHaskell(big, { file: 'Big.hs', budgets: { deadlineMs: -1 } }).budget.name, 'deadlineMs');

  // Malformed bytes and truncations never throw.
  const junk = ['\u0000\u0001\u0002', '"""\'\'\'{-{-', '}}}))){{{((([[[', 'module', 'module X where\n  where where where\n  = = =', 'f = \\', 'x = [| |]', '{-# LANGUAGE'];
  for (const j of junk) {
    const r = parseHaskell(j, { file: 'J.hs' });
    assert.ok(['parsed', 'parsed_with_errors', 'budget_exceeded'].includes(r.status), `${JSON.stringify(j)} -> ${r.status}`);
  }
  for (let cut = 0; cut < VALID.length; cut += 7) {
    const r = parseHaskell(VALID.slice(0, cut), { file: 'Cut.hs' });
    assert.notEqual(r.status, 'failed', `truncation at ${cut}`);
  }

  // A legitimately large file still parses fully, inside the default budgets.
  const huge = Array.from({ length: 12_000 }, (_, i) => `fn${i} x = helper${i} x (g${i} 1)\n`).join('');
  const rh = parseHaskell(huge, { file: 'Huge.hs' });
  assert.equal(rh.status, 'parsed');
  assert.equal(rh.calls.length, 24_000);
  assert.equal(rh.functions.length, 12_000);
  assert.ok(DEFAULT_PARSE_BUDGETS.maxBytes > Buffer.byteLength(huge));
  assert.ok(Date.now() - t0 < 60_000, 'bounded wall clock');
});

test('[HS-001.AC04] a budget hit in one Haskell file leaves other files and other languages analyzed', async () => {
  if (!isRegisteredLanguageProducer('language:nix-test')) registerLanguageProducer({ id: 'language:nix-test', language: 'nix', capability: 'sast' });
  const nixFinding = { id: 'NIX-2', severity: 'low', file: 'flake.nix', line: 1, vuln: 'v', cwe: 'CWE-1', description: 'd', remediation: 'r', parser: 'REGEX', family: 'f' };
  const files = {
    'src/Bomb.hs': `f = ${'('.repeat(5000)}x\n`,
    'src/Slow.hs': Array.from({ length: 4000 }, (_, i) => `fn${i} x = h x\n`).join(''),
    'src/Fine.hs': 'module Fine where\nmain = putStrLn "hi"\n',
    'flake.nix': '{ }',
  };
  const parses = {};
  const adapters = [
    createHaskellAdapter({ budgets: { maxDepth: 50 }, onParse: (f, p) => { parses[f] = p; } }),
    { id: 'language:nix-test', language: 'nix', analyze: () => ({ findings: [nixFinding] }) },
  ];
  const run = await runLanguageAnalysis({ files, adapters });
  assert.equal(run.ledger.byFile['src/Bomb.hs']['language:haskell-parse'], 'unresolved');
  assert.equal(run.ledger.byFile['src/Fine.hs']['language:haskell-parse'], 'analyzed');
  assert.equal(parses['src/Fine.hs'].calls.length, 1);
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].id, 'NIX-2');
  assert.deepEqual(reconcileLanguageLedger(run.ledger, files), { ok: true, errors: [] });
  assert.ok(run.outcomes.some((o) => /budget exceeded: maxDepth/.test(o.detail)));

  // A deadline overrun is reported as timed_out, not a crash.
  const slow = await runLanguageAnalysis({ files: { 'src/Slow.hs': files['src/Slow.hs'] }, adapters: [createHaskellAdapter({ budgets: { deadlineMs: -1 } })] });
  assert.equal(slow.ledger.byFile['src/Slow.hs']['language:haskell-parse'], 'timed_out');
});
