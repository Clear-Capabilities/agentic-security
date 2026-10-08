// Haskell opaque boundaries: CPP conditionals, safe Template Haskell declarations, inert quasi-quotes.
//
// Every behaviour here is pinned in BOTH directions: the safe case reports fewer `unresolved` outcomes, and the unsafe or
// undecidable twin reports exactly what it reported before (the boundary stays, the file stays unresolved, both CPP
// branches are kept). Fixtures are written for this file; nothing reads a label or a fixture name.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHaskell, spanText } from '../../src/language/haskell-parser.js';
import { createHaskellAdapter } from '../../src/language/haskell-adapter.js';
import { runLanguageAnalysis } from '../../src/language/contracts.js';
import { assessLanguageAssurance } from '../../src/language/assurance.js';
import { deriveCppContext, rangeHull } from '../../src/language/haskell-cpp.js';
import { parseVersionRange } from '../../src/language/haskell-manifests.js';
import { preprocessForSyntax } from '../../src/language/haskell-parser.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const parse = (src, opts = {}) => parseHaskell(src, { file: 'M.hs', ...opts });
const callees = (r) => r.calls.map((c) => c.callee);
const kinds = (r) => r.boundaries.map((b) => b.kind).sort();
const cppOf = (r) => r.boundaries.find((b) => b.kind === 'cpp');

async function outcomeOf(files, opts = {}) {
  const run = await runLanguageAnalysis({ files, adapters: [createHaskellAdapter(opts)] });
  return Object.fromEntries(Object.entries(run.ledger.byFile).map(([f, v]) => [f, v['language:haskell-parse']]));
}

// ── CPP: decided in the file ─────────────────────────────────────────────────────────────────────────────────────

test('[boundaries.cpp] #if 0 keeps only the #else branch; the dead branch is overwritten and locations stay exact', () => {
  const src = `module M where
import System.Process
#if 0
legacy = callCommand "dead"
#else
live = callCommand "alive"
#endif
tail1 = putStrLn "t"
`;
  const r = parse(src);
  assert.equal(r.status, 'parsed');
  assert.ok(!callees(r).includes('callCommand') || r.calls.filter((c) => c.callee === 'callCommand').length === 1, 'only the live call survives');
  const live = r.calls.find((c) => c.callee === 'callCommand');
  assert.equal(spanText(src, live.span), 'callCommand "alive"');
  assert.equal(live.span.startLine, 6);
  assert.equal(live.conditional, false, 'a decided live branch is not conditional');
  assert.ok(!r.functions.some((f) => f.name === 'legacy'), 'the dead definition does not exist');
  assert.ok(r.functions.some((f) => f.name === 'live'));
  const cpp = cppOf(r);
  assert.equal(cpp.decided, 1, 'one #if decided (the #else follows from it)');
  assert.equal(cpp.undecided, 0);
  assert.equal(cpp.deadLines, 1);
});

test('[boundaries.cpp] #define / #undef decide #if, #ifdef and #ifndef; nothing is decided from a macro the file never mentions', () => {
  const decided = parse(`module M where
#define FEATURE 1
#define OFF 0
#ifdef FEATURE
a = f1 x
#endif
#if FEATURE && !OFF
b = f2 x
#endif
#if OFF
c = f3 x
#endif
#ifndef FEATURE
d = f4 x
#endif
#undef FEATURE
#ifdef FEATURE
e = f5 x
#else
g = f6 x
#endif
`);
  assert.deepEqual(callees(decided).sort(), ['f1', 'f2', 'f6']);
  assert.equal(cppOf(decided).undecided, 0);

  // the same shapes over a macro nothing in the file defines: every branch stays
  const open = parse(`module M where
#ifdef SOMETHING_ELSEWHERE
a = f1 x
#else
b = f2 x
#endif
#if UNDEFINED_NUMBER
c = f3 x
#endif
`);
  assert.deepEqual(callees(open).sort(), ['f1', 'f2', 'f3'], 'an undecidable conditional keeps the union');
  assert.ok(open.calls.every((c) => c.conditional), 'and flags every call as conditional');
  assert.equal(cppOf(open).undecided, 2);
  assert.equal(cppOf(open).decided, 0);
});

test('[boundaries.cpp] #elif chains, nesting and three-valued &&/||', () => {
  const r = parse(`module M where
#define V 2
#if V == 1
a = f1 x
#elif V == 2
b = f2 x
#elif V == 2
c = f3 x
#else
d = f4 x
#endif
#if 0
#if UNKNOWN_THING
e = f5 x
#else
g = f6 x
#endif
#endif
#if defined(UNKNOWN_THING) && 0
h = f7 x
#endif
#if defined(UNKNOWN_THING) || 1
i = f8 x
#endif
#if 0 || UNKNOWN_THING
j = f9 x
#endif
`);
  assert.deepEqual(callees(r).sort(), ['f2', 'f8', 'f9'], 'dead outer region kills the nested undecidable one; && with 0 is false; || with 1 is true; 0 || unknown is unknown');
});

test('[boundaries.cpp] Kleene dominance with an #else: a known operand decides, an unknown one does not', () => {
  const pick = (cond) => callees(parse(`module M where\n#if ${cond}\na = yes x\n#else\nb = no x\n#endif\n`)).sort().join(',');
  assert.equal(pick('defined(UNKNOWN_THING) || 1'), 'yes');
  assert.equal(pick('1 || defined(UNKNOWN_THING)'), 'yes');
  assert.equal(pick('defined(UNKNOWN_THING) && 0'), 'no');
  assert.equal(pick('0 && defined(UNKNOWN_THING)'), 'no');
  assert.equal(pick('defined(UNKNOWN_THING) && 1'), 'no,yes');
  assert.equal(pick('defined(UNKNOWN_THING) || 0'), 'no,yes');
  assert.equal(pick('!defined(UNKNOWN_THING)'), 'no,yes');
});

test('[boundaries.cpp] a #define inside an undecided branch makes the macro undecided afterwards', () => {
  const r = parse(`module M where
#ifdef SOMEWHERE
#define K 1
#endif
#if K
a = f1 x
#else
b = f2 x
#endif
`);
  assert.deepEqual(callees(r).sort(), ['f1', 'f2']);
  assert.equal(cppOf(r).undecided, 2);
});

test('[boundaries.cpp] a function-like or unparsable expression is undecided, never guessed', () => {
  const r = parse(`module M where
#define TWICE(x) ((x) * 2)
#if TWICE(0)
a = f1 x
#else
b = f2 x
#endif
#if 1 +
c = f3 x
#endif
#if 4 / 0
d = f4 x
#endif
`);
  assert.deepEqual(callees(r).sort(), ['f1', 'f2', 'f3', 'f4']);
  assert.equal(cppOf(r).decided, 0);
});

test('[boundaries.cpp] continued directives and hsc files keep their previous behaviour', () => {
  const r = parse(`module M where
#define LONG \\
   1
#if LONG
a = f1 x
#endif
`);
  assert.deepEqual(callees(r), ['f1']);
  assert.equal(r.calls[0].span.startLine, 5);
  // hsc: never evaluated, never run
  const h = parseHaskell('module H where\n#if 0\na = f1 x\n#endif\n', { file: 'H.hsc' });
  assert.deepEqual(callees(h), ['f1'], 'an hsc conditional is not evaluated');
});

// ── CPP: decided by the project ──────────────────────────────────────────────────────────────────────────────────

const CABAL_BOUNDS = `cabal-version: 2.4
name: demo
version: 0.1
library
  exposed-modules: M
  build-depends: base >=4.18 && <4.20, aeson >=2.0 && <2.2, text
`;

test('[boundaries.cpp] MIN_VERSION_pkg is judged against the hull of the cabal bounds, and only where the bounds decide it', () => {
  const ctx = deriveCppContext({ 'demo.cabal': CABAL_BOUNDS });
  const mk = (cond) => `module M where\n#if ${cond}\na = yes x\n#else\nb = no x\n#endif\n`;
  const pick = (cond) => callees(parse(mk(cond), { cpp: ctx })).sort().join(',');
  assert.equal(pick('MIN_VERSION_base(4,17,0)'), 'yes', 'lower bound is above the target');
  assert.equal(pick('MIN_VERSION_base(4,20,0)'), 'no', 'upper bound is at or below the target');
  assert.equal(pick('MIN_VERSION_base(4,19,0)'), 'no,yes', 'inside the range: undecided');
  assert.equal(pick('MIN_VERSION_aeson(2,0,0)'), 'yes');
  assert.equal(pick('MIN_VERSION_aeson(2,2,0)'), 'no');
  assert.equal(pick('MIN_VERSION_text(2,0,0)'), 'no,yes', 'a dependency with no bounds decides nothing');
  assert.equal(pick('MIN_VERSION_unknownpkg(1,0,0)'), 'no,yes', 'a package the project never lists decides nothing');
  assert.equal(callees(parse(mk('MIN_VERSION_base(4,17,0)'))).sort().join(','), 'no,yes', 'without project data nothing is decided');
  const r = parse(mk('MIN_VERSION_base(4,17,0)'), { cpp: ctx });
  assert.deepEqual(cppOf(r).decisions[0].basis, ['cabal-bounds']);
});

test('[boundaries.cpp] bounds of several components are unioned, so a looser component keeps the question open', () => {
  const two = `${CABAL_BOUNDS}test-suite spec
  type: exitcode-stdio-1.0
  main-is: Spec.hs
  build-depends: base >=4.16 && <4.20
`;
  const ctx = deriveCppContext({ 'demo.cabal': two });
  const r = parse('module M where\n#if MIN_VERSION_base(4,17,0)\na = yes x\n#else\nb = no x\n#endif\n', { cpp: ctx });
  assert.deepEqual(callees(r).sort(), ['no', 'yes'], 'one component allows base 4.16, so the target is not guaranteed');
});

test('[boundaries.cpp] rangeHull over-approximates: || widens, && narrows', () => {
  const h = (t) => rangeHull(parseVersionRange(t).ast);
  const s = (v) => (v ? v.join('.') : null);
  const a = h('>=1.0 && <2.0');
  assert.equal(s(a.lo), '1.0'); assert.equal(s(a.hiExcl), '2.0');
  const b = h('>=1.0 && <2.0 || >=3.0 && <4.0');
  assert.equal(s(b.lo), '1.0'); assert.equal(s(b.hiExcl), '4.0');
  const c = h('>=1.0 || <0.5');
  assert.equal(c.lo, null, 'an open low end stays open'); assert.equal(c.hiExcl, null);
  const d = h('^>=1.2.3');
  assert.equal(s(d.lo), '1.2.3'); assert.equal(s(d.hiExcl), '1.3');
});

test('[boundaries.cpp] __GLASGOW_HASKELL__ is judged only against a compiler the project states; a pin outranks tested-with', () => {
  const guard = (n) => `module M where\n#if __GLASGOW_HASKELL__ >= ${n}\na = new x\n#else\nb = old x\n#endif\n`;
  const pinned = deriveCppContext({ 'cabal.project': 'packages: .\nwith-compiler: ghc-9.6.4\n' });
  assert.equal(pinned.ghc.basis, 'pinned');
  assert.deepEqual(callees(parse(guard(906), { cpp: pinned })), ['new']);
  assert.deepEqual(callees(parse(guard(908), { cpp: pinned })), ['old']);
  assert.deepEqual(callees(parse(guard(906))).sort(), ['new', 'old'], 'no compiler stated: not invented');

  const tested = deriveCppContext({ 'demo.cabal': `name: demo\ntested-with: GHC == 9.4.8, GHC == 9.6.4\nlibrary\n  build-depends: base\n` });
  assert.equal(tested.ghc.basis, 'tested-with');
  assert.deepEqual(callees(parse(guard(900), { cpp: tested })), ['new'], 'every listed version agrees');
  assert.deepEqual(callees(parse(guard(906), { cpp: tested })).sort(), ['new', 'old'], 'the listed versions disagree: undecided');
  const r = parse(guard(900), { cpp: tested });
  assert.deepEqual(cppOf(r).assumptions, ['compiler:tested-with'], 'a decision resting on tested-with is disclosed as an assumption');

  const both = deriveCppContext({ 'cabal.project': 'with-compiler: ghc-9.8.2\n', 'demo.cabal': 'name: demo\ntested-with: GHC == 8.10.7\n' });
  assert.equal(both.ghc.basis, 'pinned');
  // a tested-with range is never turned into a version
  const range = deriveCppContext({ 'demo.cabal': 'name: demo\ntested-with: GHC >= 9.4\n' });
  assert.equal(range.ghc, null);
  const mixed = deriveCppContext({ 'demo.cabal': 'name: demo\ntested-with: GHC == 9.4.8, GHC >= 9.6\n' });
  assert.equal(mixed.ghc, null, 'one unparsable item makes the whole list unusable: the range may admit versions the list does not name');
});

test('[boundaries.cpp] MIN_VERSION_base and MIN_VERSION_GLASGOW_HASKELL follow a pinned compiler at major.minor precision', () => {
  const pinned = deriveCppContext({ 'cabal.project': 'with-compiler: ghc-9.6.4\n' });
  const pick = (cond) => callees(parse(`module M where\n#if ${cond}\na = yes x\n#else\nb = no x\n#endif\n`, { cpp: pinned })).sort().join(',');
  assert.equal(pick('MIN_VERSION_base(4,18,0)'), 'yes');
  assert.equal(pick('MIN_VERSION_base(4,19,0)'), 'no');
  assert.equal(pick('MIN_VERSION_base(4,18,2)'), 'no,yes', 'the patch level of base is not known from the GHC series');
  assert.equal(pick('MIN_VERSION_GLASGOW_HASKELL(9,6,0,0)'), 'yes');
  assert.equal(pick('MIN_VERSION_GLASGOW_HASKELL(9,8,0,0)'), 'no');
  assert.equal(pick('defined(__GLASGOW_HASKELL__)'), 'yes');
  const none = callees(parse('module M where\n#ifdef __GLASGOW_HASKELL__\na = yes x\n#else\nb = no x\n#endif\n')).sort().join(',');
  assert.equal(none, 'no,yes', 'without a stated compiler even this is not assumed');
});

// ── CPP: scan health and disclosure ──────────────────────────────────────────────────────────────────────────────

test('[boundaries.cpp] a CPP file is analysed (never unresolved) and the limitation says what was decided and what was not', async () => {
  const files = {
    'demo.cabal': CABAL_BOUNDS,
    'src/M.hs': 'module M where\n#if MIN_VERSION_base(4,17,0)\na = f x\n#endif\n#ifdef ELSEWHERE\nb = g x\n#endif\n',
  };
  assert.equal((await outcomeOf({ 'src/M.hs': files['src/M.hs'] }))['src/M.hs'], 'analyzed');
  const a = await assessLanguageAssurance({ files });
  const cpp = a.limitations.find((l) => l.boundary === 'cpp');
  assert.ok(cpp, 'CPP stays disclosed');
  assert.equal(cpp.decidedConditionals, 1);
  assert.equal(cpp.undecidedConditionals, 1);
  assert.ok(/every other one keeps all of its branches/.test(cpp.note));
});

// ── Template Haskell: safe declaration splices ───────────────────────────────────────────────────────────────────

const TH_HEAD = `{-# LANGUAGE TemplateHaskell, QuasiQuotes #-}
module M where
import Control.Lens
import Data.Aeson.TH
import Database.Persist.TH
import Data.SafeCopy
`;

test('[boundaries.th] known generators applied to names and literals are analysed under a stated assumption', async () => {
  const src = `${TH_HEAD}data T = T { _a :: Int }
makeLenses ''T
makeClassy ''T
makeFields ''T
makePrisms ''T
deriveJSON defaultOptions ''T
deriveToJSON defaultOptions { fieldLabelModifier = drop 1, omitNothingFields = True } ''T
$(deriveFromJSON defaultOptions ''T)
deriveSafeCopy 0 'base ''T
share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
Person
  name String
|]
ok = putStrLn "x"
`;
  const r = parse(src);
  assert.equal(r.status, 'parsed');
  assert.deepEqual(r.errors, []);
  const k = kinds(r);
  assert.ok(k.every((x) => x === 'th-safe-splice'), `only safe-splice boundaries remain: ${k}`);
  assert.equal(k.length, 9, 'nine declaration-level splices');
  assert.equal(r.complete, true);
  const b = r.boundaries.find((x) => x.kind === 'th-safe-splice' && x.generators.includes('makeLenses'));
  assert.equal(b.assumption, 'upstream-generator');
  assert.ok(/ASSUMED/.test(b.detail) && /not modelled/.test(b.detail));
  assert.ok(callees(r).includes('putStrLn'));
  // scan health: the file is analysed, and the assumption is a disclosed limitation, not silence
  assert.equal((await outcomeOf({ 'M.hs': src }))['M.hs'], 'analyzed');
  const a = await assessLanguageAssurance({ files: { 'M.hs': src } });
  assert.ok(a.limitations.some((l) => l.boundary === 'th-safe-splice'));
  assert.ok(!a.limitations.some((l) => l.boundary === 'th-top-level-splice'));
});

test('[boundaries.th] anything else stays the opaque boundary it was, and the file stays unresolved', async () => {
  const unsafe = {
    'runIO splice': '$(runIO (readFile "x") >>= \\s -> return [])',
    'embedFile': 'import Data.FileEmbed\nembedded = $(embedFile "secret.txt")',
    'user-defined generator': 'deriveMine ::  Name -> Q [Dec]\nderiveMine = undefined\nderiveMine \'\'T',
    'qRunIO': 'qRunIO (putStrLn "x")',
    'name built from an expression': 'makeLenses (mkName (take 3 "abcdef"))',
    'variable options': 'opts = defaultOptions\nderiveJSON opts \'\'T',
    'nested splice argument': 'makeLenses $(lift "T")',
    'lambda in a record update': 'deriveJSON defaultOptions { fieldLabelModifier = \\s -> s } \'\'T',
    'unlisted helper in a record update': 'deriveJSON defaultOptions { fieldLabelModifier = userMod } \'\'T',
    'persistent file quoter': 'mkPersist sqlSettings [persistFileWith lowerCaseSettings "models"]',
    'unknown quoter': 'share [mkPersist sqlSettings] [somethingElse|x|]',
  };
  for (const [label, body] of Object.entries(unsafe)) {
    const src = `${TH_HEAD}data T = T { _a :: Int }\n${body}\nok = putStrLn "x"\n`;
    const r = parse(src);
    assert.equal(r.complete, false, `${label}: still incomplete`);
    assert.ok(kinds(r).some((x) => x !== 'th-safe-splice'), `${label}: an opaque boundary remains`);
    assert.equal((await outcomeOf({ 'M.hs': src }))['M.hs'], 'unresolved', `${label}: unresolved in scan health`);
  }
});

test('[boundaries.th] the generator must be the imported upstream one: missing, shadowed, hidden or from another module is opaque', async () => {
  const body = 'data T = T { _a :: Int }\nmakeLenses \'\'T\n';
  const base = '{-# LANGUAGE TemplateHaskell #-}\nmodule M where\n';
  const cases = {
    'no import': `${base}${body}`,
    'imported from an unrelated module': `${base}import Some.Other.Module\n${body}`,
    'defined in the file': `${base}import Control.Lens\nmakeLenses :: Name -> Q [Dec]\nmakeLenses = undefined\n${body}`,
    'hidden by the import': `${base}import Control.Lens hiding (makeLenses)\n${body}`,
    'import list omits it': `${base}import Control.Lens (view)\n${body}`,
    'qualified import used unqualified': `${base}import qualified Control.Lens as L\n${body}`,
  };
  for (const [label, src] of Object.entries(cases)) {
    assert.equal((await outcomeOf({ 'M.hs': src }))['M.hs'], 'unresolved', label);
  }
  const ok = {
    'explicit import list': `${base}import Control.Lens (makeLenses)\n${body}`,
    'qualified use': `${base}import qualified Control.Lens as L\ndata T = T { _a :: Int }\nL.makeLenses \'\'T\n`,
    'TH submodule': `${base}import Control.Lens.TH\n${body}`,
  };
  for (const [label, src] of Object.entries(ok)) {
    assert.equal((await outcomeOf({ 'M.hs': src }))['M.hs'], 'analyzed', label);
  }
});

test('[boundaries.th] one unsafe splice keeps the file unresolved and only the unsafe boundary is reported', () => {
  const src = `${TH_HEAD}data T = T { _a :: Int }
makeLenses ''T
deriveJSON defaultOptions ''T
$(runIO (return []))
`;
  const r = parse(src);
  const k = kinds(r);
  assert.equal(k.filter((x) => x === 'th-safe-splice').length, 2);
  assert.ok(k.includes('th-splice') || k.includes('th-top-level-splice'));
  assert.equal(r.complete, false);
});

test('[boundaries.th] a file with no TemplateHaskell pragma is unchanged', () => {
  const r = parse('module M where\nimport Control.Lens\nmakeLenses \'\'T\n');
  assert.ok(r.errors.length > 0 || r.boundaries.length === 0, 'without the extension this is not a splice');
  assert.ok(!kinds(r).includes('th-safe-splice'));
});

// ── quasi-quotes ──────────────────────────────────────────────────────────────────────────────────────────────

test('[boundaries.qq] raw-string and non-interpolating quasi-quotes are inert strings; interpolation, unknown quoters and unimported names are not', async () => {
  const head = '{-# LANGUAGE QuasiQuotes #-}\nmodule M where\nimport Text.RawString.QQ\nimport Data.String.Interpolate\nimport Data.String.Here\n';
  const inert = [
    'a = [r|select * from t where x = ${x} and #{y}|]',
    'a = [i|plain text|]',
    'a = [iii|plain   text|]',
    'a = [here|plain text|]',
  ];
  for (const body of inert) {
    const src = `${head}${body}\nok = putStrLn "x"\n`;
    const r = parse(src);
    assert.ok(r.boundaries.every((b) => b.kind === 'quasiquote-inert'), `${body}: ${kinds(r)}`);
    assert.equal(r.boundaries[0].assumption, 'upstream-quoter');
    assert.equal(r.complete, true);
    assert.equal((await outcomeOf({ 'M.hs': src }))['M.hs'], 'analyzed', body);
  }
  const opaque = [
    'a = [i|hello #{name}|]',
    'a = [here|hello ${name}|]',
    'a = [iii|hello #{name}|]',
    'a = [sql|select 1|]',
    'a = [parseRoutes|/ HomeR GET|]',
  ];
  for (const body of opaque) {
    const src = `${head}${body}\nok = putStrLn "x"\n`;
    assert.equal((await outcomeOf({ 'M.hs': src }))['M.hs'], 'unresolved', body);
  }
  // not imported, or shadowed by a local definition of the same name
  assert.equal((await outcomeOf({ 'M.hs': '{-# LANGUAGE QuasiQuotes #-}\nmodule M where\na = [r|text|]\n' }))['M.hs'], 'unresolved');
  assert.equal((await outcomeOf({ 'M.hs': '{-# LANGUAGE QuasiQuotes #-}\nmodule M where\nimport Text.RawString.QQ\nr = undefined\na = [r|text|]\n' }))['M.hs'], 'unresolved');
  // a qualified quoter resolves through its alias
  const q = parse('{-# LANGUAGE QuasiQuotes #-}\nmodule M where\nimport qualified Text.RawString.QQ as Q\na = [Q.r|text|]\n');
  assert.deepEqual(kinds(q), ['quasiquote-inert']);
});

test('[boundaries.qq] text inside an inert quasi-quote still never becomes a call', () => {
  const r = parse('{-# LANGUAGE QuasiQuotes #-}\nmodule M where\nimport Text.RawString.QQ\nimport System.Process\nscript = [r|callCommand "boom"|]\nreal = callCommand "x"\n');
  assert.equal(r.calls.filter((c) => c.callee === 'callCommand').length, 1);
  assert.equal(r.calls.find((c) => c.callee === 'callCommand').span.startLine, 6);
});

// ── the semantic IR sees the same decisions ──────────────────────────────────────────────────────────────────────

const HASH_IMPORTS = 'import Crypto.Hash (hashWith, MD5(..), SHA256(..))\nimport qualified Data.ByteString.Char8 as B';
const rulesOf = (src) => analyzeHaskellRules({ 'T.hs': src }).findings.map((f) => `${f.rule}@${f.line}`);

test('[boundaries.ir] a finding in a dead CPP branch is not reported, a finding in the live branch is, and an undecided branch keeps its finding', () => {
  const mk = (cond) => `module T where\n${HASH_IMPORTS}\n#${cond}\nweak = hashWith MD5 (B.pack "x")\n#else\nweak = hashWith SHA256 (B.pack "x")\n#endif\n`;
  assert.deepEqual(rulesOf(mk('if 0')), [], 'dead branch: nothing');
  assert.deepEqual(rulesOf(mk('if 1')), ['hs-weak-hash@5'], 'live branch: reported at its original line');
  assert.deepEqual(rulesOf(mk('ifdef SOME_FLAG')), ['hs-weak-hash@5'], 'undecidable: the branch is kept, never dropped');
  assert.deepEqual(rulesOf(mk('ifndef SOME_FLAG')), ['hs-weak-hash@5']);
});

test('[boundaries.ir] a weak hash next to a safe splice or an inert quasi-quote is still reported', () => {
  const src = `{-# LANGUAGE TemplateHaskell, QuasiQuotes #-}
module T where
import Control.Lens
import Text.RawString.QQ
${HASH_IMPORTS}
data D = D { _x :: Int }
makeLenses ''D
banner = [r|hello
world|]
weak = hashWith MD5 (B.pack "x")
`;
  assert.deepEqual(rulesOf(src), ['hs-weak-hash@11']);
});

test('[boundaries.ir] preprocessForSyntax is length-preserving and leaves opaque constructs untouched', () => {
  const src = `{-# LANGUAGE TemplateHaskell, QuasiQuotes #-}
module T where
import Control.Lens
import Text.RawString.QQ
#if 0
dead = 1
#endif
makeLenses ''D
a = [r|abc
def|]
b = $(runIO (return undefined))
c = [sql|select 1|]
`;
  const out = preprocessForSyntax(src, { file: 'T.hs' });
  assert.equal(out.length, src.length);
  assert.equal(out.split('\n').length, src.split('\n').length);
  assert.ok(!/dead|makeLenses|#if/.test(out), 'dead branch, directives and the safe splice are overwritten');
  assert.ok(/a = "/.test(out) && !/abc/.test(out), 'the inert quasi-quote became a string literal');
  assert.ok(out.includes('$(runIO (return undefined))') && out.includes('[sql|select 1|]'), 'opaque constructs are left exactly as written');
  assert.equal(preprocessForSyntax('module T where\nx = 1\n'), 'module T where\nx = 1\n', 'nothing to do: same text');
});
