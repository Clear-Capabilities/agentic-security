// HS-010: Haskell remediation and dependency upgrades.
// Fixes are validated against the REAL scanner (rescan of the patched tree), the real parser, and structural
// behavior assertions that re-evaluate the original and the patched program text on benign and hostile input.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { planHaskellFix, validateHaskellFix, undoFix, unifiedDiff, planHaskellUpgrade, syntaxGate, compileGate, LABELS, SUPPORTED_FIX_IDS } from '../../src/language/haskell-fix.js';
import { analyzeHaskellManifests } from '../../src/language/haskell-manifests.js';

const PG = 'import Database.PostgreSQL.Simple\nimport Data.String (fromString)';
const SRC = {
  sql: { cwe: 'CWE-89', file: 'src/Db.hs', text: `module Db where\n${PG}\n\nrun :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  _ <- execute_ conn (fromString ("DELETE FROM t WHERE n = '" ++ n ++ "'"))\n  pure ()\n` },
  proc: { cwe: 'CWE-78', file: 'src/Sh.hs', text: 'module Sh where\nimport System.Process\n\nrun :: IO ()\nrun = do\n  n <- getLine\n  callCommand ("ls " ++ n)\n' },
  html: { cwe: 'CWE-79', file: 'src/Ht.hs', text: 'module Ht where\nimport Text.Blaze.Html (Html, preEscapedToHtml)\n\nrun :: IO Html\nrun = do\n  n <- getLine\n  pure (preEscapedToHtml n)\n' },
  hash: { cwe: 'CWE-328', file: 'src/Hs.hs', text: 'module Hs where\nimport Crypto.Hash (hashWith, MD5(..))\nimport qualified Data.ByteString.Char8 as B\n\na = hashWith MD5 (B.pack "x")\n' },
  log: { cwe: 'CWE-532', file: 'src/Lg.hs', text: 'module Lg where\n\nl :: String -> IO ()\nl password = putStrLn ("user logged in with " ++ password)\n' },
};
const LINE = { sql: 8, proc: 7, html: 7, hash: 5, log: 4 };
const fin = (k) => ({ cwe: SRC[k].cwe, file: SRC[k].file, line: LINE[k] });
const filesOf = (k) => ({ [SRC[k].file]: SRC[k].text });
const HIGH = (k, cwe = SRC[k].cwe) => ({ file: SRC[k].file, cwe, family: 'f', severity: 'high' });

// ── behavior model: evaluate the program text, not just look at it ───────────
function sqlEval(src, input) {   // original: interpolate; patched: constant text + params
  if (/execute_/.test(src)) {
    const line = src.split('\n').find((l) => /execute_/.test(l));
    const m = /execute_\s+conn\s+\(fromString\s+\((.*)\)\)\s*$/.exec(line);
    const parts = m[1].split('++').map((x) => x.trim());
    return { text: parts.map((p) => (p === 'n' ? input : p.slice(1, -1))).join(''), params: [] };
  }
  const l = src.split('\n').find((x) => /execute conn/.test(x));
  return { text: /fromString\s+"([^"]*)"/.exec(l)[1], params: /Only n/.test(l) ? [input] : [] };
}
const quote = (s) => `'${s.replace(/'/g, "''")}'`;

test('[HS-010.AC01] SQL parameterization: vulnerable before, safe after, and benign behavior is preserved', async () => {
  const plan = planHaskellFix(fin('sql'), filesOf('sql'));
  assert.equal(plan.ok, true); assert.equal(plan.label, 'FULL');
  assert.match(plan.after, /execute conn \(fromString "DELETE FROM t WHERE n = \?"\) \(Only n\)/);
  const hostile = "x'; DROP TABLE t; --";
  assert.match(sqlEval(plan.before, hostile).text, /DROP TABLE/, 'before: the hostile value reaches the SQL text');
  const after = sqlEval(plan.after, hostile);
  assert.ok(!/DROP/.test(after.text), 'after: the SQL text is constant');
  assert.deepEqual(after.params, [hostile]);
  assert.equal(after.text.replace('?', quote('bob')), sqlEval(plan.before, 'bob').text);
  const v = await validateHaskellFix(fin('sql'), { files: filesOf('sql') });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
  assert.equal(v.gates.rescan.originalGone, true);
  assert.equal(v.applied, false, 'verification alone never writes');
});

test('[HS-010.AC01] safe process invocation: no shell string remains, argv matches the original words', async () => {
  const plan = planHaskellFix(fin('proc'), filesOf('proc'));
  assert.equal(plan.ok, true);
  assert.match(plan.after, /callProcess "ls" \["--", n\]/);
  assert.ok(!/callCommand/.test(plan.after));
  assert.equal(plan.behavior.program, 'ls');
  assert.deepEqual(plan.behavior.argv, [[{ lit: '--' }], [{ var: 'n' }]]);
  const hostile = 'x; id';
  const argv = plan.behavior.argv.map((w) => w.map((p) => (p.var ? hostile : p.lit)).join(''));
  assert.deepEqual(argv, ['--', hostile], 'the hostile value is one argv element, never parsed by a shell');
  assert.match(plan.explanation, /assumes the program follows that convention/, 'the option-terminator assumption is disclosed');
  const v = await validateHaskellFix(fin('proc'), { files: filesOf('proc') });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
});

test('[HS-010.AC01] contextual output escaping: raw markup sink becomes an escaping one', async () => {
  const plan = planHaskellFix(fin('html'), filesOf('html'));
  assert.equal(plan.ok, true);
  assert.match(plan.after, /pure \(toHtml n\)/);
  assert.match(plan.after, /import Text\.Blaze\.Html \(Html, preEscapedToHtml, toHtml\)/, 'the import list is extended so the file still compiles');
  assert.ok(!/pure \(preEscapedToHtml/.test(plan.after));
  const v = await validateHaskellFix(fin('html'), { files: filesOf('html') });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
});

test('[HS-010.AC01] crypto correction: a weak hash is replaced and the import is kept consistent', async () => {
  const plan = planHaskellFix(fin('hash'), filesOf('hash'));
  assert.equal(plan.ok, true);
  assert.match(plan.after, /hashWith SHA256 /);
  assert.match(plan.after, /import Crypto\.Hash \(hashWith, MD5\(\.\.\), SHA256\(\.\.\)\)/);
  assert.match(plan.explanation, /Digests change/, 'the behavior change is stated');
  const v = await validateHaskellFix(fin('hash'), { files: filesOf('hash') });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
});

test('[HS-010.AC01] logging correction: the sensitive argument is redacted, the rest of the line is untouched', async () => {
  const plan = planHaskellFix(fin('log'), filesOf('log'));
  assert.equal(plan.ok, true); assert.equal(plan.label, 'MITIGATION');
  assert.match(plan.after, /putStrLn \("user logged in with " \+\+ "\[REDACTED\]"\)/);
  assert.match(plan.after, /^l password = /m, 'the binding itself is not rewritten');
  const v = await validateHaskellFix(fin('log'), { files: filesOf('log') });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
});

test('[HS-010.AC01] patches preserve everything outside the changed line and imports (layout, comments, other lines)', () => {
  const files = { 'src/Db.hs': `{-# LANGUAGE OverloadedStrings #-}\n-- keep me\nmodule Db where\nimport Database.PostgreSQL.Simple (Connection, execute_)\n\nrun :: Connection -> IO ()\nrun conn = do\n  n <- getLine\n  -- inline note\n  _ <- execute_ conn ("DELETE FROM t WHERE n = '" ++ n ++ "'")\n  pure ()\n` };
  const plan = planHaskellFix({ cwe: 'CWE-89', file: 'src/Db.hs', line: 10 }, files);
  assert.equal(plan.ok, true, plan.reason);
  const a = files['src/Db.hs'].split('\n'), b = plan.after.split('\n');
  assert.equal(a.length, b.length);
  const changed = a.map((l, i) => (l !== b[i] ? i + 1 : 0)).filter(Boolean);
  assert.deepEqual(changed, [4, 10], 'only the import line and the sink line differ');
  assert.match(b[3], /\(Connection, execute_, execute, query, Only\)/);
  assert.match(b[9], /execute conn "DELETE FROM t WHERE n = \?" \(Only n\)/);
});

test('[HS-010.AC02] shapes with no provable rewrite are not guessed: they are proposals, not patches', () => {
  const t = 'module A where\nimport System.Process\nrun c = callCommand c\n';
  const r = planHaskellFix({ cwe: 'CWE-78', file: 'a.hs', line: 3 }, { 'a.hs': t });
  assert.equal(r.ok, false); assert.equal(r.proposal, 'model-assisted');
  const half = `module A where\n${PG}\nr c = execute_ c (fromString ("SELECT '" ++ c))\n`;
  assert.equal(planHaskellFix({ cwe: 'CWE-89', file: 'a.hs', line: 4 }, { 'a.hs': half }).ok, false, 'an unbalanced quote is refused');
  const cpp = '{-# LANGUAGE CPP #-}\nmodule A where\nrun = pure ()\n';
  assert.match(planHaskellFix({ cwe: 'CWE-89', file: 'a.hs', line: 3 }, { 'a.hs': cpp }).reason, /CPP/);
  assert.equal(planHaskellFix({ cwe: 'CWE-89', file: 'x.js', line: 1 }, { 'x.js': '1' }).ok, false);
});

test('[HS-010.AC02] a syntax-breaking patch, a still-present finding or a new finding prevents application', async () => {
  const files = filesOf('sql');
  assert.equal(syntaxGate('a.hs', 'module A where\nf = 1\n', 'module A where\nf = (1 +\n').ok, false);
  const still = await validateHaskellFix(fin('sql'), { files, rescan: async () => [HIGH('sql')] });
  assert.equal(still.status, 'blocked'); assert.match(still.reason, /still reported/); assert.equal(still.applied, false);
  let n = 0;
  const intro = await validateHaskellFix(fin('sql'), { files, rescan: async () => (n++ === 0 ? [HIGH('sql')] : [HIGH('sql', 'CWE-79')]) });
  assert.equal(intro.status, 'blocked'); assert.match(intro.reason, /new medium-or-higher/);
  n = 0;
  const low = await validateHaskellFix(fin('sql'), { files, rescan: async () => (n++ === 0 ? [HIGH('sql')] : [{ ...HIGH('sql', 'CWE-676'), severity: 'low' }]) });
  assert.equal(low.status, 'verified', 'a new LOW finding does not block');
  const beh = await validateHaskellFix(fin('sql'), { files, rescan: async () => [], behaviorCheck: () => ({ ok: false, detail: 'unrelated output change' }) });
  assert.equal(beh.status, 'blocked'); assert.match(beh.reason, /behavior/);
  const crash = await validateHaskellFix(fin('sql'), { files, rescan: async () => { throw new Error('boom'); } });
  assert.equal(crash.status, 'blocked');
});

test('[HS-010.AC02] a process fix whose argument could still be read as an option is blocked by the real rescan, not applied', async () => {
  const src = 'module Sh where\nimport System.Process\n\nrun :: IO ()\nrun = do\n  n <- getLine\n  callCommand ("ls -l " ++ n)\n';
  const v = await validateHaskellFix({ cwe: 'CWE-78', file: 'src/Sh.hs', line: 7 }, { files: { 'src/Sh.hs': src } });
  assert.equal(v.status, 'blocked');
  assert.match(v.reason, /new medium-or-higher/);
  assert.ok(v.gates.rescan.newMediumOrHigher.some((x) => /CWE-88/.test(x)));
  assert.equal(v.applied, false);
});

test('[HS-010.AC02] preview, backup, apply and undo work, and apply refuses a file that changed underneath it', async () => {
  const root = mkdtempSync(join(tmpdir(), 'hs-fixapply-'));
  const f = join(root, SRC.html.file); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, SRC.html.text);
  const stub = async (fs) => (/preEscapedToHtml n\)/.test(fs[SRC.html.file]) ? [HIGH('html')] : []);
  const dry = await validateHaskellFix(fin('html'), { files: filesOf('html'), rescan: stub });
  assert.equal(dry.status, 'verified'); assert.match(dry.preview, /^-.*preEscapedToHtml n\)/m); assert.match(dry.preview, /^\+.*toHtml n\)/m);
  assert.equal(readFileSync(f, 'utf8'), SRC.html.text, 'preview wrote nothing');
  const done = await validateHaskellFix(fin('html'), { files: filesOf('html'), rescan: stub, apply: true, root });
  assert.equal(done.status, 'applied'); assert.equal(done.applied, true);
  assert.match(readFileSync(f, 'utf8'), /toHtml n\)/);
  assert.ok(existsSync(join(done.backup.dir, 'original')));
  undoFix(root, done.backup.id);
  assert.equal(readFileSync(f, 'utf8'), SRC.html.text, 'undo restores the original byte for byte');
  writeFileSync(f, SRC.html.text + '-- edited by someone else\n');
  await assert.rejects(() => validateHaskellFix(fin('html'), { files: filesOf('html'), rescan: stub, apply: true, root }), /changed on disk/);
  assert.match(unifiedDiff('a.hs', 'x\ny\n', 'x\nz\n'), /-y\n\+z/);
});

test('[HS-010.AC02] every fix carries exactly one FULL/MITIGATION/WORKAROUND label', () => {
  assert.deepEqual([...LABELS], ['FULL', 'MITIGATION', 'WORKAROUND']);
  const labels = Object.keys(SRC).map((k) => planHaskellFix(fin(k), filesOf(k)).label);
  for (const l of labels) assert.ok(LABELS.includes(l));
  assert.ok(labels.includes('FULL') && labels.includes('MITIGATION'));
  assert.equal(SUPPORTED_FIX_IDS.length, 5);
});

const CABAL = 'name: a\nversion: 0.1\nbuild-type: Simple\nflag fast\n  default: False\n\nlibrary\n  build-depends: base >=4.14 && <5, xml-conduit >=1.8 && <2\n  if flag(fast)\n    build-depends: aeson ==2.0.0.0\ntest-suite t\n  type: exitcode-stdio-1.0\n  main-is: T.hs\n  build-depends: base, xml-conduit == 1.9.0.0\n';
const upFinding = (line, extra = {}) => ({ name: 'xml-conduit', fixedIn: ['1.9.1.0'], file: 'a.cabal', line, ...extra });

test('[HS-010.AC03] upgrade proposals edit only the declaring line and keep scope, flags and conditionals', () => {
  const lib = planHaskellUpgrade(upFinding(8), { 'a.cabal': CABAL });
  assert.equal(lib.ok, true);
  assert.equal(lib.to, '>= 1.9.1.0 && < 2');
  const a = CABAL.split('\n'), b = lib.after.split('\n');
  assert.deepEqual(a.map((l, i) => (l !== b[i] ? i + 1 : 0)).filter(Boolean), [8]);
  assert.match(b[7], /base >=4\.14 && <5, xml-conduit >= 1\.9\.1\.0 && < 2/);
  const t = planHaskellUpgrade(upFinding(14), { 'a.cabal': CABAL });
  assert.equal(t.to, '== 1.9.1.0', 'an exact pin stays an exact pin');
  assert.match(t.after.split('\n')[13], /base, xml-conduit == 1\.9\.1\.0/);
  const cond = planHaskellUpgrade({ name: 'aeson', fixedIn: ['2.0.1.0'], file: 'a.cabal', line: 10 }, { 'a.cabal': CABAL });
  assert.ok(cond.after.split('\n')[9].startsWith('    build-depends: aeson == 2.0.1.0'));
  assert.ok(cond.after.includes('if flag(fast)'));
});

test('[HS-010.AC03] a constraints-only edit is unverified, and only a supported resolved outcome makes it fixed', () => {
  const files = { 'a.cabal': CABAL };
  const none = planHaskellUpgrade(upFinding(8), files);
  assert.equal(none.status, 'unverified'); assert.match(none.note, /NOT a confirmed fix/);
  assert.equal(planHaskellUpgrade(upFinding(8), files, { verifyResolved: () => ({ ok: true, resolvedVersion: '1.9.0.0' }) }).status, 'unverified');
  assert.equal(planHaskellUpgrade(upFinding(8), files, { verifyResolved: () => { throw new Error('solver failed'); } }).status, 'unverified');
  const ok = planHaskellUpgrade(upFinding(8), files, { verifyResolved: (patched) => { assert.match(patched['a.cabal'], /1\.9\.1\.0/); return { ok: true, resolvedVersion: '1.9.1.0' }; } });
  assert.equal(ok.status, 'fixed'); assert.equal(ok.resolvedVersion, '1.9.1.0');
});

test('[HS-010.AC03] blocked upgrades: no fix published, fix outside the bound, a generated plan, or an unknown line', () => {
  const files = { 'a.cabal': CABAL };
  assert.equal(planHaskellUpgrade(upFinding(8, { fixedIn: [], unfixed: true }), files).status, 'blocked');
  assert.match(planHaskellUpgrade(upFinding(8, { fixedIn: ['2.1.0.0'] }), files).reason, /upper bound/);
  assert.match(planHaskellUpgrade(upFinding(1, { file: 'dist-newstyle/cache/plan.json' }), { 'dist-newstyle/cache/plan.json': '{}' }).reason, /generated plan/);
  assert.match(planHaskellUpgrade(upFinding(2), files).reason, /could not locate/);
  const m = analyzeHaskellManifests([{ path: 'a.cabal', text: planHaskellUpgrade(upFinding(8), files).after }]);
  assert.ok(m.dependencies.some((d) => d.name === 'xml-conduit' && /1\.9\.1\.0/.test(d.declaredRange)));
});

test('[HS-010.AC04] compilation is opt-in: it does not run by default, and a missing GHC is reported, not assumed', async () => {
  assert.equal(compileGate({ 'a.hs': 'module A where\n' }).ran, false);
  assert.match(compileGate({ 'a.hs': 'module A where\n' }).detail, /never start GHC/);
  const missing = compileGate({ 'a.hs': 'module A where\n' }, { compile: true, ghc: '/nonexistent/ghc' });
  assert.equal(missing.ran, false); assert.match(missing.detail, /not available/);
  const stub = async (fs) => (/preEscapedToHtml n\)/.test(fs[SRC.html.file]) ? [HIGH('html')] : []);
  const v = await validateHaskellFix(fin('html'), { files: filesOf('html'), rescan: stub, compile: true, ghc: '/nonexistent/ghc', requireCompile: true });
  assert.equal(v.status, 'blocked'); assert.match(v.reason, /compile verification required/);
  const lenient = await validateHaskellFix(fin('html'), { files: filesOf('html'), rescan: stub });
  assert.equal(lenient.verified.compile, 'not-run');
});

test('[HS-010.AC04] a default static scan and the default fix path never spawn ghc, cabal, stack or Setup.hs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hs-nospawn-'));
  mkdirSync(join(dir, 'bin')); mkdirSync(join(dir, 'src'));
  const log = join(dir, 'spawned.log');
  for (const t of ['ghc', 'cabal', 'stack', 'runghc', 'runhaskell']) writeFileSync(join(dir, 'bin', t), `#!/bin/sh\necho ${t} >> ${log}\nexit 1\n`, { mode: 0o755 });
  writeFileSync(join(dir, 'Setup.hs'), 'import Distribution.Simple\nmain = defaultMain\n');
  writeFileSync(join(dir, 'a.cabal'), 'name: a\nversion: 0.1\nbuild-type: Custom\ncustom-setup\n  setup-depends: base, Cabal\nlibrary\n  build-depends: base\n');
  writeFileSync(join(dir, SRC.proc.file), SRC.proc.text);
  const env = { ...process.env, PATH: `${join(dir, 'bin')}:${process.env.PATH}` }; delete env.NODE_TEST_CONTEXT;
  const bin = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
  const r = spawnSync(process.execPath, [bin, 'scan', dir, '--format', 'json'], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
  assert.ok(r.stdout.includes('"findings"'));
  assert.equal(planHaskellFix(fin('proc'), filesOf('proc')).ok, true);
  assert.equal(existsSync(log), false, existsSync(log) ? readFileSync(log, 'utf8') : '');
});
