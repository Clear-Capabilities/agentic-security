// Release 0.190.0: verified Haskell remediation for the classes that used to refuse (TLS validation, cookie attributes, predictable randomness,
// request-body size), the class-level refusals that now name the decision the operator has to make, the effective-change check, the compile gate in
// the preview path, the Haskell fix witness, and the proposal route.
//
// Every verified case here goes through the REAL scanner (the finding comes from a scan, the rescan of the patched tree is `defaultRescan`) and
// `validateHaskellFix`, with the compile gate requested. Third-party packages (connection, cookie, servant-auth-server, scotty, entropy, wai) are not
// installed on the machines this runs on, so their modules are declared STUBS of the documented API shape (names, field names, types the patch uses,
// checked against the package documentation). A type-check against a stub proves the patch is coherent with that API shape, not that it builds
// against the real package; the report says so. When GHC is absent the compile assertions are skipped LOUDLY (never passed) and the gate is asserted
// to say `ran: false`.
//
// Each fixer also has a structural behavior model that EVALUATES the before/after program text (or, for randomness and the body limit, runs the
// patched Haskell under GHC against a stub) on benign and hostile input, and a paired refusal / near-miss.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runScan } from '../../src/runScan.js';
import { planHaskellFix, validateHaskellFix, verifyHaskellProposal, compileGate, haskellEffectiveCheck, tlsSettingsOf, cookieSitesOf, BODY_HELPER, TIERS } from '../../src/language/haskell-fix.js';
import { languageFixPreview, languageProposalPreview } from '../../src/language/context.js';
import { haskellFixWitness, haskellFunctionAt } from '../../src/language/witness.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { mkTestTmp } from '../helpers/tmp.js';

const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const skipNoGhc = GHC ? false : 'GHC is not installed: compile verification could not run (this is a skip, not a pass)';

async function scan(files) {
  const dir = mkTestTmp('hs-fix0190-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
}
const find = (fs, cwe) => fs.find((x) => x.cwe === cwe && x.severity !== 'info' && /^src\/[A-Z]/.test(x.file));     // the stub modules are scanned too: never pick a finding in one

/** The real lifecycle (real rescan), compile requested. Returns the result; asserts the compile gate's honesty on either kind of host. */
async function verify(finding, files) {
  const v = await validateHaskellFix(finding, { files, compile: GHC });
  assert.equal(v.status, 'verified', JSON.stringify({ reason: v.reason, gates: v.gates }));
  assert.equal(v.gates.rescan.originalGone, true);
  assert.equal(v.tier, TIERS.edit);
  assert.ok(Array.isArray(v.consequences) && v.consequences.length > 0, 'a plan states what it changes');
  if (GHC) assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [true, true], v.gates.compile.detail);
  else assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [false, null], 'no GHC: the gate says it did not run');
  return v;
}

// ── declared stubs of the documented API shape ───────────────────────────────────────────────────────────────────────────────
const STUB_CONNECTION = `module Network.Connection (TLSSettings(..)) where
-- documented: data TLSSettings = TLSSettingsSimple { settingDisableCertificateValidation, settingDisableSession, settingUseServerName :: Bool } | TLSSettings ClientParams
data TLSSettings = TLSSettingsSimple { settingDisableCertificateValidation :: Bool, settingDisableSession :: Bool, settingUseServerName :: Bool } | TLSSettings ()
`;
const STUB_COOKIE = `module Web.Cookie (SetCookie(..), defaultSetCookie) where
import Data.ByteString (ByteString)
-- documented subset of: SetCookie { setCookieName, setCookieValue :: ByteString, .., setCookieHttpOnly, setCookieSecure :: Bool, .. }
data SetCookie = SetCookie { setCookieName :: ByteString, setCookieValue :: ByteString, setCookieHttpOnly :: Bool, setCookieSecure :: Bool }
defaultSetCookie :: SetCookie
defaultSetCookie = SetCookie mempty mempty False False
`;
const STUB_SERVANT = `module Servant.Auth.Server (CookieSettings(..), IsSecure(..), defaultCookieSettings) where
-- documented: data IsSecure = Secure | NotSecure; CookieSettings { cookieIsSecure :: !IsSecure, .. }
data IsSecure = Secure | NotSecure
data CookieSettings = CookieSettings { cookieIsSecure :: IsSecure }
defaultCookieSettings :: CookieSettings
defaultCookieSettings = CookieSettings Secure
`;
const STUB_SCOTTY_COOKIE = `module Web.Scotty.Cookie (setCookie, setSimpleCookie, makeSimpleCookie, SetCookie, defaultSetCookie, setCookieName, setCookieValue, setCookieHttpOnly, setCookieSecure) where
import Data.Text (Text)
import qualified Data.Text.Encoding as T
import Web.Cookie
-- documented: Web.Scotty.Cookie re-exports setCookie, makeSimpleCookie and the SetCookie fields; ActionT is replaced by IO in this stub
setCookie :: SetCookie -> IO ()
setCookie _ = pure ()
makeSimpleCookie :: Text -> Text -> SetCookie
makeSimpleCookie n v = defaultSetCookie { setCookieName = T.encodeUtf8 n, setCookieValue = T.encodeUtf8 v }
setSimpleCookie :: Text -> Text -> IO ()
setSimpleCookie n v = setCookie (makeSimpleCookie n v)
`;
const STUB_ENTROPY = `module System.Entropy (getEntropy) where
import qualified Data.ByteString as B
-- documented: getEntropy :: Int -> IO ByteString. This stub reads the bytes from entropy.bin so a test can choose them.
getEntropy :: Int -> IO B.ByteString
getEntropy n = B.take n <$> B.readFile "entropy.bin"
`;
const STUB_WAI = `module Network.Wai (Request, getRequestBodyChunk, strictRequestBody, mkRequest, pulled) where
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.IORef
-- documented: getRequestBodyChunk :: Request -> IO ByteString (empty at the end); strictRequestBody :: Request -> IO L.ByteString.
-- mkRequest and pulled are test helpers: they build a request from chunks and count how many chunks were pulled.
data Request = Request (IORef [B.ByteString]) (IORef Int)
mkRequest :: [B.ByteString] -> IO Request
mkRequest cs = Request <$> newIORef cs <*> newIORef 0
pulled :: Request -> IO Int
pulled (Request _ n) = readIORef n
getRequestBodyChunk :: Request -> IO B.ByteString
getRequestBodyChunk (Request r n) = do
  cs <- readIORef r
  case cs of
    [] -> pure B.empty
    (c:rest) -> writeIORef r rest >> modifyIORef n (+ 1) >> pure c
strictRequestBody :: Request -> IO L.ByteString
strictRequestBody req = go []
  where go acc = do { c <- getRequestBodyChunk req; if B.null c then pure (L.fromChunks (reverse acc)) else go (c : acc) }
`;

// ═══ 1. TLS validation (CWE-295) ═══════════════════════════════════════════════════════════════════════════════════════════
const TLS_POS = { 'src/Tls.hs': 'module Tls (mk) where\n\nimport Network.Connection\n\nmk :: TLSSettings\nmk = TLSSettingsSimple True False False\n', 'Network/Connection.hs': STUB_CONNECTION };
const TLS_REC = { 'src/Tls.hs': 'module Tls (mk) where\n\nimport Network.Connection\n\nmk :: TLSSettings\nmk = TLSSettingsSimple { settingDisableCertificateValidation = True, settingDisableSession = True, settingUseServerName = False }\n', 'Network/Connection.hs': STUB_CONNECTION };

for (const [name, files] of [['positional', TLS_POS], ['record', TLS_REC]]) {
  test(`TLS (${name}): the literal True becomes False; rescan, effective check and compile (against a stub of connection) pass`, async () => {
    const f = find(await scan(files), 'CWE-295');
    assert.ok(f, 'the scanner reports it');
    const v = await verify(f, files);
    assert.equal(v.plan.ruleId, 'hs-tls-validate');
    assert.equal(v.gates.effective.ran, true);
    assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
    assert.ok(!(await scan({ ...files, 'src/Tls.hs': v.plan.after })).some((x) => x.cwe === 'CWE-295' && x.severity !== 'info'));
  });
}

test('TLS: the behavior model evaluates every construction before and after; only the validation flag moves, on benign and hostile spellings', () => {
  const variants = [
    'TLSSettingsSimple True False False', 'TLSSettingsSimple True True True', 'TLSSettingsSimple (True) False True',
    'TLSSettingsSimple { settingDisableCertificateValidation = True, settingDisableSession = False, settingUseServerName = True }',
    'TLSSettingsSimple {settingUseServerName=True, settingDisableCertificateValidation   =   True, settingDisableSession = True}',
    'TLSSettingsSimple\n  { settingDisableCertificateValidation = True\n  , settingDisableSession = False\n  , settingUseServerName = False }',
  ];
  for (const v of variants) {
    const src = `module T where\nimport Network.Connection\n\ns :: TLSSettings\ns = ${v}\n`;
    const plan = planHaskellFix({ cwe: 'CWE-295', file: 'src/T.hs', line: 5 }, { 'src/T.hs': src });
    assert.equal(plan.ok, true, v);
    const [b] = tlsSettingsOf(plan.before); const [a] = tlsSettingsOf(plan.after);
    assert.equal(b.disableCertificateValidation, true); assert.equal(a.disableCertificateValidation, false);
    assert.deepEqual(a.others.map((x) => String(x).trim()), b.others.map((x) => String(x).trim()), 'session and server-name settings are untouched');
    assert.equal(plan.after.split('\n').length, plan.before.split('\n').length, 'no line was added or removed');
  }
});

test('TLS: a variable, a setting already False, a file without the connection import and the OpenSSL VerifyNone are refused, naming the decision', () => {
  const variable = 'module T where\nimport Network.Connection\n\ns :: Bool -> TLSSettings\ns b = TLSSettingsSimple b False False\n';
  assert.equal(planHaskellFix({ cwe: 'CWE-295', file: 'src/T.hs', line: 5 }, { 'src/T.hs': variable }).ok, false);
  const noImport = 'module T where\n\ns = TLSSettingsSimple True False False\n';
  assert.equal(planHaskellFix({ cwe: 'CWE-295', file: 'src/T.hs', line: 3 }, { 'src/T.hs': noImport }).ok, false);
  const openssl = 'module T where\nimport qualified OpenSSL.Session as SSL\n\nf ctx = SSL.contextSetVerificationMode ctx SSL.VerifyNone\n';
  const r = planHaskellFix({ cwe: 'CWE-295', file: 'src/T.hs', line: 4 }, { 'src/T.hs': openssl });
  assert.equal(r.ok, false);
  assert.equal(r.tier, TIERS.guidance);
  assert.match(r.decision, /trust store/);
  assert.match(r.reason, /VerifyPeer verifies nothing until a CA bundle is loaded/);
});

test('TLS effective check: a patch that edits a DIFFERENT TLS site is caught even though one finding is gone', () => {
  const two = 'module T where\nimport Network.Connection\n\na :: TLSSettings\na = TLSSettingsSimple True False False\n\nb :: TLSSettings\nb = TLSSettingsSimple True False False\n';
  const plan = planHaskellFix({ cwe: 'CWE-295', file: 'src/T.hs', line: 5 }, { 'src/T.hs': two });
  assert.equal(plan.ok, true);
  assert.equal(haskellEffectiveCheck(plan, { 'src/T.hs': plan.after }).ok, true);
  const wrong = two.replace('b = TLSSettingsSimple True', 'b = TLSSettingsSimple False');       // fixed site 2 instead of site 1: the planned site still disables validation
  const e = haskellEffectiveCheck(plan, { 'src/T.hs': wrong });
  assert.equal(e.ok, false, e.detail);
  assert.match(e.detail, /not False/);
});

// ═══ 2. cookie attributes (CWE-1004) ═══════════════════════════════════════════════════════════════════════════════════════
const COOKIE_HDR = { 'src/Ck.hs': '{-# LANGUAGE OverloadedStrings #-}\nmodule Ck (hdr) where\n\nimport Network.HTTP.Types.Header (hSetCookie)\nimport Data.ByteString (ByteString)\n\nhdr :: ByteString -> (Int, ByteString)\nhdr sid = (hSetCookie, "session_id=" <> sid <> "; Path=/")\n' };
const COOKIE_REC = { 'src/Ck.hs': '{-# LANGUAGE OverloadedStrings #-}\nmodule Ck (mk) where\n\nimport Web.Cookie (SetCookie(..), defaultSetCookie)\nimport Data.ByteString (ByteString)\n\nmk :: ByteString -> SetCookie\nmk sid = defaultSetCookie { setCookieName = "session", setCookieValue = sid, setCookieHttpOnly = True }\n', 'Web/Cookie.hs': STUB_COOKIE };
const COOKIE_SERVANT = { 'src/Ck.hs': 'module Ck (cfg) where\n\nimport Servant.Auth.Server\n\ncfg :: CookieSettings\ncfg = defaultCookieSettings { cookieIsSecure = NotSecure }\n', 'Servant/Auth/Server.hs': STUB_SERVANT };
const COOKIE_SCOTTY = { 'src/Ck.hs': '{-# LANGUAGE OverloadedStrings #-}\nmodule Ck (login) where\n\nimport Web.Scotty.Cookie (setSimpleCookie, setCookie)\nimport qualified Data.Text as T\n\nlogin :: T.Text -> IO ()\nlogin sid = do\n  setSimpleCookie "sess_id" sid\n  pure ()\n', 'Web/Scotty/Cookie.hs': STUB_SCOTTY_COOKIE, 'Web/Cookie.hs': STUB_COOKIE };

test('cookie: a Set-Cookie header literal gains HttpOnly and Secure; the header is EVALUATED before and after on benign and hostile session ids', async () => {
  const f = find(await scan(COOKIE_HDR), 'CWE-1004');
  assert.ok(f);
  const v = await validateHaskellFix(f, { files: COOKIE_HDR, compile: false });     // the header shape imports http-types, which has no stub here
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
  assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
  assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [false, null], 'the compile gate was not requested and says so');
  // the behavior model: evaluate `value` of the tuple for a session id
  const evalValue = (src, sid) => {
    const m = /hSetCookie, (.*)\)\s*$/m.exec(src); assert.ok(m, src);
    return m[1].split(/ <> /).map((p) => (/^".*"$/.test(p.trim()) ? p.trim().slice(1, -1) : sid)).join('');
  };
  const attrs = (h) => h.split(';').slice(1).map((x) => x.trim().toLowerCase());
  for (const sid of ['abc123', 'x; Domain=evil.example; Secure=no', '']) {
    const before = evalValue(v.plan.before, sid); const after = evalValue(v.plan.after, sid);
    assert.equal(after, `${before}; HttpOnly; Secure`, 'the old header is a prefix: name, value and Path are untouched');
    assert.ok(attrs(after).includes('httponly') && attrs(after).includes('secure'));
    assert.ok(!attrs(before).includes('secure'));
    assert.ok(after.startsWith(`session_id=${sid}`));
  }
  assert.ok(!(await scan({ 'src/Ck.hs': v.plan.after })).some((x) => x.cwe === 'CWE-1004' && x.severity !== 'info'));
});

for (const [name, files, mustHave] of [
  ['record update', COOKIE_REC, /setCookieHttpOnly = True, setCookieSecure = True/],
  ['servant-auth', COOKIE_SERVANT, /cookieIsSecure = Secure\b/],
  ['scotty helper', COOKIE_SCOTTY, /setCookie \(defaultSetCookie \{ setCookieName = AgenticTE\.encodeUtf8 "sess_id", setCookieValue = AgenticTE\.encodeUtf8 sid, setCookieHttpOnly = True, setCookieSecure = True \}\)/],
]) {
  test(`cookie (${name}): verified by the real rescan, the effective-change check and a type-check against a stub of the documented API`, async () => {
    const f = find(await scan(files), 'CWE-1004');
    assert.ok(f, 'the scanner reports it');
    const v = await verify(f, files);
    assert.equal(v.plan.ruleId, 'hs-cookie-attributes');
    assert.match(v.plan.after, mustHave);
    assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
    assert.ok(v.consequences.some((c) => /Secure|HttpOnly/.test(c)));
    // the model: the cookie site, read back from the patched program, carries both attributes and is the same cookie
    const b = cookieSitesOf(v.plan.before); const a = cookieSitesOf(v.plan.after);
    assert.equal(a.length, b.length);
    assert.ok(a.every((s) => s.httpOnly && s.secure) && b.some((s) => !(s.httpOnly && s.secure)));
  });
}

test('cookie: the effective check is NOT the rescan; renaming a cookie silences the finding without adding an attribute, and the check says so', async () => {
  const f = find(await scan(COOKIE_HDR), 'CWE-1004');
  const plan = planHaskellFix(f, COOKIE_HDR);
  assert.equal(plan.ok, true);
  const renamed = COOKIE_HDR['src/Ck.hs'].replace('session_id=', 'theme=');          // the rule judges session-shaped names only
  const rescanned = await scan({ 'src/Ck.hs': renamed });
  assert.ok(!rescanned.some((x) => x.cwe === 'CWE-1004' && x.severity !== 'info'), 'a rescan alone calls this fixed');
  const e = haskellEffectiveCheck(plan, { 'src/Ck.hs': renamed });
  assert.equal(e.ok, false, e.detail);
  assert.match(e.detail, /still reads HttpOnly=false/);
});

test('cookie: near-misses are refused (value from a variable, flag from an expression, Secure not importable, not a whole statement, the library itself)', () => {
  const plan = (src, line) => planHaskellFix({ cwe: 'CWE-1004', file: 'src/Ck.hs', line }, { 'src/Ck.hs': src });
  // the last operand is a variable: nowhere to append attributes
  assert.equal(plan(COOKIE_HDR['src/Ck.hs'].replace('"; Path=/"', 'path'), 8).ok, false);
  // a flag set from an expression is not a literal we can judge
  assert.equal(plan(COOKIE_REC['src/Ck.hs'].replace('setCookieHttpOnly = True', 'setCookieHttpOnly = flag'), 8).ok, false);
  // `Secure` is not in scope when only NotSecure was imported
  assert.equal(plan(COOKIE_SERVANT['src/Ck.hs'].replace('import Servant.Auth.Server', 'import Servant.Auth.Server (CookieSettings(..), defaultCookieSettings, IsSecure(NotSecure))'), 6).ok, false);
  // setSimpleCookie as a value, not a statement
  assert.equal(plan(COOKIE_SCOTTY['src/Ck.hs'].replace('  setSimpleCookie "sess_id" sid\n  pure ()', '  _ <- pure (setSimpleCookie "sess_id" sid)\n  pure ()'), 9).ok, false);
  // the module that DEFINES the helper
  assert.equal(plan(COOKIE_SCOTTY['src/Ck.hs'].replace('module Ck (login)', 'module Web.Scotty.Cookie (login)'), 9).ok, false);
  // a cookie that is not in a recognised framework shape keeps the class refusal and names the decision
  const r = planHaskellFix({ cwe: 'CWE-1004', file: 'src/X.hs', line: 3 }, { 'src/X.hs': 'module X where\nx :: Int\nx = 1\n' });
  assert.equal(r.ok, false); assert.match(r.decision, /Secure, HttpOnly, SameSite/);
});

// ═══ 3. predictable randomness (CWE-338) ═════════════════════════════════════════════════════════════════════════════════════
const RND = (ty = 'Word64') => ({ 'src/Tok.hs': `module Tok (newCsrfToken) where\n\nimport System.Random (randomIO)\nimport System.Entropy (getEntropy)\nimport Data.Word\nimport Data.Int\n\nnewCsrfToken :: IO ${ty}\nnewCsrfToken = randomIO\n`, 'System/Entropy.hs': STUB_ENTROPY });

test('randomness: the whole-value token action reads the OS entropy; verified by rescan, effective check and compile; the patched program is RUN against chosen bytes', async () => {
  const files = RND('Word64');
  const f = find(await scan(files), 'CWE-338');
  assert.ok(f, 'the scanner reports it');
  const v = await verify(f, files);
  assert.equal(v.plan.ruleId, 'hs-random-os-entropy');
  assert.match(v.plan.after, /newCsrfToken = AgenticBS\.foldl' \(\\acc b -> acc \* 256 \+ fromIntegral b\) 0 <\$> getEntropy 8/);
  assert.ok(!/import System\.Random/.test(v.plan.after), 'the now-unused System.Random import is removed');
  assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
  assert.ok(!(await scan({ ...files, 'src/Tok.hs': v.plan.after })).some((x) => x.cwe === 'CWE-338' && x.severity !== 'info'));
});

test('randomness: the patched action is EVALUATED by GHC against chosen entropy (benign, all-ones, zero) for several fixed-width types', { skip: skipNoGhc }, () => {
  for (const [ty, bytes, signed] of [['Word64', 8, false], ['Word32', 4, false], ['Word8', 1, false], ['Int64', 8, true], ['Int', 8, true]]) {
    const files = RND(ty);
    const plan = planHaskellFix({ cwe: 'CWE-338', file: 'src/Tok.hs', line: 9 }, files);
    assert.equal(plan.ok, true, ty);
    const dir = mkTestTmp('hs-rnd-eval-');
    for (const [p, t] of Object.entries({ ...files, 'src/Tok.hs': plan.after })) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), t); }
    for (const raw of [[1, 2, 3, 4, 5, 6, 7, 8], new Array(8).fill(255), new Array(8).fill(0)]) {
      const used = raw.slice(0, bytes);
      writeFileSync(join(dir, 'entropy.bin'), Buffer.from(raw));
      const r = spawnSync('ghc', ['-isrc', '-i.', '-e', ':load *src/Tok.hs', '-e', 'newCsrfToken >>= print'], { cwd: dir, encoding: 'utf8', timeout: 120000 });
      assert.equal(r.status, 0, r.stderr);
      let want = used.reduce((acc, b) => acc * 256n + BigInt(b), 0n);
      if (signed && used[0] >= 128) want -= 1n << BigInt(8 * bytes);
      assert.equal(BigInt(r.stdout.trim()), want, `${ty} from ${used}`);
    }
  }
});

test('randomness: every other shape is refused (a range, no entropy import, a wider or non-integer type, a function with parameters)', () => {
  const plan = (src, line) => planHaskellFix({ cwe: 'CWE-338', file: 'src/Tok.hs', line }, { 'src/Tok.hs': src });
  const base = RND('Word64')['src/Tok.hs'];
  assert.equal(plan(base.replace('= randomIO', '= randomRIO (0, 1000000000)').replace('import System.Random (randomIO)', 'import System.Random (randomRIO)'), 9).ok, false, 'a bounded range needs rejection sampling, not a byte decode');
  assert.equal(plan(base.replace('import System.Entropy (getEntropy)\n', ''), 9).ok, false, 'the entropy dependency is not declared by the file');
  assert.equal(plan(base.replace('IO Word64', 'IO Integer'), 9).ok, false);
  assert.equal(plan(base.replace('newCsrfToken :: IO Word64\nnewCsrfToken = randomIO', 'newCsrfToken :: Int -> IO Word64\nnewCsrfToken n = fmap (+ fromIntegral n) randomIO'), 9).ok, false);
  const gitit = 'module S where\nimport System.Random (randomRIO)\nnewSession :: IO Int\nnewSession = randomRIO (0, 1000000000)\n';
  const r = plan(gitit, 4);
  assert.equal(r.ok, false); assert.match(r.reason, /CSPRNG/); assert.match(r.decision, /token's type and size/);
});

// ═══ 4. request body size (CWE-770) ══════════════════════════════════════════════════════════════════════════════════════════
const BODY = { 'src/Svc.hs': 'module Svc where\n\nimport Network.Wai\nimport qualified Data.ByteString.Lazy as LBS\n\nreadIt :: Request -> IO LBS.ByteString\nreadIt req = do\n  strictRequestBody req\n', 'Network/Wai.hs': STUB_WAI };

test('request body: strictRequestBody becomes a bounded reader with a DECLARED default limit; verified by rescan, effective check and compile', async () => {
  const f = (await scan(BODY)).find((x) => x.rule === 'hs-unbounded-request-body' || (x.cwe === 'CWE-770' && /request body/i.test(x.vuln)));
  assert.ok(f, 'the scanner reports it');
  const v = await verify(f, BODY);
  assert.equal(v.plan.ruleId, 'hs-request-body-bound');
  assert.equal(v.plan.label, 'MITIGATION');
  assert.match(v.plan.after, /boundedRequestBody req\n/);
  assert.ok(v.plan.after.includes(BODY_HELPER));
  assert.ok(v.consequences.some((c) => /1048576/.test(c) && /requestBodyLimitBytes/.test(c)), 'the consequence states the default and what it rejects');
  assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
  assert.ok(!(await scan({ ...BODY, 'src/Svc.hs': v.plan.after })).some((x) => x.cwe === 'CWE-770' && x.severity !== 'info'));
});

test('request body: the patched reader is RUN by GHC; a benign body is returned whole, a hostile one stops early, the original reads everything', { skip: skipNoGhc }, () => {
  const plan = planHaskellFix({ cwe: 'CWE-770', rule: 'hs-unbounded-request-body', file: 'src/Svc.hs', line: 8 }, BODY);
  assert.equal(plan.ok, true);
  const dir = mkTestTmp('hs-body-eval-');
  const harness = `module Main (main) where
import Network.Wai
import Svc
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Control.Exception

run :: String -> (Request -> IO L.ByteString) -> [B.ByteString] -> IO ()
run name f chunks = do
  req <- mkRequest chunks
  r <- try (f req) :: IO (Either IOException L.ByteString)
  n <- pulled req
  putStrLn (name ++ " " ++ either (const "threw") (\\b -> "ok " ++ show (L.length b)) r ++ " pulled=" ++ show n)

main :: IO ()
main = do
  let benign = replicate 3 (B.replicate 1000 65)
      hostile = replicate 200 (B.replicate 100000 66)
  run "patched-benign" readIt benign
  run "patched-hostile" readIt hostile
  run "original-hostile" strictRequestBody hostile
`;
  for (const [p, t] of Object.entries({ ...BODY, 'src/Svc.hs': plan.after, 'Main.hs': harness })) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), t); }
  const r = spawnSync('runghc', ['-isrc', '-i.', 'Main.hs'], { cwd: dir, encoding: 'utf8', timeout: 180000 });
  assert.equal(r.status, 0, r.stderr);
  const out = Object.fromEntries(r.stdout.trim().split('\n').map((l) => { const m = /^(\S+) (threw|ok \d+) pulled=(\d+)$/.exec(l); return [m[1], { result: m[2], pulled: Number(m[3]) }]; }));
  assert.deepEqual(out['patched-benign'], { result: 'ok 3000', pulled: 3 });
  assert.equal(out['patched-hostile'].result, 'threw');
  assert.ok(out['patched-hostile'].pulled <= 11, `stopped after ${out['patched-hostile'].pulled} chunks of 100000 bytes (limit 1048576)`);
  assert.equal(out['original-hostile'].pulled, 200, 'the original pulled every chunk into memory');
});

test('request body: near-misses are refused (lazyRequestBody, no wai import, a taken name) and a second call reuses the one helper', () => {
  const plan = (files, line) => planHaskellFix({ cwe: 'CWE-770', rule: 'hs-unbounded-request-body', file: 'src/Svc.hs', line }, files);
  assert.equal(plan({ 'src/Svc.hs': BODY['src/Svc.hs'].replace('strictRequestBody req', 'lazyRequestBody req') }, 8).ok, false);
  assert.equal(plan({ 'src/Svc.hs': BODY['src/Svc.hs'].replace('import Network.Wai\n', 'import Network.Wai.Internal\n') }, 8).ok, false);
  assert.equal(plan({ 'src/Svc.hs': `${BODY['src/Svc.hs']}\nboundedRequestBody :: Int\nboundedRequestBody = 1\n` }, 8).ok, false, 'a name of ours is already used by something else');
  assert.equal(plan({ 'src/Svc.hs': BODY['src/Svc.hs'].replace('module Svc', '{-# LANGUAGE NoImplicitPrelude #-}\nmodule Svc') }, 9).ok, false);
  // the rule reports one finding per function, so every strictRequestBody call of the file is rewritten and the helper is defined once
  const two = BODY['src/Svc.hs'] + '\nreadAgain :: Request -> IO LBS.ByteString\nreadAgain r = strictRequestBody r\n';
  const first = plan({ 'src/Svc.hs': two }, 8);
  assert.equal(first.ok, true);
  assert.equal(first.behavior.replaced, 2);
  assert.ok(!/strictRequestBody/.test(first.after.replace(BODY_HELPER, '')), 'both calls were replaced');
  assert.equal(first.after.split('boundedRequestBody req = go 0 []').length - 1, 1, 'the helper is defined once');
  assert.equal(first.after.split('import qualified Network.Wai as AgentcW').length - 1, 1);
  // a file that already holds the helper gets a new call rewritten without a second definition
  const later = first.after + '\nreadThird :: Request -> IO LBS.ByteString\nreadThird q = strictRequestBody q\n';
  const third = planHaskellFix({ cwe: 'CWE-770', rule: 'hs-unbounded-request-body', file: 'src/Svc.hs', line: later.split('\n').findIndex((l) => /readThird q =/.test(l)) + 1 }, { 'src/Svc.hs': later });
  assert.equal(third.ok, true);
  assert.equal(third.after.split('boundedRequestBody req = go 0 []').length - 1, 1);
  const r = planHaskellFix({ cwe: 'CWE-770', file: 'src/X.hs', line: 3 }, { 'src/X.hs': 'module X where\nx :: Int\nx = 1\n' });
  assert.equal(r.ok, false); assert.match(r.decision, /limit for this input/);
});

// ═══ 5. the classes that keep refusing: the reason names the decision ═════════════════════════════════════════════════════════
test('refusals name the decision: SSRF, argument injection, missing auth, hard-coded secrets, password hashing, with a tier and no patch', () => {
  const want = { 'CWE-918': /allow-list|address policy/, 'CWE-88': /permitted values/, 'CWE-306': /which credential/, 'CWE-798': /where the secret is read from/, 'CWE-916': /which KDF and library/ };
  for (const [cwe, re] of Object.entries(want)) {
    const r = planHaskellFix({ cwe, file: 'src/X.hs', line: 3 }, { 'src/X.hs': 'module X where\nx :: Int\nx = 1\n' });
    assert.equal(r.ok, false, cwe);
    assert.equal(r.tier, TIERS.guidance);
    assert.equal(r.proposal, 'model-assisted');
    assert.match(r.reason, /The decision needed:/, cwe);
    assert.match(r.decision, re, cwe);
  }
  const pw = planHaskellFix({ cwe: 'CWE-916', file: 'src/X.hs', line: 3 }, { 'src/X.hs': 'module X where\nx :: Int\nx = 1\n' });
  assert.match(pw.reason, /KDF/);
  assert.match(pw.reason, /library the project may not declare/, 'the dependency');
  assert.match(pw.reason, /every stored hash was produced by the old function/, 'why a swap is worse than a refusal');
  assert.match(pw.reason, /migration/);
});

// ═══ 6. the compile gate in the preview path ═══════════════════════════════════════════════════════════════════════════════════
const PROC = { 'src/Main.hs': 'module Main (main, run) where\n\nimport System.Process\n\nrun :: String -> IO ()\nrun n = callCommand ("ls " ++ n)\n\nmain :: IO ()\nmain = getLine >>= run\n' };

test('the preview path requests the compile gate: GHC type-checks the patch against the original; an absent GHC or a missing package is not-run, never a pass', async () => {
  const f = find(await scan(PROC), 'CWE-78');
  assert.ok(f);
  const pv = await languageFixPreview(f, PROC);
  assert.equal(pv.status, 'verified', JSON.stringify(pv.gates));
  assert.equal(pv.tier, TIERS.edit);
  assert.ok(pv.consequences.some((c) => /shell/.test(c)));
  if (GHC) assert.deepEqual([pv.gates.compile.ran, pv.gates.compile.ok], [true, true], pv.gates.compile.detail);
  else assert.equal(pv.gates.compile.ran, false);
  const off = await languageFixPreview(f, PROC, { compile: false });
  assert.equal(off.gates.compile.ran, false);
  assert.match(off.gates.compile.detail, /not requested/);
  // no GHC at the path given: recorded as not run
  const none = await validateHaskellFix(f, { files: PROC, compile: true, ghc: '/nonexistent/ghc' });
  assert.equal(none.status, 'verified');
  assert.deepEqual([none.gates.compile.ran, none.gates.compile.ok], [false, null]);
  assert.match(none.gates.compile.detail, /not available/);
  assert.equal(none.verified.compile, 'not-run');
  // requireCompile turns that into a block
  const req = await validateHaskellFix(f, { files: PROC, compile: true, ghc: '/nonexistent/ghc', requireCompile: true });
  assert.equal(req.status, 'blocked');
});

test('compile gate: a project that does not type-check on this host (a package it lacks) is not-run; a patch that breaks a compiling file is a failure', { skip: skipNoGhc }, () => {
  const lacks = { 'src/A.hs': 'module A where\nimport Some.Missing.Package (thing)\n\nx :: Int\nx = thing\n' };
  const g = compileGate({ 'src/A.hs': lacks['src/A.hs'].replace('x = thing', 'x = thing + 1') }, { compile: true, baseline: lacks, targets: ['src/A.hs'] });
  assert.deepEqual([g.ran, g.ok], [false, null]);
  assert.match(g.detail, /original does not type-check on this host/);
  const good = { 'src/B.hs': 'module B where\nx :: Int\nx = 1\n' };
  const bad = compileGate({ 'src/B.hs': 'module B where\nx :: Int\nx = "one"\n' }, { compile: true, baseline: good, targets: ['src/B.hs'] });
  assert.deepEqual([bad.ran, bad.ok], [true, false]);
  const adds = compileGate({ 'src/B.hs': 'module B where\nimport Not.Installed (y)\nx :: Int\nx = y\n' }, { compile: true, baseline: good, targets: ['src/B.hs'] });
  assert.deepEqual([adds.ran, adds.ok], [false, null], 'a module the patch adds that this host lacks cannot be judged');
  assert.match(adds.detail, /not installed on this host/);
});

// ═══ 7. the fix witness ══════════════════════════════════════════════════════════════════════════════════════════════════════
test('haskellFixWitness: a command-injection fix is witness-verified (the payload runs the shell in the original, not in the patch) where GHC and the sandbox exist', { skip: !GHC || !sandboxAvailable() ? 'GHC or the confinement sandbox is unavailable (a skip, not a pass)' : false }, async () => {
  const f = find(await scan(PROC), 'CWE-78');
  const v = await validateHaskellFix(f, { files: PROC, compile: true, witness: haskellFixWitness(f), requireWitness: true });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates.witness || v.reason));
  assert.equal(v.gates.witness.verified, true);
  assert.equal(v.verified.witness, 'passed');
  assert.equal(haskellFunctionAt(PROC['src/Main.hs'], 6).name, 'run');
});

test('haskellFixWitness: refuses, with the reason, every class whose effect a program GHC runs alone cannot show; and an unloadable file', () => {
  const hook = (f) => haskellFixWitness(f);
  for (const [kind, re] of [['tls', /untrusted certificate/], ['cookie', /response header/], ['random', /distribution/], ['body-limit', /wai/], ['sql', /database/], ['hash', /digest|exploitable/], ['path', /base directory/]]) {
    const w = hook({ line: 1 })({ behavior: { kind }, before: '', after: '', file: 'a.hs' }, {}, {});
    assert.equal(w.verified, false, kind); assert.match(w.reason, re, kind);
  }
  const notLoadable = 'module Main (run) where\nimport Network.Wai\nimport System.Process\n\nrun :: String -> IO ()\nrun n = callCommand ("ls " ++ n)\n';
  const plan = { behavior: { kind: 'process' }, before: notLoadable, after: notLoadable, file: 'src/Main.hs' };
  const w = hook({ line: 6 })(plan, {}, {});
  assert.equal(w.verified, false);
  assert.ok(/boot packages|GHC on PATH|could not be listed/.test(w.reason), w.reason);
  const noParam = hook({ line: 6 })({ ...plan, before: 'module M where\nimport System.Process\n\nrun :: Int -> IO ()\nrun n = callCommand ("ls " ++ show n)\n' }, {}, {});
  assert.equal(noParam.verified, false);
});

// ═══ 8. proposals: the wiring of verifyHaskellProposal ═════════════════════════════════════════════════════════════════════════
test('a patch someone else wrote goes through the same gates: a correct one verifies, one that leaves the flaw or breaks the types is blocked', async () => {
  const f = find(await scan(PROC), 'CWE-78');
  const good = PROC['src/Main.hs'].replace('callCommand ("ls " ++ n)', 'callProcess "ls" ["--", n]');
  const ok = await languageProposalPreview(f, PROC, { file: 'src/Main.hs', proposal: good });
  assert.equal(ok.status, 'verified', JSON.stringify(ok.gates));
  assert.equal(ok.tier, 'proposal-verified');
  assert.equal(ok.applied, false);
  if (GHC) assert.deepEqual([ok.gates.compile.ran, ok.gates.compile.ok], [true, true]);
  const still = await languageProposalPreview(f, PROC, { file: 'src/Main.hs', proposal: PROC['src/Main.hs'].replace('"ls " ++ n', '"ls -l " ++ n') });
  assert.equal(still.ok, false); assert.match(still.reason, /still reported/);
  if (GHC) {
    const broken = await languageProposalPreview(f, PROC, { file: 'src/Main.hs', proposal: PROC['src/Main.hs'].replace('callCommand ("ls " ++ n)', 'callProcess "ls" "--" n') });
    assert.equal(broken.ok, false);
    assert.match(broken.reason, /compile/);
  }
  const direct = await verifyHaskellProposal(f, { files: PROC, file: 'src/Main.hs', proposal: good, compile: false });
  assert.equal(direct.status, 'verified');
  const missing = await languageProposalPreview(f, PROC, { file: 'src/Nope.hs', proposal: good });
  assert.equal(missing.ok, false);
});

// ═══ 9. qualified spellings ═══════════════════════════════════════════════════════════════════════════════════════════════════
test('qualified spellings: a qualified strictRequestBody call is replaced whole, and a qualified SetCookie update keeps its qualifier on the new fields', () => {
  const body = planHaskellFix({ cwe: 'CWE-770', rule: 'hs-unbounded-request-body', file: 'src/Svc.hs', line: 8 }, { 'src/Svc.hs': BODY['src/Svc.hs'].replace('import Network.Wai\n', 'import qualified Network.Wai as W\n').replace('Request ->', 'W.Request ->').replace('  strictRequestBody req', '  W.strictRequestBody req') });
  assert.equal(body.ok, true);
  assert.match(body.after, /^  boundedRequestBody req$/m);
  assert.ok(!/W\.boundedRequestBody/.test(body.after), 'the qualifier belongs to the call that was replaced');
  const rec = planHaskellFix({ cwe: 'CWE-1004', file: 'src/Ck.hs', line: 8 }, { 'src/Ck.hs': '{-# LANGUAGE OverloadedStrings #-}\nmodule Ck (mk) where\n\nimport qualified Web.Cookie as C\nimport Data.ByteString (ByteString)\n\nmk :: ByteString -> C.SetCookie\nmk sid = C.defaultSetCookie { C.setCookieName = "session", C.setCookieValue = sid }\n' });
  assert.equal(rec.ok, true);
  assert.match(rec.after, /C\.setCookieHttpOnly = True, C\.setCookieSecure = True/);
  const sites = cookieSitesOf(rec.after);
  assert.ok(sites.length === 1 && sites[0].httpOnly && sites[0].secure);
});
