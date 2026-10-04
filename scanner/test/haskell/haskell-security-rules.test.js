// HS-004: Haskell crypto, parser, resource and privacy rules.
// Suite "haskell-security-rules" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeHaskellRules, RULES, BOUNDARIES, HS_RULES_VERSION } from '../../src/language/haskell-security-rules.js';
import { modelStatus, HS_PACKAGES } from '../../src/language/haskell-models.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const mod = (name, imports, body) => `module ${name} where\n${imports}\n${body}\n`;
const rulesOf = (files) => analyzeHaskellRules(files);
const one = (src, name = 'T') => rulesOf({ [`${name}.hs`]: src }).findings.map((f) => f.rule).sort();
const CH = 'import Crypto.Hash (hash, hashWith, MD5(..), SHA1(..), SHA256(..))\nimport qualified Crypto.Hash.MD5 as MD5\nimport qualified Crypto.Hash.SHA256 as S256\nimport qualified Data.ByteString.Char8 as B';

function scan(files) {
  const dir = mkdtempSync(join(tmpdir(), 'hs-rules-'));
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings;
}

// ---- AC01 ------------------------------------------------------------------

test('[HS-004.AC01] weak hashes are flagged by API identity; strong hashes and unrelated functions are not', () => {
  assert.deepEqual(one(mod('T', CH, 'a = hashWith MD5 (B.pack "x")')), ['hs-weak-hash']);
  assert.deepEqual(one(mod('T', CH, 'a = hashWith SHA1 (B.pack "x")')), ['hs-weak-hash']);
  assert.deepEqual(one(mod('T', CH, 'a = MD5.hash (B.pack "x")')), ['hs-weak-hash']);
  assert.deepEqual(one(mod('T', CH, 'a = hashWith SHA256 (B.pack "x")')), [], 'SHA-256 is not weak');
  assert.deepEqual(one(mod('T', CH, 'a = S256.hash (B.pack "x")')), []);
  // same bare name, different module and a user-defined function
  assert.deepEqual(one(mod('T', 'import Data.Hashable (hash)', 'a = hash "x"')), [], 'Data.Hashable.hash is a hashtable hash, not Crypto.Hash');
  assert.deepEqual(one(mod('T', '', 'md5 :: String -> String\nmd5 = id\na = md5 "x"')), [], 'a user function named md5 is not Data.Digest.Pure.MD5.md5');
});

test('[HS-004.AC01] password storage: a fast hash of a password-shaped value is flagged, a KDF with enough iterations is not', () => {
  assert.deepEqual(one(mod('T', CH, 'store pw = hashWith SHA256 (B.pack pw)')), ['hs-fast-password-hash']);
  assert.deepEqual(one(mod('T', CH, 'store password = S256.hash (B.pack password)')), ['hs-fast-password-hash']);
  assert.deepEqual(one(mod('T', CH, 'checksum payload = S256.hash (B.pack payload)')), [], 'hashing a non-secret with SHA-256 is fine');
  const P = 'import Crypto.KDF.PBKDF2 (generate, prfHMAC, Parameters(..))\nimport Crypto.Hash (SHA256(..))';
  const low = rulesOf({ 'T.hs': mod('T', P, 'k pw salt = generate (prfHMAC SHA256) (Parameters { iterCounts = 100, outputLength = 32 }) pw salt') }).findings;
  assert.deepEqual(low.map((f) => f.rule), ['hs-pbkdf2-low-iterations']);
  assert.equal(low[0].evidence.iterations, 100);
  assert.deepEqual(one(mod('T', P, 'k pw salt = generate (prfHMAC SHA256) (Parameters { iterCounts = 600000, outputLength = 32 }) pw salt')), [], 'an effective iteration count passes');
});

test('[HS-004.AC01] cipher choice: obsolete primitives and ECB are flagged, AEAD and CBC calls are not', () => {
  assert.deepEqual(one(mod('T', 'import Crypto.Cipher.DES (DES)', 'x = 1')), ['hs-weak-cipher']);
  assert.deepEqual(one(mod('T', 'import Crypto.Cipher.RC4', 'x = 1')), ['hs-weak-cipher']);
  assert.deepEqual(one(mod('T', 'import Crypto.Cipher.AES (AES256)', 'x = 1')), []);
  assert.deepEqual(one(mod('T', 'import Crypto.Cipher.Types (ecbEncrypt)', 'e c b = ecbEncrypt c b')), ['hs-ecb-mode']);
  assert.deepEqual(one(mod('T', 'import Crypto.Cipher.Types (cbcEncrypt)', 'e c iv b = cbcEncrypt c iv b')), []);
  const w = rulesOf({ 'T.hs': mod('T', 'import Crypto.Cipher.DES (DES)', 'x = 1') }).findings[0];
  assert.ok(w.confidence < 0.7 && /type/.test(w.description), 'the finding discloses that type-directed use is not resolved');
});

test('[HS-004.AC01] static IVs and nonces: a constant is flagged, a freshly generated value is not', () => {
  const B = 'import Crypto.Cipher.Types (makeIV, nullIV)\nimport qualified Data.ByteString.Char8 as B\nimport Crypto.Random (getRandomBytes)';
  assert.deepEqual(one(mod('T', B, 'iv = makeIV (B.pack "0123456789abcdef")')), ['hs-static-iv']);
  assert.deepEqual(one(mod('T', B, 'iv = nullIV')), ['hs-static-iv']);
  assert.deepEqual(one(mod('T', B, 'mk = do\n  bs <- getRandomBytes 16\n  pure (makeIV (bs :: B.ByteString))')), [], 'a value from the OS CSPRNG is not static');
  assert.deepEqual(one(mod('T', B, 'mk bs = makeIV bs')), [], 'an argument supplied by the caller is not provably static');
});

test('[HS-004.AC01] randomness: a deterministic PRNG is a finding only when it produces a security value; generic random use is not', () => {
  const R = 'import System.Random (randomRIO, mkStdGen, randomRs)\nimport Crypto.Random (getRandomBytes)';
  assert.deepEqual(one(mod('T', R, 'f = do\n  token <- randomRIO (0, 1000000 :: Int)\n  pure token')), ['hs-predictable-random']);
  assert.deepEqual(one(mod('T', R, 'f = do\n  sessionKey <- randomRIO (0, 99999999 :: Int)\n  pure sessionKey')), ['hs-predictable-random']);
  assert.deepEqual(one(mod('T', R, 'f = do\n  roll <- randomRIO (1, 6 :: Int)\n  pure roll')), [], 'a dice roll is not a security value');
  assert.deepEqual(one(mod('T', R, 'f = do\n  jitter <- randomRIO (0, 100 :: Int)\n  pure jitter')), []);
  assert.deepEqual(one(mod('T', R, 'f = do\n  token <- getRandomBytes 32\n  pure token')), [], 'the OS CSPRNG is the supported generator');
  assert.deepEqual(one(mod('T', '', 'random :: Int -> Int\nrandom = id\nf = do\n  let token = random 4\n  pure token')), [], 'a user function named random is not System.Random');
});

test('[HS-004.AC01] input and resource limits are judged on effective configuration', () => {
  const W = 'import Network.Wai (strictRequestBody, Request)';
  const open = rulesOf({ 'A.hs': mod('A', W, 'handler :: Request -> IO ()\nhandler req = strictRequestBody req >> pure ()') });
  assert.deepEqual(open.findings.map((f) => f.rule), ['hs-unbounded-request-body']);
  assert.equal(open.findings[0].severity, 'medium');
  // a size-limit middleware anywhere in the project is an effective-limit signal: still visible, but lower and uncertain
  const limited = rulesOf({
    'A.hs': mod('A', W, 'handler :: Request -> IO ()\nhandler req = strictRequestBody req >> pure ()'),
    'Main.hs': mod('Main', 'import Network.Wai.Middleware.RequestSizeLimit', 'app = requestSizeLimitMiddleware defaultRequestSizeLimitSettings undefined'),
  });
  assert.equal(limited.findings.length, 1);
  assert.equal(limited.findings[0].severity, 'low');
  assert.equal(limited.findings[0].uncertainty[0].kind, 'unresolved-import', 'it is not verified that the limit wraps this handler');
  assert.equal(limited.controls[0].kind, 'request-size-limit'); assert.equal(limited.controls[0].verified, false);
});

test('[HS-004.AC01] XML entity handling is flagged only when substitution is explicitly enabled', () => {
  const X = 'import Text.XML.HXT.Core (withSubstDTDEntities, yes, no)';
  assert.deepEqual(one(mod('T', X, 'o = withSubstDTDEntities yes')), ['hs-xml-entity-substitution']);
  assert.deepEqual(one(mod('T', X, 'o = withSubstDTDEntities True')), ['hs-xml-entity-substitution']);
  assert.deepEqual(one(mod('T', X, 'o = withSubstDTDEntities no')), []);
  assert.deepEqual(one(mod('T', X, 'o = withSubstDTDEntities False')), []);
});

test('[HS-004.AC01] generic decode/random/read/hash identifiers and unmodelled library calls trigger nothing', () => {
  const src = mod('T', 'import Text.Read (readMaybe)\nimport qualified Data.Aeson as A\nimport Data.Binary (decode)\nimport qualified Data.Map as M', `
decodeThing :: String -> Int
decodeThing = read
parse :: String -> Maybe Int
parse = readMaybe
j s = A.decode s
b s = decode s
random :: Int
random = 4
hash :: Int -> Int
hash = (+ 1)
m = M.fromList [(1, "a")]
`);
  assert.deepEqual(rulesOf({ 'T.hs': src }).findings, []);
});

test('[HS-004.AC01] the model records tested package versions and never treats an unknown version as covered', () => {
  assert.ok(HS_PACKAGES.cryptonite && HS_PACKAGES.random && HS_PACKAGES.hxt);
  assert.equal(modelStatus('cryptonite', '0.30'), 'tested');
  assert.equal(modelStatus('cryptonite', '0.99'), 'untested-version');
  assert.equal(modelStatus('cryptonite', undefined), 'unknown-version');
  const f = rulesOf({ 'T.hs': mod('T', CH, 'a = MD5.hash (B.pack "x")') }).findings[0];
  assert.equal(f.rulesetVersion, HS_RULES_VERSION);
  assert.match(f.modelVersion, /^haskell-models\//);
  for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) assert.ok(f[k], k);
  for (const rule of Object.values(RULES)) assert.ok(/^CWE-\d+$/.test(rule.cwe) && rule.remediation && rule.family);
});

// ---- AC02 ------------------------------------------------------------------

const LOGGING_SRC = (body, imports = '') => mod('T', `import qualified Data.Text as T\nimport System.IO (hPutStrLn, stderr)\nimport qualified Data.ByteString.Char8 as B\n${CH}\n${imports}`, `data User = User { name :: String, password :: String, apiToken :: String }\n${body}`);

test('[HS-004.AC02] sensitive values are followed through conversions and field selectors to the logger', () => {
  const hits = (body, imports) => rulesOf({ 'T.hs': LOGGING_SRC(body, imports) }).findings.filter((f) => f.rule === 'hs-sensitive-logging');
  assert.equal(hits('l password = putStrLn password').length, 1, 'direct');
  assert.equal(hits('l password = putStrLn ("user logged in with " ++ password)').length, 1, 'concatenation');
  assert.equal(hits('l password = do\n  let msg = "pw=" ++ show password\n  putStrLn msg').length, 1, 'through a local binding and show');
  assert.equal(hits('l password = do\n  let t = T.pack password\n  let u = T.unpack t\n  putStrLn u').length, 1, 'through Text round trips');
  assert.equal(hits('l u = putStrLn (password u)').length, 1, 'through a record field selector');
  assert.equal(hits('l apiToken = hPutStrLn stderr apiToken').length, 1, 'to a handle: the MESSAGE argument is judged');
  const f = hits('l password = putStrLn password')[0];
  assert.equal(f.severity, 'high'); assert.equal(f.cwe, 'CWE-532'); assert.equal(f.evidence.channel, 'stdout');
});

test('[HS-004.AC02] values that are not sensitive, or never reach a logger, or are not the message, are not flagged', () => {
  const hits = (body) => rulesOf({ 'T.hs': LOGGING_SRC(body) }).findings.filter((f) => f.rule === 'hs-sensitive-logging');
  assert.equal(hits('l name = putStrLn name').length, 0, 'a user name is not a secret');
  assert.equal(hits('l password = pure (length password)').length, 0, 'never logged');
  assert.equal(hits('l password = putStrLn "login attempt"').length, 0, 'the secret is not in the message');
  assert.equal(hits('l pwHandle = hPutStrLn pwHandle "x"').length, 0, 'the handle argument is not the message');
});

test('[HS-004.AC02] hashing and redaction are judged in context, not treated as universal sanitization', () => {
  const hits = (body) => rulesOf({ 'T.hs': LOGGING_SRC(body, 'import qualified Crypto.KDF.BCrypt as BC') }).findings.filter((f) => f.rule === 'hs-sensitive-logging');
  // a redactor, a constant, or a password KDF removes the secret
  assert.equal(hits('redact :: String -> String\nredact _ = "[redacted]"\nl password = putStrLn (redact password)').length, 0);
  assert.equal(hits('l password = putStrLn (const "x" password)').length, 0);
  assert.equal(hits('l password = do\n  h <- BC.hashPassword 12 (B.pack password)\n  print h').length, 0, 'bcrypt output is not the password');
  // a fast hash of a LOW-entropy secret is still guessable: reported, but lower
  const weak = hits('l password = do\n  let d = S256.hash (B.pack password)\n  print d');
  assert.equal(weak.length, 1); assert.equal(weak[0].severity, 'low'); assert.equal(weak[0].evidence.hashed, true);
  // a hash of a HIGH-entropy token carries no usable secret
  assert.equal(hits('l apiToken = do\n  let d = S256.hash (B.pack apiToken)\n  print d').length, 0);
  // an unknown helper is not assumed to redact
  assert.equal(hits('scramble :: String -> String\nscramble = reverse\nl password = putStrLn (scramble password)').length, 1);
});

test('[HS-004.AC02] a clean sibling stays clean and an overwritten binding stops being sensitive', () => {
  const hits = (body) => rulesOf({ 'T.hs': LOGGING_SRC(body) }).findings.filter((f) => f.rule === 'hs-sensitive-logging');
  assert.equal(hits('l password name = do\n  putStrLn name\n  putStrLn password').length, 1, 'only the password line');
  assert.equal(hits('l password = do\n  let msg = password\n  let msg2 = "fixed"\n  putStrLn msg2').length, 0);
});

// ---- AC03 ------------------------------------------------------------------

test('[HS-004.AC03] unsafe IO and coercion are disclosed as boundaries with the exact modeled behavior and a low confidence', () => {
  const r = rulesOf({ 'T.hs': mod('T', 'import System.IO.Unsafe (unsafePerformIO)\nimport Unsafe.Coerce (unsafeCoerce)', 'g = unsafePerformIO (readFile "x")\nh = unsafeCoerce (1 :: Int) :: Bool') }).findings;
  assert.deepEqual(r.map((f) => f.rule), ['hs-unsafe-io-boundary', 'hs-unsafe-io-boundary']);
  for (const f of r) {
    assert.ok(f.confidence <= 0.5);
    assert.equal(f.severity, 'low');
    assert.ok(f.modelNote && f.modelNote.length > 20, 'the modeled behavior is stated');
    assert.notEqual(f.cwe, 'CWE-502');
  }
  assert.equal(r[0].modelNote, BOUNDARIES.unsafePerformIO);
  assert.match(r[0].modelNote, /no vulnerability class \(including CWE-502\) is claimed/);
});

test('[HS-004.AC03] CWE-502 is never claimed for read, readMaybe or generic decoders: there is no modelled executing deserializer', () => {
  const src = mod('T', 'import Text.Read (readMaybe)\nimport qualified Data.Aeson as A\nimport qualified Data.Yaml as Y\nimport Data.Binary (decode)\nimport Data.Serialize (decode)', `
a :: IO Int
a = do
  s <- getLine
  pure (read s)
b = do
  s <- getLine
  pure (readMaybe s :: Maybe Int)
c = do
  s <- getLine
  pure (A.decode s)
d = do
  s <- getLine
  pure (Y.decodeThrow s)
`);
  const r = rulesOf({ 'T.hs': src }).findings;
  assert.deepEqual(r.filter((f) => f.cwe === 'CWE-502'), []);
  assert.deepEqual(r, [], 'and nothing else fires either');
  assert.ok(!Object.values(RULES).some((x) => x.cwe === 'CWE-502'), 'no rule in the table claims CWE-502');
  const cli = scan({ 'src/D.hs': src });
  assert.deepEqual(cli.filter((f) => f.cwe === 'CWE-502'), [], 'including through the real scan');
});

test('[HS-004.AC03] a foreign import (FFI) is disclosed by the parser as an opaque boundary, not analysed and not called clean', async () => {
  const { parseHaskell } = await import('../../src/language/haskell-parser.js');
  const res = parseHaskell('module F where\nforeign import ccall unsafe "string.h strlen" c_strlen :: String -> IO Int\nf :: IO Int\nf = c_strlen "x"\n', { file: 'F.hs' });
  const ffi = (res.boundaries || res.gaps || []).filter((b) => /ffi|foreign/i.test(JSON.stringify(b)));
  assert.ok(ffi.length >= 1, 'the foreign boundary is recorded');
});

// ---- end to end ------------------------------------------------------------

test('[HS-004.AC01] the real scan reports the rules with language, family, original location and the source snippet', () => {
  const fs = scan({
    'src/Auth.hs': mod('Auth', CH + '\nimport System.Random (randomRIO)', 'store pw = hashWith SHA256 (B.pack pw)\nmkToken = do\n  token <- randomRIO (0, 999999 :: Int)\n  pure token\nlogIt password = putStrLn password'),
    'src/Clean.hs': mod('Clean', CH, 'checksum payload = S256.hash (B.pack payload)'),
  });
  const rules = fs.filter((f) => f.parser === 'HS-RULES');
  assert.deepEqual(rules.map((f) => f.family).sort(), ['password-hashing', 'sensitive-logging', 'weak-randomness']);
  assert.ok(rules.every((f) => f.language === 'haskell' && f.file === 'src/Auth.hs' && f.originalLocation.line === f.line));
  assert.equal(rules.find((f) => f.family === 'weak-randomness').snippet, 'token <- randomRIO (0, 999999 :: Int)');
  assert.equal(fs.filter((f) => f.file === 'src/Clean.hs').length, 0);
});
