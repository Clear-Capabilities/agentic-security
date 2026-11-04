// The password-hashing migration fixer (CWE-916, `hs-password-kdf-migrate`) and the rule it relies on.
//
// A fast password hash cannot be swapped for a KDF on its line: every stored hash was made by the old function, and a swap locks every user
// out. The fixer writes the migration out instead: the old function is kept under `<name>Legacy` for verification only, `<name>` becomes
// PBKDF2-HMAC-SHA256 with a tag in front of the hex, `<name>NeedsRehash` reads the tag, `<name>Verify` checks either form, and every
// `stored == <name> salt pw` in the file calls it. The rule then reports the kept weak hash at `info`, because every use of it is an equality
// beside a password KDF (the migration shape), decided from the IR and never from the name.
//
// Every verified case goes through the REAL scanner and `validateHaskellFix` with the compile gate requested. cryptonite is not installed
// where this runs, so `Crypto.KDF.PBKDF2` and `Crypto.Hash` are declared STUBS of the documented API shape (names, field names, the types
// the patch uses); the stub KDF derives its output from its inputs and is NOT a KDF. A type-check against a stub proves the patch is
// coherent with that API shape, not that it builds against the real package. The patched program is also RUN under GHC against the stub
// to check the dispatch: a legacy hash still verifies, a new hash verifies, a wrong password does not, and the tag decides re-hashing.
// Where GHC is absent those assertions are skipped LOUDLY and the compile gate is asserted to say it did not run.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runScan } from '../../src/runScan.js';
import { planHaskellFix, validateHaskellFix, haskellEffectiveCheck, TIERS, SUPPORTED_FIX_IDS } from '../../src/language/haskell-fix.js';
import { languageFixPreview } from '../../src/language/context.js';
import { mkTestTmp } from '../helpers/tmp.js';

// The stubs and the patch need only boot packages (base, bytestring, text). A host's GHC package environment file (written by `cabal install
// --lib`) can HIDE boot packages it does not list, which would turn every compile below into not-run for a reason that has nothing to do with the
// patch; this test file runs its own process, so it tells GHC to ignore that environment.
process.env.GHC_ENVIRONMENT = '-';
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const skipNoGhc = GHC ? false : 'GHC is not installed: the patched program could not be compiled or run (this is a skip, not a pass)';

async function scan(files) {
  const dir = mkTestTmp('hs-fix-kdf-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
}
const pwFindings = (fs) => fs.filter((x) => x.cwe === 'CWE-916' && /^src\/[A-Z]/.test(x.file));
const actionable = (fs) => pwFindings(fs).filter((x) => x.severity !== 'info');

// ── declared stubs of the documented API shape ───────────────────────────────────────────────────────────────────────────────
const STUB_PBKDF2 = `module Crypto.KDF.PBKDF2 (Parameters(..), fastPBKDF2_SHA256) where
import qualified Data.ByteString as B
-- documented: data Parameters = Parameters { iterCounts :: Int, outputLength :: Int }
--             fastPBKDF2_SHA256 :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray out) => Parameters -> password -> salt -> out
-- This stub fixes the byte-array types to strict ByteString and derives the output from its inputs; it is NOT a KDF (the test checks shape and dispatch).
data Parameters = Parameters { iterCounts :: Int, outputLength :: Int }
fastPBKDF2_SHA256 :: Parameters -> B.ByteString -> B.ByteString -> B.ByteString
fastPBKDF2_SHA256 p pw salt = B.pack (take (outputLength p) (cycle (B.unpack (B.append pw salt) ++ [fromIntegral (iterCounts p \`mod\` 251)])))
`;
const STUB_HASH = `module Crypto.Hash (Digest, SHA256(..), hash) where
import qualified Data.ByteString as B
-- documented subset: hash :: (ByteArrayAccess ba, HashAlgorithm a) => ba -> Digest a; show of a Digest is its hex. The stub fixes ba to ByteString.
data SHA256 = SHA256
newtype Digest a = Digest B.ByteString
instance Show (Digest a) where
  show (Digest b) = concatMap (\\w -> [hexDigit (w \`div\` 16), hexDigit (w \`mod\` 16)]) (B.unpack b)
    where hexDigit d = "0123456789abcdef" !! fromIntegral d
hash :: B.ByteString -> Digest a
hash = Digest
`;
const STUBS = { 'Crypto/KDF/PBKDF2.hs': STUB_PBKDF2, 'Crypto/Hash.hs': STUB_HASH };

const AUTH_STRING = `module Auth (hashPassword, register, login) where

import Crypto.Hash (Digest, SHA256, hash)
import qualified Data.ByteString.Char8 as BC
import qualified Data.Text as T

hashPassword :: String -> String -> String
hashPassword salt password = show (hash (BC.pack (salt ++ password)) :: Digest SHA256)

register :: String -> String -> (String, String)
register salt password = (salt, hashPassword salt password)

login :: (String, String) -> String -> Bool
login (salt, stored) password = stored == hashPassword salt password

greeting :: T.Text
greeting = T.pack "hello"
`;
const AUTH_TEXT = `module Auth where

import Crypto.Hash (Digest, SHA256, hash)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

hashPassword :: Text -> Text -> Text
hashPassword salt password = T.pack (show (hash (TE.encodeUtf8 (T.append salt password)) :: Digest SHA256))

checkLogin :: Text -> Text -> Text -> Bool
checkLogin stored salt password = (hashPassword salt password) == stored
`;
const AUTH_BYTES = `module Auth where

import Crypto.Hash (Digest, SHA256, hash)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC

hashPassword :: BS.ByteString -> BS.ByteString -> BS.ByteString
hashPassword salt pw = BC.pack (show (hash (BS.append salt pw) :: Digest SHA256))

verifyUser :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Bool
verifyUser stored salt pw = stored == hashPassword salt pw
`;

// ── the SHA package form (gitit's shape): no cryptonite module, the hash is Data.Digest.Pure.SHA's, the bytes of a String come from utf8-string ──
// Stubs of the documented API shape (SHA 1.6.4.4; utf8-string 1.0.2): the stub digest is derived from its inputs and is NOT a hash.
const STUB_SHA = `module Data.Digest.Pure.SHA (Digest, SHA256State, SHA512State, sha512, hmacSha256, showDigest, bytestringDigest) where
import qualified Data.ByteString.Lazy as BL
-- documented: hmacSha256 :: ByteString -> ByteString -> Digest SHA256State; sha512 :: ByteString -> Digest SHA512State;
--             bytestringDigest :: Digest t -> ByteString; showDigest :: Digest t -> String   (lazy ByteStrings throughout)
data SHA256State
data SHA512State
newtype Digest t = Digest BL.ByteString
mix :: Int -> BL.ByteString -> BL.ByteString
mix n b = BL.pack (take n (zipWith (+) [1 ..] (cycle (if BL.null b then [0] else BL.unpack b))))
sha512 :: BL.ByteString -> Digest SHA512State
sha512 = Digest . mix 64
hmacSha256 :: BL.ByteString -> BL.ByteString -> Digest SHA256State
hmacSha256 key msg = Digest (mix 32 (BL.append msg key))
bytestringDigest :: Digest t -> BL.ByteString
bytestringDigest (Digest b) = b
showDigest :: Digest t -> String
showDigest (Digest b) = concatMap (\\w -> [hexDigit (w \`div\` 16), hexDigit (w \`mod\` 16)]) (BL.unpack b)
  where hexDigit d = "0123456789abcdef" !! fromIntegral d
`;
const STUB_UTF8 = `module Data.ByteString.Lazy.UTF8 (fromString) where
import qualified Data.ByteString.Lazy as BL
-- documented: fromString :: String -> ByteString (UTF-8). The stub maps code points below 256 only.
fromString :: String -> BL.ByteString
fromString = BL.pack . map (fromIntegral . fromEnum)
`;
const STUBS_SHA = { 'Data/Digest/Pure/SHA.hs': STUB_SHA, 'Data/ByteString/Lazy/UTF8.hs': STUB_UTF8 };
const AUTH_SHA_STRING = `module Auth where

import Data.Digest.Pure.SHA (sha512, showDigest)
import qualified Data.ByteString.Lazy.UTF8 as L (fromString)

hashPassword :: String -> String -> String
hashPassword salt pass = showDigest $ sha512 $ L.fromString $ salt ++ pass

register :: String -> String -> (String, String)
register salt pass = (salt, hashPassword salt pass)

login :: (String, String) -> String -> Bool
login (salt, stored) pass = stored == hashPassword salt pass
`;
const AUTH_SHA_TEXT = `module Auth where

import Data.Digest.Pure.SHA (sha512, showDigest)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE

hashPassword :: Text -> Text -> Text
hashPassword salt password = T.pack (showDigest (sha512 (TLE.encodeUtf8 (TL.fromStrict (T.append salt password)))))

checkLogin :: Text -> Text -> Text -> Bool
checkLogin stored salt password = (hashPassword salt password) == stored
`;
const AUTH_SHA_BYTES = `module Auth where

import Data.Digest.Pure.SHA (sha512, showDigest)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL

hashPassword :: BS.ByteString -> BS.ByteString -> BS.ByteString
hashPassword salt pw = BC.pack (showDigest (sha512 (BL.fromStrict (BS.append salt pw))))

verifyUser :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Bool
verifyUser stored salt pw = stored == hashPassword salt pw
`;

const MAIN_RUN = `module Main (main) where
import Auth
main :: IO ()
main = do
  let salt = "s4lt"
      legacyStored = hashPasswordLegacy salt "hunter2"
      newStored = hashPassword salt "hunter2"
  print (take 21 newStored == "pbkdf2-sha256$600000$", legacyStored /= newStored)
  print (hashPasswordNeedsRehash legacyStored, hashPasswordNeedsRehash newStored)
  print (hashPasswordVerify legacyStored salt "hunter2", hashPasswordVerify newStored salt "hunter2")
  print (hashPasswordVerify legacyStored salt "wrong", hashPasswordVerify newStored salt "wrong", hashPasswordVerify newStored "other" "hunter2")
  print (login (register salt "hunter2") "hunter2", login (register salt "hunter2") "nope", hashPasswordNeedsRehash (snd (register salt "hunter2")))
`;

function runGhc(files, mainFile) {
  const dir = mkTestTmp('hs-kdf-run-');
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return spawnSync('runghc', ['-isrc', '-i.', mainFile], { cwd: dir, encoding: 'utf8', timeout: 180000 });
}
// Compiled, not interpreted: the written-out PBKDF2 iterates 600000 times, which the interpreter would take minutes over.
function runGhcCompiled(files, mainFile, extraArgs = []) {
  const dir = mkTestTmp('hs-kdf-bin-');
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  const build = spawnSync('ghc', ['-O0', '-isrc', '-i.', '-outputdir', 'o', '-o', 'main', ...extraArgs, mainFile], { cwd: dir, encoding: 'utf8', timeout: 180000 });
  if (build.status !== 0) return build;
  return spawnSync(join(dir, 'main'), [], { cwd: dir, encoding: 'utf8', timeout: 180000 });
}
// The real SHA package, when the host's GHC can see it (`ghc-pkg latest SHA`): only then is the construction run against the RFC vectors.
const SHA_PKG = GHC && !spawnSync('ghc-pkg', ['latest', 'SHA'], { encoding: 'utf8' }).error && spawnSync('ghc-pkg', ['latest', 'SHA'], { encoding: 'utf8' }).status === 0;
const skipNoShaPkg = SHA_PKG ? false : 'the SHA package is not installed for the GHC on PATH: the written-out PBKDF2 could not be run against the RFC 7914 vectors (this is a skip, not a pass)';

// ═══ 1. the String form, verified by the real rescan, the effective check and a compile against the stubs ═══════════════════════
test('migration (String): the old function is kept as the legacy verifier, the KDF form is tagged, the comparison calls the verify helper; rescan, effective check and compile pass; the export list gains the helpers', async () => {
  const files = { 'src/Auth.hs': AUTH_STRING, ...STUBS };
  const fs = await scan(files);
  const f = actionable(fs)[0];
  assert.ok(f, JSON.stringify(fs.map((x) => [x.cwe, x.file, x.line, x.severity])));
  const v = await validateHaskellFix(f, { files, compile: GHC });
  assert.equal(v.status, 'verified', JSON.stringify({ reason: v.reason, gates: v.gates }));
  assert.equal(v.plan.ruleId, 'hs-password-kdf-migrate');
  assert.equal(v.label, 'MITIGATION');
  assert.equal(v.tier, TIERS.edit);
  assert.equal(v.gates.rescan.originalGone, true);
  assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
  if (GHC) assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [true, true], v.gates.compile.detail);
  else assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [false, null]);
  const after = v.plan.after;
  assert.match(after, /^hashPasswordLegacy salt password = show \(hash \(BC\.pack \(salt \+\+ password\)\) :: Digest SHA256\)$/m, 'the original body is kept verbatim under the legacy name');
  assert.match(after, /^hashPassword salt password = hashPasswordTag <> hashPasswordHex \(AgenticPBKDF2\.fastPBKDF2_SHA256 \(AgenticPBKDF2\.Parameters \{ AgenticPBKDF2\.iterCounts = 600000, AgenticPBKDF2\.outputLength = 32 \}\) \(AgenticTE\.encodeUtf8 \(AgenticT\.pack password\)\) \(AgenticTE\.encodeUtf8 \(AgenticT\.pack salt\)\)\)$/m);
  assert.match(after, /^hashPasswordTag = "pbkdf2-sha256\$600000\$"$/m);
  assert.match(after, /^login \(salt, stored\) password = hashPasswordVerify stored salt password$/m, 'the comparison now calls the verify helper');
  assert.match(after, /^register salt password = \(salt, hashPassword salt password\)$/m, 'a store site keeps hashing with the (now KDF) function');
  assert.match(after, /^module Auth \(hashPassword, hashPasswordLegacy, hashPasswordVerify, hashPasswordNeedsRehash, register, login\) where$/m, 'the export list gains the helpers');
  assert.ok(v.consequences.some((c) => /no user is locked out/.test(c)) && v.consequences.some((c) => /declared default/.test(c)));
  // the kept weak hash is reported at `info` (the migration shape), so nothing actionable remains and the reviewer still sees it
  const again = await scan({ ...files, 'src/Auth.hs': after });
  assert.equal(actionable(again).length, 0, JSON.stringify(pwFindings(again).map((x) => [x.line, x.severity])));
  const kept = pwFindings(again).find((x) => x.severity === 'info');
  assert.ok(kept && /used only to verify hashes made before a migration/.test(kept.description), kept && kept.description);
});

test('migration (String): the patched program RUNS under GHC against the stub: a legacy hash still verifies, a new one verifies, a wrong password does not, and the tag decides re-hashing', { skip: skipNoGhc }, () => {
  const files = { 'src/Auth.hs': AUTH_STRING.replace('module Auth (hashPassword, register, login) where', 'module Auth where'), ...STUBS };
  const plan = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 8 }, files);
  assert.equal(plan.ok, true, plan.reason);
  const r = runGhc({ ...files, 'src/Auth.hs': plan.after, 'Main.hs': MAIN_RUN }, 'Main.hs');
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.trim().split('\n'), ['(True,True)', '(True,False)', '(True,True)', '(False,False,False)', '(True,False,False)']);
});

// ═══ 2. the Text and ByteString forms ═════════════════════════════════════════════════════════════════════════════════════════
for (const [name, src, cmpLine] of [['Text', AUTH_TEXT, /^checkLogin stored salt password = hashPasswordVerify stored salt password$/m], ['ByteString', AUTH_BYTES, /^verifyUser stored salt pw = hashPasswordVerify stored salt pw$/m]]) {
  test(`migration (${name}): the same migration with the bytes of that type; verified by the real rescan and the compile gate`, async () => {
    const files = { 'src/Auth.hs': src, ...STUBS };
    const f = actionable(await scan(files))[0];
    assert.ok(f);
    const v = await validateHaskellFix(f, { files, compile: GHC });
    assert.equal(v.status, 'verified', JSON.stringify({ reason: v.reason, gates: v.gates }));
    assert.equal(v.plan.behavior.type, name);
    assert.match(v.plan.after, cmpLine);
    if (GHC) assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [true, true], v.gates.compile.detail);
  });
}

// ═══ 2b. the SHA package form: the derivation is written out over the package's HMAC ═════════════════════════════════════════
test('migration over the SHA package (String, gitit\'s shape): PBKDF2 is written out over hmacSha256, the bytes come from utf8-string; rescan, effective check and compile pass, and the kept weak hash is reported at info', async () => {
  const files = { 'src/Auth.hs': AUTH_SHA_STRING, ...STUBS_SHA };
  const fs = await scan(files);
  const f = actionable(fs)[0];
  assert.ok(f, JSON.stringify(fs.map((x) => [x.cwe, x.file, x.line, x.severity])));
  assert.equal(f.line, 7);
  const v = await validateHaskellFix(f, { files, compile: GHC });
  assert.equal(v.status, 'verified', JSON.stringify({ reason: v.reason, gates: v.gates }));
  assert.equal(v.plan.ruleId, 'hs-password-kdf-migrate');
  assert.equal(v.label, 'MITIGATION');
  assert.equal(v.plan.behavior.backend, 'sha');
  assert.equal(v.gates.rescan.originalGone, true);
  assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
  if (GHC) assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [true, true], v.gates.compile.detail);
  const after = v.plan.after;
  assert.match(after, /^hashPasswordLegacy salt pass = showDigest \$ sha512 \$ L\.fromString \$ salt \+\+ pass$/m, 'the original body is kept verbatim under the legacy name');
  assert.match(after, /^hashPassword salt pass = hashPasswordTag <> hashPasswordHex \(hashPasswordPbkdf2 \(AgenticUTF8\.fromString pass\) \(AgenticUTF8\.fromString salt\)\)$/m);
  assert.match(after, /^hashPasswordPbkdf2 password salt = AgenticList\.foldl' xorBytes u1 \(take \(600000 - 1\) \(tail \(iterate prf u1\)\)\)$/m);
  assert.match(after, /^    prf = AgenticSHA\.bytestringDigest \. AgenticSHA\.hmacSha256 password$/m);
  assert.match(after, /^    u1 = prf \(AgenticBL\.append salt \(AgenticBL\.pack \[0, 0, 0, 1\]\)\)$/m);
  assert.match(after, /^import qualified Data\.Digest\.Pure\.SHA as AgenticSHA$/m);
  assert.match(after, /^import qualified Data\.ByteString\.Lazy\.UTF8 as AgenticUTF8$/m);
  assert.doesNotMatch(after, /Crypto\.KDF|AgenticPBKDF2/, 'no cryptonite name is introduced');
  assert.match(after, /^login \(salt, stored\) pass = hashPasswordVerify stored salt pass$/m);
  assert.ok(v.consequences.some((c) => /Requires the SHA package .* utf8-string/.test(c)), JSON.stringify(v.consequences));
  assert.ok(v.consequences.some((c) => /seconds of CPU per attempt, not tenths/.test(c)), 'the cost of the pure-Haskell HMAC is stated');
  const again = await scan({ ...files, 'src/Auth.hs': after });
  assert.equal(actionable(again).length, 0, JSON.stringify(pwFindings(again).map((x) => [x.line, x.severity, x.description])));
  const kept = pwFindings(again).find((x) => x.severity === 'info');
  assert.ok(kept && /used only to verify hashes made before a migration/.test(kept.description), kept && kept.description);
  // the written-out derivation is a KDF by its structure, not by its name: the same file with the xor fold removed is no migration
  const noFold = after.replace(/^hashPasswordPbkdf2 password salt = .*$/m, 'hashPasswordPbkdf2 password salt = last (take 600000 (iterate prf u1))').replace(/^    xorBytes a b = .*\n/m, '');
  const notKdf = await scan({ ...files, 'src/Auth.hs': noFold });
  assert.ok(actionable(notKdf).some((x) => x.line > 7), `an iterated HMAC with no xor fold is not the construction: the kept hash is the full finding (${JSON.stringify(pwFindings(notKdf).map((x) => [x.line, x.severity]))})`);
});

test('migration over the SHA package: the patched program RUNS (compiled) against the stubs: a legacy hash still verifies, a new one verifies, a wrong password does not, and the tag decides re-hashing', { skip: skipNoGhc }, () => {
  const files = { 'src/Auth.hs': AUTH_SHA_STRING, ...STUBS_SHA };
  const plan = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 7 }, files);
  assert.equal(plan.ok, true, plan.reason);
  const r = runGhcCompiled({ ...files, 'src/Auth.hs': plan.after, 'Main.hs': MAIN_RUN }, 'Main.hs');
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.trim().split('\n'), ['(True,True)', '(True,False)', '(True,True)', '(False,False,False)', '(True,False,False)']);
});

// The construction itself, against the real package: the generated definition is compiled as written, with ONLY its iteration-count literal
// replaced by the vector's count (c = 1 and c = 80000), and must produce the first 32 bytes of the RFC 7914 section 11 PBKDF2-HMAC-SHA-256 vectors.
const RFC7914 = [
  ['passwd', 'salt', 1, '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc'],
  ['Password', 'NaCl', 80000, '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56'],
];
test('the written-out PBKDF2 matches the RFC 7914 vectors against the real SHA package (the generated definition, count literal replaced)', { skip: skipNoShaPkg || skipNoGhc }, () => {
  const plan = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 10 }, { 'src/Auth.hs': AUTH_SHA_TEXT });
  assert.equal(plan.ok, true, plan.reason);
  const ls = plan.after.split('\n');
  const start = ls.findIndex((l) => /^hashPasswordPbkdf2 ::/.test(l));
  assert.ok(start > 0);
  const def = ls.slice(start, start + 6);
  assert.match(def[1], /take \(600000 - 1\)/);
  const mods = RFC7914.map(([, , c], i) => `module V${i} (hashPasswordPbkdf2) where\nimport qualified Data.Digest.Pure.SHA as AgenticSHA\nimport qualified Data.ByteString.Lazy as AgenticBL\nimport qualified Data.Bits as AgenticBits\nimport qualified Data.List as AgenticList\n${def.join('\n').replace('take (600000 - 1)', `take (${c} - 1)`)}\n`);
  const main = `module Main (main) where\nimport qualified Data.ByteString.Lazy.Char8 as BLC\nimport qualified Data.ByteString.Lazy as BL\nimport qualified V0\nimport qualified V1\nhex :: BL.ByteString -> String\nhex = BL.foldr (\\w acc -> hexDigit (w \`div\` 16) : hexDigit (w \`mod\` 16) : acc) "" where hexDigit d = "0123456789abcdef" !! fromIntegral d\nmain :: IO ()\nmain = do\n  putStrLn (hex (V0.hashPasswordPbkdf2 (BLC.pack "${RFC7914[0][0]}") (BLC.pack "${RFC7914[0][1]}")))\n  putStrLn (hex (V1.hashPasswordPbkdf2 (BLC.pack "${RFC7914[1][0]}") (BLC.pack "${RFC7914[1][1]}")))\n`;
  const r = runGhcCompiled({ 'V0.hs': mods[0], 'V1.hs': mods[1], 'Main.hs': main }, 'Main.hs', ['-package', 'SHA']);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.trim().split('\n'), RFC7914.map((v) => v[3]));
});

for (const [name, src, line, cmpLine] of [['Text', AUTH_SHA_TEXT, 10, /^checkLogin stored salt password = hashPasswordVerify stored salt password$/m], ['ByteString', AUTH_SHA_BYTES, 9, /^verifyUser stored salt pw = hashPasswordVerify stored salt pw$/m]]) {
  test(`migration over the SHA package (${name}): the bytes of that type; verified by the real rescan and the compile gate against the stub`, async () => {
    const files = { 'src/Auth.hs': src, 'Data/Digest/Pure/SHA.hs': STUB_SHA };
    const f = actionable(await scan(files))[0];
    assert.ok(f); assert.equal(f.line, line);
    const v = await validateHaskellFix(f, { files, compile: GHC });
    assert.equal(v.status, 'verified', JSON.stringify({ reason: v.reason, gates: v.gates }));
    assert.deepEqual([v.plan.behavior.type, v.plan.behavior.backend], [name, 'sha']);
    assert.match(v.plan.after, cmpLine);
    if (GHC) assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [true, true], v.gates.compile.detail);
  });
}

// ═══ 3. the effective check is not the rescan ═════════════════════════════════════════════════════════════════════════════════
test('effective check: a verify helper that checks only the new form, or a legacy function whose body was changed, fails it although the finding is gone', () => {
  const files = { 'src/Auth.hs': AUTH_STRING, ...STUBS };
  const plan = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 8 }, files);
  assert.equal(plan.ok, true, plan.reason);
  assert.equal(haskellEffectiveCheck(plan, { 'src/Auth.hs': plan.after }).ok, true);
  const onlyNew = plan.after.replace(/^hashPasswordVerify stored salt password = .*$/m, 'hashPasswordVerify stored salt password = stored == hashPassword salt password');
  const e1 = haskellEffectiveCheck(plan, { 'src/Auth.hs': onlyNew });
  assert.equal(e1.ok, false); assert.match(e1.detail, /does not check both forms/);
  const edited = plan.after.replace(/^hashPasswordLegacy salt password = .*$/m, 'hashPasswordLegacy salt password = salt ++ password');
  const e2 = haskellEffectiveCheck(plan, { 'src/Auth.hs': edited });
  assert.equal(e2.ok, false); assert.match(e2.detail, /not the original definition kept verbatim/);
  const stillCompares = plan.after.replace(/^login \(salt, stored\) password = .*$/m, 'login (salt, stored) password = stored == hashPassword salt password');
  const e3 = haskellEffectiveCheck(plan, { 'src/Auth.hs': stillCompares });
  assert.equal(e3.ok, false); assert.match(e3.detail, /1 comparison\(s\) remain/);
});

// ═══ 4. refusals, each naming the decision ════════════════════════════════════════════════════════════════════════════════════
test('refusals: no KDF package imported, a one-parameter hash, a comparison in another file, a taken name, another type, an impure body, a lazy ByteString', async () => {
  const at = (src, line = 8) => planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line }, { 'src/Auth.hs': src, ...STUBS });
  const refused = (r, why) => { assert.equal(r.ok, false, why); assert.equal(r.tier, TIERS.guidance); assert.match(r.reason, /The one shape rewritten is a migration/); assert.match(r.decision, /which KDF and library/); };
  refused(at(AUTH_STRING.replace('import Crypto.Hash (Digest, SHA256, hash)', 'import Data.Digest.Pure.MD5 (md5)').replace(/^hashPassword salt password = .*$/m, 'hashPassword salt password = show (md5 (BC.pack (salt ++ password)))')), 'neither a cryptonite module nor the SHA package: no declared package offers a KDF or an HMAC to build one on');
  // the SHA package's shape needs a declared package for the bytes of a String: with no utf8-string and no text module imported, refused
  refused(at(AUTH_SHA_STRING.replace('import qualified Data.ByteString.Lazy.UTF8 as L (fromString)', 'import qualified Data.ByteString.Lazy.Char8 as L (pack)').replace('L.fromString', 'L.pack'), 7), 'SHA package, but no declared package turns a String into UTF-8 bytes');
  refused(at(AUTH_STRING.replace('hashPassword :: String -> String -> String', 'hashPassword :: String -> String').replace(/^hashPassword salt password = /m, 'hashPassword password = ').replace('salt ++ password', 'password').replace(/hashPassword salt password/g, 'hashPassword password')), 'no salt parameter: a pure function cannot add one');
  refused(at(AUTH_STRING.replace(/String -> String -> String/, 'Int -> String -> String').replace(/^hashPassword salt password = .*$/m, 'hashPassword salt password = show salt ++ password')), 'a parameter of another type');
  refused(at(AUTH_STRING.replace(/^hashPassword salt password = .*$/m, 'hashPassword salt password = unsafePerformIO (pure (salt ++ password))')), 'not a pure one-line definition');
  refused(at(AUTH_STRING.replace('import qualified Data.Text as T', 'import qualified Data.Text as T\nhashPasswordVerify :: Int\nhashPasswordVerify = 1')), 'a helper name is taken');
  refused(at(AUTH_BYTES.replace('import qualified Data.ByteString as BS', 'import qualified Data.ByteString.Lazy as BS')), 'a lazy ByteString is not what the KDF takes');
  // a comparison in ANOTHER file would be left comparing the old form against the new one: refused, the lockout is the harm
  const other = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 8 }, { 'src/Auth.hs': AUTH_STRING, 'src/Login.hs': 'module Login where\nimport Auth\nok :: String -> String -> String -> Bool\nok stored salt pw = stored == hashPassword salt pw\n', ...STUBS });
  refused(other, 'a comparison in another file');
  // the same other file only HASHING (a store site) is fine: new passwords get the KDF there too
  const storeElsewhere = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 8 }, { 'src/Auth.hs': AUTH_STRING, 'src/Signup.hs': 'module Signup where\nimport Auth\nmk :: String -> String -> String\nmk salt pw = hashPassword salt pw\n', ...STUBS });
  assert.equal(storeElsewhere.ok, true, storeElsewhere.reason);
  assert.ok(storeElsewhere.consequences.some((c) => /re-hashes it/.test(c)));
  // the preview path reports the same refusal with the class reason
  const pv = await languageFixPreview({ cwe: 'CWE-916', rule: 'hs-fast-password-hash', file: 'src/Auth.hs', line: 8, vuln: 'Password hashed with a fast general-purpose hash' }, { 'src/Auth.hs': AUTH_STRING.replace('import Crypto.Hash (Digest, SHA256, hash)', 'import Data.Digest.Pure.MD5 (md5)').replace(/^hashPassword salt password = .*$/m, 'hashPassword salt password = show (md5 (BC.pack (salt ++ password)))') });
  assert.equal(pv.ok, false); assert.equal(pv.proposal, 'model-assisted'); assert.match(String(pv.reason), /KDF/);
});

// ═══ 5. the rule: the migration shape is decided from the IR, both ways ═══════════════════════════════════════════════════════
const MIGRATED = `module Auth where

import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.Hash (Digest, SHA256, hash)
import qualified Data.ByteString.Char8 as BC
import Data.List (isPrefixOf)

oldHash :: String -> String -> String
oldHash salt password = show (hash (BC.pack (salt ++ password)) :: Digest SHA256)

newHash :: String -> String -> String
newHash salt password = "pbkdf2$" ++ BC.unpack (PBKDF2.fastPBKDF2_SHA256 (PBKDF2.Parameters 600000 32) (BC.pack password) (BC.pack salt))

check :: String -> String -> String -> Bool
check stored salt password = if "pbkdf2$" \`isPrefixOf\` stored then stored == newHash salt password else stored == oldHash salt password
`;
test('rule: a fast hash whose every use is an equality beside a password KDF is the migration shape (info); the same function also STORING a hash, or compared beside no KDF, is the full finding', async () => {
  const migrated = pwFindings(await scan({ 'src/Auth.hs': MIGRATED, ...STUBS }));
  assert.equal(migrated.filter((x) => x.severity !== 'info').length, 0, JSON.stringify(migrated.map((x) => [x.line, x.severity, x.description])));
  assert.ok(migrated.some((x) => x.severity === 'info' && x.line === 9 && x.evidence && x.evidence.legacyVerifier === true), 'the kept weak hash is still reported, at info, with the reason');
  // the old function is also used to store a new hash: not a migration, the full finding
  const stores = pwFindings(await scan({ 'src/Auth.hs': `${MIGRATED}\nregister :: String -> String -> String\nregister salt password = oldHash salt password\n`, ...STUBS }));
  assert.ok(stores.some((x) => x.severity === 'high' && x.line === 9), JSON.stringify(stores.map((x) => [x.line, x.severity])));
  // compared, but beside no KDF: a weak verifier with nothing to migrate to, the full finding
  const noKdf = pwFindings(await scan({ 'src/Auth.hs': MIGRATED.replace(/^check stored salt password = .*$/m, 'check stored salt password = stored == oldHash salt password').replace(/^newHash.*\n.*\n/m, ''), ...STUBS }));
  assert.ok(noKdf.some((x) => x.severity === 'high' && x.line === 9), JSON.stringify(noKdf.map((x) => [x.line, x.severity])));
});

test('the fixer set names the migration fixer', () => {
  assert.ok(SUPPORTED_FIX_IDS.includes('hs-password-kdf-migrate'));
});
