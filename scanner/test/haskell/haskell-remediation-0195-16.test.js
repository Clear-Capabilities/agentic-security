// The 0.195.16 fixer work besides entropy, Text commands and path containment (each in its own file):
//   hs-tls-validate for HsOpenSSL (IHP's OpenAI client: `contextSetVerificationMode context SSL.VerifyNone` in a do block),
//   hs-log-redact no longer rewrites inside a string literal (the guide's captured example showed `" "[REDACTED]"="`),
//   hs-xml-no-entity-substitution (`withSubstDTDEntities yes` -> `no`),
//   hs-pbkdf2-low-iterations routed to the password-KDF migration (the old count is kept for verification, new hashes use 600000).
// Patches are type-checked under GHC against stubs of the documented HsOpenSSL and hxt names (versions in the fixer's comments).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { planHaskellFix, validateHaskellFix } from '../../src/language/haskell-fix.js';

process.env.GHC_ENVIRONMENT = '-';
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const STUB_SSL = `module OpenSSL.Session (SSLContext, VerificationMode(..), contextSetVerificationMode, contextSetDefaultVerifyPaths, context) where
data SSLContext = SSLContext
-- HsOpenSSL 0.11.7.11: VerifyPeer { vpFailIfNoPeerCert :: Bool, vpClientOnce :: Bool, vpCallback :: Maybe (Bool -> X509StoreCtx -> IO Bool) }
data X509StoreCtx = X509StoreCtx
data VerificationMode = VerifyNone | VerifyPeer { vpFailIfNoPeerCert :: Bool, vpClientOnce :: Bool, vpCallback :: Maybe (Bool -> X509StoreCtx -> IO Bool) }
contextSetVerificationMode :: SSLContext -> VerificationMode -> IO ()
contextSetVerificationMode _ _ = pure ()
contextSetDefaultVerifyPaths :: SSLContext -> IO ()
contextSetDefaultVerifyPaths _ = pure ()
context :: IO SSLContext
context = pure SSLContext
`;
const STUB_HXT = `module Text.XML.HXT.Core (SysConfig, withSubstDTDEntities, yes, no, readString) where
type SysConfig = Bool -> Bool
withSubstDTDEntities :: Bool -> SysConfig
withSubstDTDEntities b _ = b
yes, no :: Bool
yes = True
no = False
readString :: [SysConfig] -> String -> IO ()
readString _ _ = pure ()
`;

async function checked(finding, files) {
  const plan = planHaskellFix(finding, files);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  const v = await validateHaskellFix(finding, { files, compile: true });
  assert.equal(v.gates.syntax.ok, true, JSON.stringify(v.gates.syntax));
  assert.equal(v.gates.effective.ok, true, JSON.stringify(v.gates.effective));
  if (GHC) { assert.equal(v.gates.compile.ran, true, 'ghc ran'); assert.equal(v.gates.compile.ok, true, JSON.stringify(v.gates.compile)); }
  return plan;
}

test('HsOpenSSL: VerifyNone in a do block becomes default CA paths plus VerifyPeer, qualified and unqualified', async () => {
  const qualified = {
    'Client.hs': `module Client (setup) where
import qualified OpenSSL.Session as SSL

setup :: IO ()
setup = do
    ctx <- SSL.context
    modify (\\context -> do
            SSL.contextSetVerificationMode context SSL.VerifyNone
            pure context
        ) ctx
  where modify f c = f c >> pure ()
`,
    'OpenSSL/Session.hs': STUB_SSL,
  };
  const f = { cwe: 'CWE-295', rule: 'hs-tls-validation-disabled', file: 'Client.hs', line: 8, severity: 'high', vuln: 'TLS certificate validation is disabled' };
  const plan = await checked(f, qualified);
  assert.equal(plan.ruleId, 'hs-tls-validate'); assert.equal(plan.label, 'MITIGATION');
  assert.match(plan.after, /\n            SSL\.contextSetDefaultVerifyPaths context\n            SSL\.contextSetVerificationMode context \(SSL\.VerifyPeer True True Nothing\)\n/);
  assert.ok(plan.consequences.some((c) => /host name is NOT verified/.test(c)));
  const unqualified = { 'C.hs': 'module C (setup) where\nimport OpenSSL.Session (context, contextSetVerificationMode, VerificationMode(..))\n\nsetup :: IO ()\nsetup = do\n  ctx <- context\n  contextSetVerificationMode ctx VerifyNone\n', 'OpenSSL/Session.hs': STUB_SSL };
  const plan2 = await checked({ ...f, file: 'C.hs', line: 7 }, unqualified);
  assert.match(plan2.after, /^import OpenSSL\.Session \(context, contextSetVerificationMode, VerificationMode\(\.\.\), contextSetDefaultVerifyPaths\)$/m);
  assert.match(plan2.after, /\n  contextSetDefaultVerifyPaths ctx\n  contextSetVerificationMode ctx \(VerifyPeer True True Nothing\)\n/);
  // not a statement (an argument), so the second line cannot be inserted: refused
  const expr = { 'E.hs': 'module E (setup) where\nimport qualified OpenSSL.Session as SSL\n\nsetup :: SSL.SSLContext -> IO ()\nsetup ctx = run $\n    SSL.contextSetVerificationMode ctx SSL.VerifyNone\n  where run = id\n' };
  assert.equal(planHaskellFix({ ...f, file: 'E.hs', line: 6 }, expr).ok, false);
  // two client functions in one file (the real IHP shape): both sites are rewritten in one patch, because the rule reports the class once
  // per file and a second site left alone would keep the finding
  const two = { 'Two.hs': `module Two (a, b) where
import qualified OpenSSL.Session as SSL

a :: IO ()
a = do
    ctx <- SSL.context
    SSL.contextSetVerificationMode ctx SSL.VerifyNone

b :: IO ()
b = do
    c <- SSL.context
    SSL.contextSetVerificationMode c SSL.VerifyNone
`, 'OpenSSL/Session.hs': STUB_SSL };
  const plan3 = await checked({ ...f, file: 'Two.hs', line: 7 }, two);
  assert.equal((plan3.after.match(/VerifyPeer True True Nothing/g) || []).length, 2);
  assert.equal((plan3.after.match(/VerifyNone/g) || []).length, 0);
  assert.match(plan3.explanation, /2 sites/);
});

test('log redaction never rewrites inside a string literal', () => {
  const files = { 'L.hs': 'module L where\nlogLogin :: String -> String -> IO ()\nlogLogin user password = putStrLn ("login " ++ user ++ " password=" ++ password)\n' };
  const plan = planHaskellFix({ cwe: 'CWE-532', rule: 'hs-sensitive-logging', file: 'L.hs', line: 3 }, files);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  assert.match(plan.after, /logLogin user password = putStrLn \("login " \+\+ user \+\+ " password=" \+\+ "\[REDACTED\]"\)/);
  assert.match(plan.explanation, /Replaced 1 sensitive/);
});

test('hxt: withSubstDTDEntities yes becomes no (FULL); True becomes False; an explicit import list gains `no`', async () => {
  const files = {
    'X.hs': `module X (parse) where
import Text.XML.HXT.Core (withSubstDTDEntities, yes, readString)

parse :: String -> IO ()
parse doc = readString [withSubstDTDEntities yes] doc
`,
    'Text/XML/HXT/Core.hs': STUB_HXT,
  };
  const f = { cwe: 'CWE-611', rule: 'hs-xml-entity-substitution', file: 'X.hs', line: 5, severity: 'medium', vuln: 'XML parser configured to substitute DTD entities' };
  const plan = await checked(f, files);
  assert.equal(plan.ruleId, 'hs-xml-no-entity-substitution'); assert.equal(plan.label, 'FULL');
  assert.match(plan.after, /^import Text\.XML\.HXT\.Core \(withSubstDTDEntities, yes, readString, no\)$/m);
  assert.match(plan.after, /readString \[withSubstDTDEntities no\] doc/);
  const bool = { 'Y.hs': 'module Y (parse) where\nimport Text.XML.HXT.Core\n\nparse :: String -> IO ()\nparse doc = readString [withSubstDTDEntities True] doc\n', 'Text/XML/HXT/Core.hs': STUB_HXT };
  const plan2 = await checked({ ...f, file: 'Y.hs' }, bool);
  assert.match(plan2.after, /withSubstDTDEntities False/);
});

test('PBKDF2 with too few iterations goes through the KDF migration: the old count stays for verification only', () => {
  const files = { 'K.hs': `module K (hashPassword) where
import Crypto.KDF.PBKDF2 (generate, prfHMAC, Parameters(..))
import Crypto.Hash (SHA256(..))
import Data.ByteString (ByteString)

hashPassword :: ByteString -> ByteString -> ByteString
hashPassword salt password = generate (prfHMAC SHA256) (Parameters { iterCounts = 100, outputLength = 32 }) password salt
` };
  const plan = planHaskellFix({ cwe: 'CWE-916', rule: 'hs-pbkdf2-low-iterations', file: 'K.hs', line: 7, vuln: 'PBKDF2 with too few iterations' }, files);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  assert.equal(plan.ruleId, 'hs-password-kdf-migrate');
  assert.match(plan.after, /hashPasswordLegacy salt password = generate \(prfHMAC SHA256\) \(Parameters \{ iterCounts = 100, outputLength = 32 \}\) password salt/);
  assert.match(plan.after, /600000/);
});
