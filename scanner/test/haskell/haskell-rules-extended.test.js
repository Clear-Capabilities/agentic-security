// Haskell structural rules added after the first release: disabled TLS certificate validation (CWE-295) and signing/encryption secrets written in the
// source (CWE-798). DEVELOPMENT cases with renamed, qualified and near-miss twins; the frozen holdout and the unseen-shapes split were not read or run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const CASES = [
 {
  "id": "ctl-md5",
  "rule": "hs-weak-hash",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Crypto.Hash.MD5 as MD5\nimport qualified Data.ByteString as B\n\ndigest :: B.ByteString -> B.ByteString\ndigest x = MD5.hash x\n"
 },
 {
  "id": "tls-positional",
  "rule": "hs-tls-validation-disabled",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.Connection (TLSSettings (..))\nimport Network.HTTP.Client.TLS (mkManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nmain :: IO ()\nmain = do\n  mgr <- newManager (mkManagerSettings (TLSSettingsSimple True False False) Nothing)\n  return ()\n"
 },
 {
  "id": "tls-record",
  "rule": "hs-tls-validation-disabled",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.Connection (TLSSettings (..))\nimport Network.HTTP.Client.TLS (mkManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nnoVerify :: TLSSettings\nnoVerify = TLSSettingsSimple { settingDisableCertificateValidation = True, settingDisableSession = False, settingUseServerName = False }\n\nmain :: IO ()\nmain = do\n  mgr <- newManager (mkManagerSettings noVerify Nothing)\n  return ()\n"
 },
 {
  "id": "tls-verify-none",
  "rule": "hs-tls-validation-disabled",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified OpenSSL.Session as SSL\n\nsetup :: SSL.SSLContext -> IO ()\nsetup ctx = SSL.contextSetVerificationMode ctx SSL.VerifyNone\n"
 },
 {
  "id": "tls-safe-positional",
  "rule": "hs-tls-validation-disabled",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.Connection (TLSSettings (..))\nimport Network.HTTP.Client.TLS (mkManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nmain :: IO ()\nmain = do\n  mgr <- newManager (mkManagerSettings (TLSSettingsSimple False False False) Nothing)\n  return ()\n"
 },
 {
  "id": "tls-safe-default",
  "rule": "hs-tls-validation-disabled",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.HTTP.Client.TLS (tlsManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nmain :: IO ()\nmain = do\n  mgr <- newManager tlsManagerSettings\n  return ()\n"
 },
 {
  "id": "tls-safe-verify-peer",
  "rule": "hs-tls-validation-disabled",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified OpenSSL.Session as SSL\n\nsetup :: SSL.SSLContext -> IO ()\nsetup ctx = SSL.contextSetVerificationMode ctx (SSL.VerifyPeer True True Nothing)\n"
 },
 {
  "id": "tls-own-con",
  "rule": "hs-tls-validation-disabled",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\n\n\ndata Settings = TLSSettingsSimple Bool Bool Bool\n\nmk :: Settings\nmk = TLSSettingsSimple True False False\n"
 },
 {
  "id": "jwt-hmac-literal",
  "rule": "hs-hardcoded-secret",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.JWT\nimport Data.Text (Text)\n\nsigner :: EncodeSigner\nsigner = hmacSecret \"changeme-super-secret\"\n"
 },
 {
  "id": "servant-fromsecret",
  "rule": "hs-hardcoded-secret",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Servant.Auth.Server (fromSecret)\nimport qualified Data.ByteString.Char8 as B\n\nkey = fromSecret (B.pack \"0123456789abcdef0123456789abcdef\")\n"
 },
 {
  "id": "session-initkey",
  "rule": "hs-hardcoded-secret",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.ClientSession (initKey)\nimport qualified Data.ByteString.Char8 as B\n\nmk = initKey (B.pack \"a-very-long-secret-key-that-never-changes-0123456789abcdef\")\n"
 },
 {
  "id": "jwt-hmac-env",
  "rule": "hs-hardcoded-secret",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.JWT\nimport System.Environment (getEnv)\nimport qualified Data.Text as T\n\nsigner :: IO EncodeSigner\nsigner = do\n  s <- getEnv \"JWT_SECRET\"\n  return (hmacSecret (T.pack s))\n"
 },
 {
  "id": "jwt-hmac-param",
  "rule": "hs-hardcoded-secret",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.JWT\nimport Data.Text (Text)\n\nsignerFor :: Text -> EncodeSigner\nsignerFor s = hmacSecret s\n"
 },
 {
  "id": "own-hmacsecret",
  "rule": "hs-hardcoded-secret",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\n\n\nhmacSecret :: String -> Int\nhmacSecret s = length s\n\nuse :: Int\nuse = hmacSecret \"just-a-label\"\n"
 },
 {
  "id": "tls-qualified",
  "rule": "hs-tls-validation-disabled",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Network.Connection as NC\nimport Network.HTTP.Client.TLS (mkManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nmain :: IO ()\nmain = do\n  mgr <- newManager (mkManagerSettings (NC.TLSSettingsSimple True False False) Nothing)\n  return ()\n"
 },
 {
  "id": "tls-where-bound",
  "rule": "hs-tls-validation-disabled",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.Connection (TLSSettings (..))\nimport Network.HTTP.Client.TLS (mkManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nmain :: IO ()\nmain = do\n  mgr <- newManager (mkManagerSettings cfg Nothing)\n  return ()\n  where\n    cfg = TLSSettingsSimple True True True\n"
 },
 {
  "id": "tls-first-false-second-true",
  "rule": "hs-tls-validation-disabled",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.Connection (TLSSettings (..))\nimport Network.HTTP.Client.TLS (mkManagerSettings)\nimport Network.HTTP.Client (newManager)\n\nmain :: IO ()\nmain = do\n  mgr <- newManager (mkManagerSettings (TLSSettingsSimple False True True) Nothing)\n  return ()\n"
 },
 {
  "id": "secret-short-placeholder",
  "rule": "hs-hardcoded-secret",
  "vuln": false,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.JWT\n\nsigner :: EncodeSigner\nsigner = hmacSecret \"x\"\n"
 },
 {
  "id": "secret-renamed",
  "rule": "hs-hardcoded-secret",
  "vuln": true,
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Web.JWT as J\n\ntokenSigner :: J.EncodeSigner\ntokenSigner = J.hmacSecret \"prod-signing-key-2024\"\n"
 }
];

for (const c of CASES) {
  test(`${c.vuln ? 'FOUND' : 'SILENT'}: ${c.id} (${c.rule})`, () => {
    const hits = analyzeHaskellRules({ 'Main.hs': c.src }).findings.filter((f) => f.rule === c.rule);
    if (c.vuln) { assert.ok(hits.length >= 1, 'a finding'); assert.ok(hits.every((h) => /^CWE-\d+$/.test(h.cwe) && Number.isInteger(h.line) && h.line >= 1)); }
    else assert.equal(hits.length, 0, JSON.stringify(hits.map((h) => ({ line: h.line, detail: h.description }))));
  });
}
