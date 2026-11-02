// Language-neutral text detectors must not fire on Haskell source because of how a Haskell file LOOKS. Three real cases, each pinned in both
// directions: a Haskell module that opens with a `{-# LANGUAGE #-}` pragma was sniffed as a JSON document and its doc comments were read as a cloud
// IAM policy (a critical finding for the word `allUsers`); JavaScript-syntax structural patterns (`parseString(`, `$(document)`) fired on Haskell
// text; and the `unsafe*` boundary notes, which claim no vulnerability class, were reported at `low`.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { scanCloudIam } from '../../src/sast/cloud-iam.js';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

async function scan(files) {
  const dir = mkTestTmp('hs-generic-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])];
}

const GCP_JSON = '{\n  "bindings": [ { "role": "roles/storage.objectViewer", "members": ["allUsers"] } ]\n}\n';

test('cloud IAM: a Haskell module whose doc comment says allUsers is not a policy; a real JSON binding still is', () => {
  const hs = '{-# LANGUAGE OverloadedStrings #-}\nmodule Fetch where\n\n-- | Fetching all users\n--\n-- > allUsers <- query @User |> fetchVector\nfetchAll :: IO [Int]\nfetchAll = pure []\n';
  assert.equal(scanCloudIam('src/Fetch.hs', hs).length, 0);
  assert.equal(scanCloudIam('src/Fetch.hs', `{- bindings: allUsers -}\n${hs}`).length, 0, 'a block comment opens with a brace too');
  assert.ok(scanCloudIam('policy.json', GCP_JSON).length >= 1, 'a JSON policy by extension');
  assert.ok(scanCloudIam('policy', GCP_JSON).length >= 1, 'a JSON policy by its opening brace and quoted key');
  assert.ok(scanCloudIam('policy', GCP_JSON.replace('{\n', '{ \n')).length >= 1);
});

test('structural patterns written in JavaScript syntax do not run on Haskell text; they still run on JavaScript', async () => {
  const hs = `{-# LANGUAGE OverloadedStrings #-}
module Cfg where

import Data.Text (Text)
import qualified Data.Text as T

data Val = String Text | Number Int

parseString :: Val -> Maybe String
parseString (String x) = Just (T.unpack x)
parseString _ = Nothing

page :: Text
page = "<script>$(document).on('ready', init);</script>"
`;
  const fs = await scan({ 'src/Cfg.hs': hs, 'web/app.js': "$(document).on('ready', init);\n" });
  assert.equal(fs.filter((f) => f.parser === 'STRUCTURAL' && /Cfg\.hs$/.test(f.file)).length, 0);
  assert.ok(fs.some((f) => f.parser === 'STRUCTURAL' && /app\.js$/.test(f.file)), 'the same pattern on JavaScript is still reported');
});

test('unsafe boundary notes are information in a scan, with the severity the rule gives them kept', async () => {
  const fs = await scan({ 'src/Counter.hs': 'module Counter (counter) where\n\nimport System.IO.Unsafe (unsafePerformIO)\nimport Data.IORef\n\ncounter :: IORef Int\ncounter = unsafePerformIO (newIORef 0)\n{-# NOINLINE counter #-}\n' });
  const notes = fs.filter((f) => f.rule === 'hs-unsafe-io-boundary');
  assert.equal(notes.length, 1);
  assert.equal(notes[0].severity, 'info');
  assert.equal(notes[0].originalSeverity, 'low');
});

// ── the comment-blanked view (since 0.195.11) ────────────────────────────────────────────────────────────────────────────────────
// The language-neutral detectors (ciphers, protocol shapes, structural text patterns) read a comment-blanked view of every file. For Haskell
// that view was the C-family one, which knows neither `--` lines nor `{- -}` blocks, so an API name quoted in a Haskell doc comment
// (`crypto.createHash('md5')`, a JWT verify with `none`) was reported as a call. The view for `.hs` is now the Haskell comment lexer's
// (language/haskell-comments.js), the same one the Haskell findings' snippets use. Pinned both ways: the comment is silent, and the same text
// in code position of a JavaScript file still fires.
async function scanWithCiphers(files) {
  const dir = mkTestTmp('hs-generic-view-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return { findings: [...(r.scan.findings || []), ...(r.scan.logicVulns || [])], ciphers: (r.scan.ciphers && r.scan.ciphers.atRest) || r.scan.ciphersAtRest || [] };
}
const QUOTED = "crypto.createHash('md5') over the password; jwt.verify(token, secret, { algorithms: ['none'] })";

test('a Haskell comment quoting other-language API calls produces no language-neutral finding; the same text as JavaScript code does', async () => {
  const hs = await scanWithCiphers({ 'src/Svc.hs': `module Svc (run) where\n\n-- ${QUOTED}\n{- ${QUOTED}\n   nested {- ${QUOTED} -} still a comment -}\nrun :: IO ()\nrun = putStrLn "ok"\n` });
  const generic = hs.findings.filter((f) => f.file === 'src/Svc.hs' && !/^HS-|^IR-TAINT$/.test(String(f.parser || '')));
  assert.deepEqual(generic.map((f) => `${f.parser}:${f.vuln}`), [], 'nothing fires on a comment');
  assert.deepEqual(hs.ciphers.filter((c) => c.file === 'src/Svc.hs'), [], 'no cipher is read from a comment');
  const js = await scanWithCiphers({ 'src/svc.js': `const crypto = require('crypto');\nconst jwt = require('jsonwebtoken');\nfunction run(password, token, secret) {\n  const h = ${QUOTED.replace(/ over the password; /, '; const v = ')};\n  return [h, v];\n}\nmodule.exports = { run };\n` });
  assert.ok(js.findings.some((f) => /none/i.test(String(f.vuln))) || js.ciphers.some((c) => c.cipher === 'md5'), `the detectors still fire on code: ${JSON.stringify(js.findings.map((f) => f.vuln))} ${JSON.stringify(js.ciphers)}`);
});

test('a Haskell string literal is code, not a comment: a dash sequence inside it does not blank the rest of the line', async () => {
  // `"--"` inside a string must not be read as a comment start (the Haskell lexer handles it; this pins that the engine uses that lexer and not
  // a naive `--` rule). The rule-based Haskell analyzers must still see the shell call on the line.
  const hs = await scanWithCiphers({ 'src/Svc.hs': `module Svc (run) where\n\nimport System.Process (callCommand)\n\nrun :: String -> IO ()\nrun host = callCommand ("ping -- " ++ host)\n` });
  assert.ok(hs.findings.some((f) => f.cwe === 'CWE-78' && f.file === 'src/Svc.hs'), JSON.stringify(hs.findings.map((f) => [f.cwe, f.parser])));
});
