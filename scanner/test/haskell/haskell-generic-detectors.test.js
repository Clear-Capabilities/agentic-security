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
