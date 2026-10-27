// A function the program calls takes its parameters from its callers, so a flow into it is found only if the CALLER's request accessor is a known
// source. This pins that for IHP, whose controllers read the request with `param @Text "name"`: before IHP's accessors were modelled, a helper that
// ran a shell command on such a value was reported only because nothing in the project called it (a coincidence of call-graph ambiguity), and
// stopped being reported once the helper counted as called. Both directions: the request value is found, a constant is not.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

async function scanAll(files) {
  const dir = mkTestTmp('hs-trust-fw-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])];
}
const flagged = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));

const IHP_CTL = (arg) => `{-# LANGUAGE TypeApplications, OverloadedStrings, ImplicitParams #-}
module Ctl where

import IHP.ControllerPrelude
import qualified System.Process as Process
import Data.Text (Text)

data Action = OpenEditorAction

instance Controller Action where
    action OpenEditorAction = do
        let path = ${arg}
        openEditor path
        renderPlain ""

openEditor :: Text -> IO ()
openEditor path = do
    let command = "code " <> path
    _ <- Process.system (cs command)
    pure ()
`;

test('IHP: a controller action that hands param @Text "path" to a helper that runs a shell command is attacker-reachable; the same helper called with a constant is not', async () => {
  const hit = flagged(await scanAll({ 'Ctl.hs': IHP_CTL('param @Text "path"') }), 'CWE-78');
  assert.equal(hit.length, 1);
  assert.equal(hit[0].trustBoundary.verdict, 'attacker-reachable');
  assert.match(hit[0].source.label, /IHP request parameter/);
  const miss = flagged(await scanAll({ 'Ctl.hs': IHP_CTL('("README.md" :: Text)') }), 'CWE-78');
  assert.equal(miss.length, 0, 'a constant argument: the helper is called, so its parameter is not an unknown outside caller\'s');
});
