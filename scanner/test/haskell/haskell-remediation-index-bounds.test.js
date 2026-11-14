// hs-index-bounds (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md, lever 3): `list !! i` where `i` is caller-supplied text
// (the three IHP schema-designer true positives: `deleteEnum tableId list = delete (list !! tableId) list` and two like it) gets a guard equation
// before the function's first equation, returning the list unchanged when the index is out of range. The CWE-248 class reason names three
// candidate failure values; "an unchanged result" is the one that type-checks by construction, so the fixer applies only where the
// declared result type IS the indexed parameter's type. The check is a relational test on the index against the list's length, which the
// rule already reads as the bounds test, so the rescan goes quiet on semantics. A MITIGATION: the caller is not told the input was ignored.
import test from 'node:test';
import assert from 'node:assert/strict';
import { planHaskellFix, validateHaskellFix } from '../../src/language/haskell-fix.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

process.env.GHC_ENVIRONMENT = '-';
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

const FRAMEWORK = `{-# LANGUAGE ImplicitParams #-}
module IHP.Controller.Param (param) where

import Data.Text (Text)
import qualified Data.Text as T
import Network.Wai (Request, queryString)

param :: (?request :: Request) => Text -> Text
param name = maybe "" (T.pack . show) (lookup (T.unpack name) (map (\\(k, v) -> (show k, v)) (queryString ?request)))
`;
const ENUMS = (helper) => `{-# LANGUAGE ImplicitParams, OverloadedStrings #-}
module IHP.IDE.SchemaDesigner.Controller.Enums (deleteEnumAction) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.List (delete)
import IHP.Controller.Param (param)
import Network.Wai (Request)

type Schema = [Text]

deleteEnumAction :: (?request :: Request) => IO ()
deleteEnumAction = do
    let tableId = length (T.unpack (param "tableId"))
    ${'CALLS'}

updateSchema :: ([Text] -> [Text]) -> IO ()
updateSchema f = print (f ["users", "posts"])

${helper}
`;
const withCalls = (text, calls) => text.replace('CALLS', calls);
const HELPERS = `deleteEnum :: Int -> [Text] -> [Text]
deleteEnum tableId list = delete (list !! tableId) list

updateTable :: Int -> Text -> Schema -> Schema
updateTable tableId tableName statements =
    let
        oldName = statements !! tableId
    in
        map (\\s -> if s == oldName then tableName else s) statements
`;

const partials = (files) => analyzeHaskellRules(files).findings.filter((f) => f.rule === 'hs-partial-function-on-input' && /caller-supplied index/.test(f.description));

test('both helpers get a guard equation returning the list unchanged for an out-of-range index; the rescan shows the rule quiet', async () => {
  const files = { 'IHP/Controller/Param.hs': FRAMEWORK, 'Enums.hs': withCalls(ENUMS(HELPERS), 'updateSchema (deleteEnum tableId)\n    updateSchema (updateTable tableId "renamed")') };
  const before = partials(files);
  assert.deepEqual(before.map((f) => f.line).sort(), [22, 27], JSON.stringify(before.map((f) => [f.line, f.description])));
  const one = before.find((f) => f.line === 22); const two = before.find((f) => f.line === 27);
  const p1 = planHaskellFix(one, files);
  assert.equal(p1.ok, true, JSON.stringify(p1));
  assert.equal(p1.ruleId, 'hs-index-bounds'); assert.equal(p1.label, 'MITIGATION');
  assert.match(p1.after, /^deleteEnum tableId list\n    \| tableId < 0 \|\| tableId >= length list = list\ndeleteEnum tableId list = delete/m);
  assert.ok(p1.consequences.some((c) => /unchanged/.test(c)), JSON.stringify(p1.consequences));
  const p2 = planHaskellFix(two, files);
  assert.equal(p2.ok, true, JSON.stringify(p2));
  assert.match(p2.after, /^updateTable tableId tableName statements\n    \| tableId < 0 \|\| tableId >= length statements = statements\nupdateTable tableId tableName statements =$/m);
  for (const [f, plan] of [[one, p1], [two, p2]]) {
    const v = await validateHaskellFix(f, { files });
    assert.equal(v.gates.syntax.ok, true, JSON.stringify(v.gates.syntax));
    assert.equal(v.gates.effective.ok, true, JSON.stringify(v.gates.effective));
    assert.equal(v.gates.rescan && v.gates.rescan.originalGone, true, JSON.stringify(v.gates.rescan));
    const after = partials({ ...files, 'Enums.hs': plan.after });
    assert.equal(after.filter((x) => x.line >= f.line && x.line <= f.line + 1).length, 0, JSON.stringify(after.map((x) => [x.line, x.description])));
  }
});

test('refused, with the class decision named: a result type that is not the list, a list that is not a parameter, two different indexes, an already tested index', () => {
  const cases = {
    'a result that is not the list': 'pick :: Int -> [Text] -> Text\npick tableId list = list !! tableId\n',
    'a list built in the body': 'pick :: Int -> [Text] -> [Text]\npick tableId list = delete ((list ++ list) !! tableId) list\n',
    'two indexes on one line': 'pick :: Int -> Int -> [Text] -> [Text]\npick i j list = delete (list !! i) (delete (list !! j) list)\n',
    'a tested index': 'pick :: Int -> [Text] -> [Text]\npick tableId list = if tableId < length list then delete (list !! tableId) list else list\n',
  };
  for (const [why, helper] of Object.entries(cases)) {
    const files = { 'IHP/Controller/Param.hs': FRAMEWORK, 'Enums.hs': withCalls(ENUMS(helper), why === 'two indexes on one line' ? 'updateSchema (pick tableId tableId)' : why === 'a result that is not the list' ? 'print (pick tableId ["users", "posts"])' : 'updateSchema (pick tableId)') };
    const hits = partials(files);
    if (why === 'a tested index') { assert.equal(hits.length, 0, why); continue; }
    assert.ok(hits.length >= 1, `${why}: ${JSON.stringify(hits)}`);
    const plan = planHaskellFix(hits[0], files);
    assert.equal(plan.ok, false, why);
    assert.match(plan.reason, /The decision needed:/, why);
    assert.match(plan.reason, /unchanged result|out of range/, why);
  }
});
