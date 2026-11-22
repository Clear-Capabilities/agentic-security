// Haskell taint, round 12: a library constructor the models name as a sink (hasql's `Statement sql enc dec prepared`, postgresql-simple's
// `Query bytes`) is applied like the function it is, so the catalog matches it; every other library constructor stays a positional record and
// a project constructor is never a library API. `Hasql.Session.sql` is the whole-text sink. Each positive case has a refusing twin.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildProjectIRAsync } from '../../src/ir/index.js';

async function scanOf(prefix, files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-89' && f.severity !== 'info' && !f._provenUnreachable);
}
const HEAD = `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import qualified Hasql.Session as S
import qualified Hasql.Statement as St
import qualified Hasql.Encoders as E
import qualified Hasql.Decoders as D
import qualified Data.ByteString.Char8 as BC
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
main :: IO ()
main = scotty 3000 $ do
  get "/q" $ do
    name <- param "name"
`;
const DEC = `(D.rowList (D.column (D.nonNullable D.int8)))`;

test('hasql: the statement text of a Statement constructor built from a request value is SQL injection (qualified and unqualified constructor)', async () => {
  const concat = `    let stmt = St.Statement (BC.pack ("SELECT id FROM t WHERE n = '" ++ TL.unpack name ++ "'")) E.noParams ${DEC} True\n    _ <- liftIO (S.run (S.statement () stmt) undefined)\n    text "ok"\n`;
  const a = await scanOf('hs-r12-a', { 'Main.hs': HEAD + concat });
  assert.deepEqual(a.map((f) => [f.line, f.vuln.slice(0, 32)]), [[15, 'SQL Injection (statement text)']]);
  const b = await scanOf('hs-r12-b', { 'Main.hs': HEAD.replace('import qualified Hasql.Statement as St\n', 'import Hasql.Statement (Statement(..))\n') + concat.replace('St.Statement', 'Statement') });
  assert.deepEqual(b.map((f) => f.line), [15]);
});
test('hasql: Session.sql with concatenated text is the sink; a prepared Statement with an encoded parameter is not', async () => {
  const a = await scanOf('hs-r12-c', { 'Main.hs': HEAD + `    _ <- liftIO (S.run (S.sql (BC.pack ("DELETE FROM t WHERE n = '" ++ TL.unpack name ++ "'"))) undefined)\n    text "ok"\n` });
  assert.deepEqual(a.map((f) => [f.line, f.vuln.slice(0, 34)]), [[15, 'SQL Injection (session SQL text)']]);
  const b = await scanOf('hs-r12-d', { 'Main.hs': HEAD + `    let stmt = St.Statement "SELECT id FROM t WHERE n = $1" (E.param (E.nonNullable E.text)) ${DEC} True\n    _ <- liftIO (S.run (S.statement (TL.toStrict name) stmt) undefined)\n    text "ok"\n` });
  assert.deepEqual(b, []);
});
test('postgresql-simple: the Query constructor applied to request text is the sink the models always named (it had no call site before)', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.Types (Query(..))
import qualified Data.ByteString.Char8 as BC
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
main :: IO ()
main = do
  conn <- connectPostgreSQL ""
  scotty 3000 $ do
    get "/q" $ do
      name <- param "name"
      let q = Query (BC.pack ("SELECT * FROM t WHERE n = '" ++ TL.unpack name ++ "'"))
      rows <- liftIO (query_ conn q :: IO [Only Int])
      json (length rows)
`;
  const a = await scanOf('hs-r12-e', { 'Main.hs': src });
  assert.ok(a.some((f) => f.line === 15 && /Query constructed from text/.test(f.vuln)), JSON.stringify(a.map((f) => [f.line, f.vuln])));
});
test('the IR states the facts: a modelled library constructor is a call to its qualified name; an unmodelled one and a project constructor are records', async () => {
  const ir = await buildProjectIRAsync({ 'M.hs': `module M where
import qualified Hasql.Statement as St
import Data.Aeson (Value(..))
data Box = Box Int String
f :: String -> (St.Statement () [Int], Value, Box)
f s = (St.Statement (pack s) enc dec True, String (pack s), Box 1 s)
` });
  const fn = ir.perFile['M.hs'].functions.find((x) => /(^|\.)f$/.test(x.name));
  const ret = Object.values(fn.cfg.nodes).find((n) => n.kind === 'return');
  const [stmt, aesonString, box] = ret.value.elements;
  assert.equal(stmt.kind, 'call');
  assert.equal(stmt.callee, 'Hasql.Statement.Statement');
  assert.equal(stmt.hs.con, 'Statement');
  assert.equal(aesonString.kind, 'array');      // Data.Aeson's String constructor: no model names it
  assert.equal(box.kind, 'array');              // the project's own constructor, positional
  assert.equal(box.hs.con, 'Box');
});
