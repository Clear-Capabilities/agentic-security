// OverloadedRecordDot (`order.customer`, `(.note)`) and OverloadedLabels (`get #customer order`): read as a field selection and a label
// value when the module's LANGUAGE pragma enables the extension (haskell-syntax.js). Before this, `r.field` lexed as composition: a probe of
// the shapes below still fired through the composition value, but with the source LOST (trust `unattributed`); now the request parameter is
// the recorded root (`attacker-reachable`). Without the extension `f.g` stays composition. Pinned both ways.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { parseSyntax } from '../../src/language/haskell-syntax.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
function scan(src) {
  const dir = mkTestTmp('hs-rdot-');
  writeFileSync(join(dir, 'Main.hs'), src);
  const env = { ...process.env, AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1' }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings.filter((f) => f.parser === 'IR-TAINT');
}
const cmd = (fs) => fs.filter((f) => f.cwe === 'CWE-78' && f.severity !== 'info');
const SCOTTY = `module Main where
import Web.Scotty
import System.Process (callCommand)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL

data Order = Order { customer :: TL.Text, note :: TL.Text }
`;

test('a field read through record dot carries the request parameter to the sink with its source recorded', () => {
  const fs = scan(`{-# LANGUAGE OverloadedRecordDot, OverloadedStrings #-}\n${SCOTTY}
main :: IO ()
main = scotty 3000 $
  post "/orders" $ do
    name <- formParam "customer"
    let order = Order { customer = name, note = "x" }
    liftIO (callCommand ("label " ++ TL.unpack order.customer))
    text order.note
`);
  const c = cmd(fs);
  assert.equal(c.length, 1, JSON.stringify(fs.map((f) => [f.line, f.vuln])));
  assert.equal(c[0].trustBoundary && c[0].trustBoundary.verdict, 'attacker-reachable');
  assert.match((c[0].source && c[0].source.label) || '', /request parameter/, JSON.stringify(c[0].source));
  // the sibling field is clean: reading `order.note` into a sink does not fire
  const sibling = scan(`{-# LANGUAGE OverloadedRecordDot, OverloadedStrings #-}\n${SCOTTY}
main :: IO ()
main = scotty 3000 $
  post "/orders" $ do
    name <- formParam "customer"
    let order = Order { customer = name, note = "x" }
    liftIO (callCommand ("label " ++ TL.unpack order.note))
    text name
`);
  assert.equal(cmd(sibling).length, 0, 'a clean sibling field is not tainted');
});

test('record dot through a helper and the selector section (.field) are followed', () => {
  const fs = scan(`{-# LANGUAGE OverloadedRecordDot, OverloadedStrings #-}\n${SCOTTY}
label :: Order -> String
label o = "label " ++ TL.unpack o.customer

main :: IO ()
main = scotty 3000 $
  post "/orders" $ do
    name <- formParam "customer"
    let order = Order { customer = name, note = "x" }
    liftIO (callCommand (label order))
    liftIO (mapM_ (callCommand . TL.unpack) (map (.customer) [order]))
`);
  assert.equal(cmd(fs).length, 2, JSON.stringify(fs.map((f) => [f.line, f.vuln])));
});

test('without the extension a dotted lowercase pair is composition, and the lexer reads the shapes it should', () => {
  const r = parseSyntax('{-# LANGUAGE OverloadedRecordDot #-}\nmodule M where\nf o xs = g o.customer.name (map (.note) xs) (h . k $ o)\n');
  assert.deepEqual(r.errors, []);
  const b = r.decls[0].clause.rhs.body;
  assert.equal(b.args[0].t, 'app'); assert.equal(b.args[0].f.name, 'name'); assert.equal(b.args[0].args[0].f.name, 'customer');
  assert.equal(b.args[1].e.args[0].name, 'note', 'the selector section is the field function');
  assert.equal(b.args[2].e.t, 'op', 'spaced `h . k` stays composition');
  const off = parseSyntax('module M where\nf o = (g.h) o\n');
  assert.equal(off.decls[0].clause.rhs.body.f.e.t, 'op', 'without the extension `g.h` is composition');
});

test('OverloadedLabels: `set #field v r` and `get #field r` carry the value (IHP style)', () => {
  const fs = scan(`{-# LANGUAGE OverloadedLabels, OverloadedStrings #-}\n${SCOTTY}import IHP.ModelSupport (get, set)

main :: IO ()
main = scotty 3000 $
  post "/orders" $ do
    name <- formParam "customer"
    let order = set #customer name (Order "" "x")
    liftIO (callCommand ("label " ++ TL.unpack (get #customer order)))
`);
  const c = cmd(fs);
  assert.equal(c.length, 1, JSON.stringify(fs.map((f) => [f.line, f.vuln])));
  assert.equal(c[0].trustBoundary && c[0].trustBoundary.verdict, 'attacker-reachable');
  const r = parseSyntax('{-# LANGUAGE OverloadedLabels #-}\nmodule M where\nf r = get #name r\ng x = x # 1\n');
  assert.deepEqual(r.errors, []);
  assert.equal(r.decls[0].clause.rhs.body.args[0].t, 'label');
  assert.equal(r.decls[1].clause.rhs.body.t, 'op', 'an infix `#` operator stays an operator');
});
