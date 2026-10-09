// HS-006: Haskell web authentication, authorization and entry points.
// Suite "haskell-web-auth" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// The route fixtures under test/fixtures/haskell-web/ are real Haskell modules for Scotty, WAI/Warp, Servant and
// Yesod. Expected classifications are written here, in the test, never in the fixtures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeHaskellWeb, WEB_RULES, spine } from '../../src/language/haskell-web.js';
import { HS_WEB_FRAMEWORKS, HS_WEB_MODEL_VERSION } from '../../src/language/haskell-models.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = join(HERE, '..', 'fixtures', 'haskell-web');
const BIN = join(HERE, '..', '..', 'bin', 'agentic-security.js');
const DOC = join(HERE, '..', '..', '..', 'docs', 'guides', 'haskell.md');

const load = (dir, only = null) => {
  const files = {};
  for (const f of readdirSync(join(FX, dir))) if (f.endsWith('.hs') && (!only || only.includes(f))) files[`${dir}/${f}`] = readFileSync(join(FX, dir, f), 'utf8');
  return files;
};
const analyze = (dir, only, opts) => analyzeHaskellWeb(load(dir, only), opts);
const route = (r, method, path) => r.routes.find((x) => x.method === method && x.path === path);
const rules = (r) => r.findings.map((f) => `${f.rule}:${f.route.method} ${f.route.path}`).sort();

function cliScan(files) {
  const dir = mkTestTmp('hs-web-');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout);
}

// ---- AC01 ------------------------------------------------------------------

test('[HS-006.AC01] Scotty: public, authenticated, role-restricted and object-scoped routes are classified, and each flaw is reported', () => {
  const r = analyze('scotty', ['Auth.hs', 'Main.hs']);
  assert.deepEqual(r.frameworks, ['scotty']);
  const a = (m, p) => route(r, m, p).auth.status;
  assert.equal(a('GET', '/health'), 'none');
  assert.equal(a('GET', '/public/items'), 'none');
  assert.equal(a('POST', '/items'), 'authenticated');
  assert.equal(a('POST', '/items/bulk'), 'none');
  assert.equal(a('GET', '/items/:id'), 'authenticated');
  assert.equal(a('GET', '/orders/:id'), 'authenticated');
  assert.equal(a('POST', '/admin/purge'), 'authenticated');
  assert.equal(a('POST', '/late'), 'late');
  assert.equal(route(r, 'POST', '/admin/purge').role.status, 'present', 'requireAdmin carries a role check');
  assert.equal(route(r, 'POST', '/admin/users').role.status, 'none');
  assert.equal(route(r, 'GET', '/items/:id').ownership.kind, 'principal-scoped-query', 'the lookup is scoped by id AND owner');
  assert.equal(route(r, 'GET', '/orders/:id').ownership, null);
  assert.deepEqual(rules(r), [
    'hs-route-bfla:POST /admin/users',
    'hs-route-bola:GET /orders/:id',
    'hs-route-csrf:POST /cookie/settings',
    'hs-route-late-auth:POST /late',
    'hs-route-missing-auth:POST /items/bulk',
  ]);
});

test('[HS-006.AC01] Scotty: guard dominance - a guard before the first sensitive operation counts, one after it does not', () => {
  const r = analyze('scotty', ['Auth.hs', 'Main.hs']);
  assert.equal(route(r, 'POST', '/items').auth.evidence[0].kind, 'handler-guard');
  const late = route(r, 'POST', '/late');
  assert.equal(late.auth.status, 'late');
  assert.equal(late.auth.evidence[0].kind, 'late-guard');
  assert.ok(r.findings.some((f) => f.rule === 'hs-route-late-auth' && f.cwe === 'CWE-306'));
  assert.ok(!r.findings.some((f) => f.rule === 'hs-route-missing-auth' && f.route.path === '/late'), 'reported as late, not as missing');
});

test('[HS-006.AC01] Scotty: CSRF applies to cookie-authenticated state changes only, not to Authorization-header APIs', () => {
  const r = analyze('scotty', ['Auth.hs', 'Main.hs']);
  assert.deepEqual([...route(r, 'POST', '/cookie/settings').credentialKinds], ['cookie']);
  assert.deepEqual([...route(r, 'POST', '/items').credentialKinds], ['token']);
  const csrf = r.findings.filter((f) => f.rule === 'hs-route-csrf');
  assert.deepEqual(csrf.map((f) => f.route.path), ['/cookie/settings']);
  assert.equal(csrf[0].cwe, 'CWE-352');
});

test('[HS-006.AC01] WAI/Warp: routes come from the router case, and a middleware only protects the routers in the `run` that installs it', () => {
  const r = analyze('wai', ['Auth.hs', 'Main.hs', 'Unprotected.hs']);
  const protectedRoutes = r.routes.filter((x) => x.file === 'wai/Main.hs');
  assert.deepEqual(protectedRoutes.map((x) => `${x.method} ${x.path}`).sort(), ['GET /health', 'GET /items/:param', 'POST /items']);
  assert.ok(protectedRoutes.every((x) => x.auth.status === 'authenticated' && x.auth.evidence[0].kind === 'global-guard'));
  const open = route(r, 'POST', '/transfer');
  assert.equal(open.auth.status, 'none', 'passthroughMiddleware reads no credential and rejects nothing');
  assert.deepEqual(rules(r), ['hs-route-missing-auth:POST /transfer']);
  assert.equal(r.middleware.find((m) => m.file.endsWith('Unprotected.hs')).status, 'not-an-auth-guard');
  assert.equal(r.middleware.find((m) => m.file.endsWith('Main.hs')).status, 'auth-guard');
});

test('[HS-006.AC01] Servant: the API type is the route table; auth combinators, ownership and role come from the type and the handler', () => {
  const r = analyze('servant');
  assert.deepEqual(r.routes.map((x) => `${x.method} ${x.path}`).sort(), ['DELETE /admin/purge', 'GET /health', 'GET /mine/:id', 'GET /theirs/:id', 'POST /items']);
  assert.equal(route(r, 'GET', '/health').auth.status, 'none');
  assert.equal(route(r, 'POST', '/items').auth.status, 'none');
  assert.equal(route(r, 'GET', '/mine/:id').auth.evidence[0].kind, 'type-combinator');
  assert.equal(route(r, 'GET', '/mine/:id').ownership.kind, 'principal-scoped-query');
  assert.equal(route(r, 'GET', '/theirs/:id').ownership, null);
  assert.equal(route(r, 'DELETE', '/admin/purge').role.status, 'present', 'AuthProtect "admin" is a role-scoped combinator');
  assert.deepEqual(rules(r), ['hs-route-bola:GET /theirs/:id', 'hs-route-missing-auth:POST /items']);
  assert.ok(![...route(r, 'GET', '/mine/:id').credentialKinds].includes('cookie'), 'a header-credential API is not CSRF-exposed');
});

test('[HS-006.AC01] Yesod: routes come from parseRoutes, auth from isAuthorized, handlers by naming convention', () => {
  const r = analyze('yesod');
  assert.deepEqual(r.routes.map((x) => `${x.method} ${x.path}`).sort(), ['GET /', 'GET /account', 'GET /orders/:param', 'POST /account', 'POST /admin/purge']);
  assert.equal(route(r, 'GET', '/').auth.status, 'none');
  assert.equal(route(r, 'POST', '/account').auth.status, 'authenticated');
  assert.equal(route(r, 'POST', '/account').auth.evidence[0].via, 'isAuthorized');
  assert.equal(route(r, 'POST', '/admin/purge').auth.status, 'none', 'the catch-all `isAuthorized _ _ = return Authorized` is public');
  assert.deepEqual(rules(r), ['hs-route-bola:GET /orders/:param', 'hs-route-missing-auth:POST /admin/purge']);
  assert.ok(route(r, 'GET', '/orders/:param').handler.name === 'getOrderR');
});

test('[HS-006.AC01] a real scan reports the route findings and registers the routes in the engine inventory', () => {
  const out = cliScan(load('scotty', ['Auth.hs', 'Main.hs']));
  const web = out.findings.filter((f) => f.parser === 'HS-WEB');
  assert.equal(web.length, 5);
  assert.ok(web.every((f) => f.language === 'haskell' && f.originalLocation.line === f.line && f.route && f.family));
  assert.equal(out.routes.filter((x) => x.language === 'haskell').length, 10);
  assert.equal(out.entrypointInventory.coverage.byType.http, 10);
  const stable = new Set(web.map((f) => f.stableId));
  assert.equal(stable.size, web.length, 'routes with similar handlers are not clustered into one');
});

test('[HS-006.AC01] the route fixtures compile (requires GHC; an unavailable compiler is a failed criterion, never a skip)', () => {
  let ghc;
  try { ghc = execFileSync('ghc', ['--numeric-version'], { encoding: 'utf8', timeout: 20000 }).trim(); } catch { ghc = null; }
  assert.ok(ghc, 'ghc is not installed on this host: AC01 requires real COMPILABLE route fixtures, so it cannot be verified here. Install GHC (and the fixtures\' packages) and re-run `verify --requirement HS-006`.');
  // A directory holds several PROGRAMS that share Auth.hs, each with its own Main: compile each program (its entry module, with the
  // directory on the import path) separately, never every file in one invocation.
  const out = mkTestTmp('hs-compile-');
  const mains = (dir) => readdirSync(join(FX, dir)).filter((f) => f.endsWith('.hs') && f !== 'Auth.hs');
  for (const dir of ['scotty', 'wai', 'servant', 'yesod']) {
    for (const f of mains(dir)) {
      const p = spawnSync('ghc', ['-fno-code', '-Wno-all', `-i${join(FX, dir)}`, '-outputdir', out, join(FX, dir, f)], { encoding: 'utf8', timeout: 600000 });
      assert.equal(p.status, 0, `${dir}/${f}: ${p.stderr.slice(0, 400)}`);
    }
  }
});

// ---- AC02 ------------------------------------------------------------------

test('[HS-006.AC02] the route inventory reconciles: every route is either analysed or unknown, and nothing is omitted', () => {
  for (const [dir, only] of [['scotty', ['Auth.hs', 'Main.hs']], ['wai', null], ['servant', null], ['yesod', null], ['scotty', ['Auth.hs', 'Dynamic.hs']]]) {
    const r = analyze(dir, only);
    assert.equal(r.coverage.routes, r.routes.length);
    assert.equal(r.coverage.analysed + r.coverage.unknown, r.coverage.routes, `${dir}: coverage reconciles`);
    assert.equal(r.routes.filter((x) => x.handler.kind === 'unknown').length, r.coverage.unknown);
  }
});

test('[HS-006.AC02] Warp being present, a type annotation, and an authentication declaration disconnected from the handler establish nothing', () => {
  const r = analyze('scotty', ['Auth.hs', 'Disconnected.hs']);
  assert.equal(route(r, 'POST', '/account/delete').auth.status, 'none', '`deleteAccount :: ActionM ()` imports requireUser and never calls it');
  assert.equal(route(r, 'POST', '/account/rename').auth.status, 'none', 'checkUser reads a header but rejects nothing: not a guard');
  assert.deepEqual(rules(r), ['hs-route-missing-auth:POST /account/delete', 'hs-route-missing-auth:POST /account/rename']);
  const w = analyze('wai', ['Auth.hs', 'Unprotected.hs']);
  assert.equal(route(w, 'POST', '/transfer').auth.status, 'none', 'Warp `run` serves the app; it authorizes nothing, and authMiddleware is imported but never installed');
});

test('[HS-006.AC02] an auth guard counts only when it really reads a credential AND rejects', () => {
  const mk = (guard) => analyzeHaskellWeb({ 'G.hs': `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Network.HTTP.Types (status401)
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
${guard}
main :: IO ()
main = scotty 3000 $ do
  post "/x" $ do
    g
    conn <- liftIO (connectPostgreSQL "d")
    _ <- liftIO (execute_ conn "DELETE FROM t")
    text "ok"
` });
  const reads = 'g :: ActionM ()\ng = do\n  h <- header "Authorization"\n  case h of\n    Nothing -> status status401 >> finish\n    Just _ -> pure ()';
  const readsOnly = 'g :: ActionM ()\ng = do\n  _ <- header "Authorization"\n  pure ()';
  const rejectsOnly = 'g :: ActionM ()\ng = status status401 >> finish';
  assert.equal(route(mk(reads), 'POST', '/x').auth.status, 'authenticated');
  assert.equal(route(mk(readsOnly), 'POST', '/x').auth.status, 'none');
  assert.equal(route(mk(rejectsOnly), 'POST', '/x').auth.status, 'none', 'rejecting unconditionally is not authentication');
});

// ---- AC03 ------------------------------------------------------------------

test('[HS-006.AC03] a route through imported middleware is analysed across files', () => {
  const r = analyze('wai', ['Auth.hs', 'Main.hs']);
  const g = route(r, 'POST', '/items').auth.evidence[0];
  assert.equal(g.kind, 'global-guard');
  assert.equal(g.via, 'Auth.authMiddleware', 'resolved through the import to the defining module');
  assert.equal(g.file, 'wai/Main.hs');
  // the same module analysed without its imported guard cannot be credited
  const alone = analyzeHaskellWeb({ 'wai/Main.hs': load('wai', ['Main.hs'])['wai/Main.hs'] });
  assert.equal(route(alone, 'POST', '/items').auth.status, 'none');
  assert.ok(alone.gaps.some((x) => x.kind === 'opaque-middleware'), 'an unresolvable middleware is disclosed, not trusted');
});

test('[HS-006.AC03] a Scotty guard imported from another module is credited; Scotty `middleware` is classified', () => {
  const files = {
    'Guard.hs': load('scotty', ['Auth.hs'])['scotty/Auth.hs'],
    'Main.hs': `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
import Auth (requireUser)
main :: IO ()
main = scotty 3000 $ do
  post "/a" $ do
    _ <- requireUser
    conn <- liftIO (connectPostgreSQL "d")
    _ <- liftIO (execute_ conn "DELETE FROM t")
    text "ok"
`,
  };
  // the module is named Auth: file name does not matter, the module header does
  const r = analyzeHaskellWeb(files);
  assert.equal(route(r, 'POST', '/a').auth.status, 'authenticated');
});

test('[HS-006.AC03] dynamic registration and computed paths are disclosed as gaps and counted as unknown, not omitted', () => {
  const r = analyze('scotty', ['Auth.hs', 'Dynamic.hs']);
  assert.equal(r.routes.length, 3);
  assert.equal(route(r, 'GET', '/static').handler.kind, 'inline');
  const dyn = r.routes.filter((x) => x.path === '<dynamic>');
  assert.equal(dyn.length, 2);
  assert.ok(dyn.every((x) => x.handler.kind === 'unknown' && x.auth.status === 'unknown'), 'an unanalysed route is unknown, never protected');
  assert.deepEqual([...new Set(r.gaps.map((g) => g.kind))].sort(), ['dynamic-route-path', 'dynamic-route-registration']);
  assert.equal(r.coverage.unknown, 2);
  assert.equal(r.findings.length, 0, 'no verdict is invented for routes that were not analysed');
});

test('[HS-006.AC03] a Servant API whose handler list does not match its endpoints is disclosed, not guessed', () => {
  const src = readFileSync(join(FX, 'servant', 'Api.hs'), 'utf8').replace('health :<|> addItem :<|> mine :<|> theirs :<|> purge', 'health :<|> addItem :<|> mine');
  const r = analyzeHaskellWeb({ 'Api.hs': src });
  assert.ok(r.gaps.some((g) => g.kind === 'servant-handler-arity'));
  assert.ok(r.routes.every((x) => x.handler.kind === 'unknown'));
});

// ---- AC04 ------------------------------------------------------------------

test('[HS-006.AC04] framework versions and supported auth patterns live in the model registry', () => {
  assert.equal(HS_WEB_MODEL_VERSION, 'haskell-web-models/1');
  for (const name of ['scotty', 'wai', 'servant', 'yesod']) {
    const f = HS_WEB_FRAMEWORKS[name];
    assert.ok(f.package && f.modules.length && f.tested.length, name);
  }
  const r = analyze('scotty', ['Auth.hs', 'Main.hs'], { packageVersions: { scotty: '0.12.1' } });
  assert.equal(r.versionStatus.scotty.status, 'tested');
  assert.equal(r.modelVersion, HS_WEB_MODEL_VERSION);
  assert.ok(WEB_RULES['hs-route-bola'].cwe === 'CWE-639' && WEB_RULES['hs-route-bfla'].cwe === 'CWE-285');
});

test('[HS-006.AC04] an unrecognised or unknown framework version falls back to best-effort analysis and says so', () => {
  const tested = analyze('scotty', ['Auth.hs', 'Main.hs'], { packageVersions: { scotty: '0.12' } });
  const odd = analyze('scotty', ['Auth.hs', 'Main.hs'], { packageVersions: { scotty: '9.9.9' } });
  const unknown = analyze('scotty', ['Auth.hs', 'Main.hs']);
  assert.equal(odd.versionStatus.scotty.status, 'untested-version');
  assert.equal(unknown.versionStatus.scotty.status, 'unknown-version');
  assert.deepEqual(rules(odd), rules(tested), 'the same routes are analysed');
  for (const f of odd.findings) {
    assert.ok(f.uncertainty.some((u) => u.kind === 'untested-model' && /9\.9\.9/.test(u.detail)));
    const base = tested.findings.find((x) => x.id === f.id);
    assert.ok(f.confidence < base.confidence, 'confidence is reduced for an untested version');
  }
  for (const f of unknown.findings) assert.ok(f.uncertainty.some((u) => u.kind === 'untested-model' && /version unknown/.test(u.detail)));
  for (const f of tested.findings) assert.ok(!(f.uncertainty || []).some((u) => u.kind === 'untested-model'));
});

test('[HS-006.AC04] the documented framework table is generated from, and agrees with, the registry', () => {
  const doc = readFileSync(DOC, 'utf8');
  const table = doc.split('<!-- web-framework-table:start -->')[1].split('<!-- web-framework-table:end -->')[0];
  const names = { scotty: 'Scotty', wai: 'WAI/Warp', servant: 'Servant', yesod: 'Yesod' };
  for (const [key, def] of Object.entries(HS_WEB_FRAMEWORKS)) {
    const row = table.split('\n').find((l) => l.startsWith(`| ${names[key]} |`));
    assert.ok(row, `${key} is documented`);
    assert.ok(row.includes(`\`${def.package}\``), `${key}: package`);
    assert.ok(row.includes(def.tested.join(', ')), `${key}: tested versions ${def.tested.join(', ')}`);
  }
  assert.match(doc, /Warp is a\s+server, not an authorization control/);
  assert.match(doc, /untested-model/);
});

test('[HS-006.AC04] the application spine helper normalises `f a $ b` and `f $ b`', () => {
  const ast = { t: 'op', op: '$', l: { t: 'app', f: { t: 'var', name: 'get' }, args: [{ t: 'lit', kind: 'str', v: '/x' }] }, r: { t: 'var', name: 'h' } };
  const sp = spine(ast);
  assert.equal(sp.head.name, 'get'); assert.equal(sp.args.length, 2); assert.equal(sp.args[1].name, 'h');
});
