// Haskell parity outside the core engine: the MCP tools, capability classification, attack-taxonomy and compliance family
// aliases, and the entry-point inventory. Each test pins BOTH directions (the Haskell case works, and the near miss does not).
// The matrix these cells belong to is docs/language-parity-haskell.md.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildSnapshot } from '../../src/language/haskell-sca.js';
import { classifyExecutable } from '../../src/capabilities/decide.js';
import { annotateAttackTaxonomy } from '../../src/posture/attack-taxonomy.js';
import { resolveFamilyKeys } from '../../src/posture/family-resolve.js';
import { buildEntrypointInventory } from '../../src/posture/entrypoint-inventory.js';
import { addedDatabaseImports, loadLanguageProject, languageFixPreview } from '../../src/language/context.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const MCP = path.join(SCANNER, 'bin', 'agentic-security-mcp.js');
const HSEC_DIR = path.join(SCANNER, 'test', 'fixtures', 'hackage-advisories', 'records');

const mk = (files) => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hsparity-')));
  for (const [rel, text] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true }); fs.writeFileSync(path.join(d, rel), text); }
  return d;
};
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const envFor = (dir, extra = {}) => { const e = { ...process.env, NO_COLOR: '1', AGENTIC_SECURITY_OFFLINE: '1', HOME: dir, ...extra }; delete e.NODE_TEST_CONTEXT; delete e.XDG_CONFIG_HOME; return e; };
const scan = (dir, extra = {}) => spawnSync(process.execPath, [CLI, 'scan', dir, '--format', 'json', '--no-provenance'], { encoding: 'utf8', env: envFor(dir, extra), timeout: 240_000, maxBuffer: 1 << 28 });
const call = (id, name, args) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
function mcp(dir, requests, extra = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [MCP, '--root', dir], { stdio: ['pipe', 'pipe', 'pipe'], env: envFor(dir, extra) });
    let out = '';
    c.stdout.on('data', (d) => { out += d; });
    const init = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } } };
    for (const q of [init, ...requests]) c.stdin.write(`${JSON.stringify(q)}\n`);
    const want = requests.length + 1; const t0 = Date.now();
    const iv = setInterval(() => {
      if (out.trim().split('\n').filter(Boolean).length >= want || Date.now() - t0 > 90_000) {
        clearInterval(iv); c.stdin.end();
        setTimeout(() => { c.kill('SIGKILL'); const by = new Map(out.trim().split('\n').filter(Boolean).map((l) => { const m = JSON.parse(l); return [m.id, m]; })); resolve(by); }, 200);
      }
    }, 50);
  });
}
const body = (by, id) => { const m = by.get(id); return m.result.isError ? { error: m.result.content[0].text } : JSON.parse(m.result.content[0].text); };

const CABAL = 'cabal-version: 3.0\nname: app\nversion: 0.1\nbuild-type: Simple\nexecutable app\n  main-is: Main.hs\n  hs-source-dirs: src\n  build-depends: base, scotty, sqlite-simple, postgresql-simple, process\n';
const HS_SQLITE = [
  '{-# LANGUAGE OverloadedStrings #-}', 'module Main (main) where', 'import Data.String (fromString)', 'import Database.SQLite.Simple', 'import Web.Scotty', '',
  'lookupOrder :: Connection -> String -> IO [Only String]',
  'lookupOrder conn ref = query_ conn (fromString ("SELECT status FROM orders WHERE ref = \'" ++ ref ++ "\'"))', '',
  'main :: IO ()', 'main = do', '  conn <- open "orders.db"', '  scotty 3000 $ do', '    get "/orders/:ref" $ do', '      ref <- param "ref"', '      rows <- liftIO (lookupOrder conn ref)', '      json (map fromOnly rows)', ''].join('\n');
const HS_PG = HS_SQLITE.replace('import Database.SQLite.Simple', 'import Database.PostgreSQL.Simple (Connection, Only(..), query_, connectPostgreSQL)').replace('open "orders.db"', 'connectPostgreSQL "dbname=orders"');

// ── MCP: query_taint and explain_finding on a Haskell taint finding ──────────────────────────────
test('[parity] MCP query_taint matches a Haskell taint path by its source and sink, and not an unrelated pair; explain_finding returns the flow steps', async () => {
  const dir = mk({ 'app.cabal': CABAL, 'src/Main.hs': HS_SQLITE });
  try {
    const r = scan(dir); assert.equal(r.status, 3, r.stderr);
    const f = JSON.parse(r.stdout).findings.find((x) => x.parser === 'IR-TAINT' && x.cwe === 'CWE-89');
    assert.ok(f && Array.isArray(f.chain) && f.chain.length >= 2, 'the Haskell taint finding records its flow as a chain');
    const by = await mcp(dir, [
      call(1, 'query_taint', { source: 'request parameter', sink: 'query_' }),
      call(2, 'query_taint', { source: 'request parameter', sink: 'callCommand' }),
      call(3, 'query_taint', { source: 'no-such-source', sink: 'query_' }),
      call(4, 'explain_finding', { finding_id: f.id }),
    ]);
    const hit = body(by, 1);
    assert.ok(hit.totalMatches >= 1 && hit.matches.some((m) => m.id === f.id), 'the real path is found');
    assert.ok(hit.matches[0].trace.length >= 2 && hit.matches[0].trace.some((s) => s.kind === 'sink'), 'and returned with its steps');
    assert.equal(body(by, 2).totalMatches, 0, 'a sink the flow does not reach is not matched');
    assert.equal(body(by, 3).totalMatches, 0, 'a source the flow does not start at is not matched');
    const ex = body(by, 4);
    assert.ok(Array.isArray(ex.trace) && ex.trace.length >= 2 && ex.trace.every((s) => s.file === 'src/Main.hs'), 'explain_finding carries the source-to-sink steps, not null');
  } finally { rm(dir); }
});

// ── Fix preview: no import of a database library the file did not use ───────────────────────────
test('[parity] the SQL fix is refused when it would import a database library the file did not use, and still offered when the file already uses it', async () => {
  const bad = mk({ 'app.cabal': CABAL, 'src/Main.hs': HS_SQLITE });
  const ok = mk({ 'app.cabal': CABAL, 'src/Main.hs': HS_PG });
  try {
    for (const [d, label] of [[bad, 'sqlite'], [ok, 'postgres']]) { const r = scan(d); assert.equal(r.status, 3, r.stderr); assert.ok(label); }
    const sqlOf = (d) => JSON.parse(fs.readFileSync(path.join(d, '.agentic-security', 'last-scan.json'), 'utf8')).findings.find((x) => x.parser === 'IR-TAINT' && x.cwe === 'CWE-89');
    const pb = await languageFixPreview(sqlOf(bad), loadLanguageProject(bad).files);
    assert.equal(pb.ok, false); assert.equal(pb.status, 'blocked');
    assert.match(pb.reason, /Database\.PostgreSQL\.Simple/); assert.match(pb.reason, /refused rather than guessed/);
    const po = await languageFixPreview(sqlOf(ok), loadLanguageProject(ok).files);
    assert.equal(po.ok, true, `a file already on postgresql-simple is still fixed (${po.reason})`);
    assert.doesNotMatch(po.after, /import Database\.SQLite/);
    // through MCP: no autofix patch with a foreign import reaches the agent
    const by = await mcp(bad, [call(1, 'synthesize_fix', { finding_id: sqlOf(bad).id })]);
    const sy = body(by, 1);
    assert.equal(sy.autofix, null, 'no deterministic patch is offered'); assert.equal(sy.languageFix.status, 'blocked');
  } finally { rm(bad); rm(ok); }
  assert.deepEqual(addedDatabaseImports({ before: 'import Database.SQLite.Simple\n', after: 'import Database.SQLite.Simple\nimport Database.PostgreSQL.Simple (Only)\n' }), ['Database.PostgreSQL.Simple']);
  assert.deepEqual(addedDatabaseImports({ before: 'import Database.PostgreSQL.Simple (query_)\n', after: 'import Database.PostgreSQL.Simple (query_, query, Only)\n' }), [], 'extending an existing import is not a new library');
  assert.deepEqual(addedDatabaseImports({ before: 'import Data.List\n', after: 'import Data.List\nimport Data.String (fromString)\n' }), [], 'a non-database import is not this rule');
});

// ── MCP SCA upgrade for a Hackage dependency ────────────────────────────────────────────────────
test('[parity] MCP synthesize_sca_upgrade previews and apply_sca_upgrade writes a Hackage constraint edit, never claiming it verified', async () => {
  const rec = JSON.parse(fs.readFileSync(path.join(HSEC_DIR, fs.readdirSync(HSEC_DIR).find((n) => JSON.parse(fs.readFileSync(path.join(HSEC_DIR, n), 'utf8')).id === 'HSEC-2023-0004')), 'utf8'));
  const cabal = 'cabal-version: 3.0\nname: demo\nversion: 0.1.0.0\nbuild-type: Simple\n\nlibrary\n  exposed-modules: Lib\n  hs-source-dirs: src\n  build-depends:\n      base >=4.14 && <5\n    , xml-conduit >=1.9 && <2\n  default-language: Haskell2010\n';
  const dir = mk({ 'demo.cabal': cabal, 'cabal.project': 'packages: .\n', 'cabal.project.freeze': 'constraints: xml-conduit ==1.9.0.0\n', 'src/Lib.hs': 'module Lib where\nimport Text.XML\nx :: Int\nx = 1\n' });
  try {
    fs.writeFileSync(path.join(dir, 'adv.json'), JSON.stringify(buildSnapshot([rec], new Date().toISOString())));
    const extra = { AGENTIC_SECURITY_HACKAGE_ADVISORIES: path.join(dir, 'adv.json') };
    const r = scan(dir, extra); assert.ok([2, 3].includes(r.status), r.stderr);
    const f = JSON.parse(r.stdout).findings.find((x) => x.package === 'xml-conduit');
    assert.ok(f && f.ecosystem === 'hackage' && f.type === 'vulnerable_dep');
    assert.equal(f.reachabilityTier, 'import-reachable', 'the report keeps the reachability tier, not a bare "unknown"');
    assert.deepEqual(f.reachability.modules, ['Text.XML']); assert.match(f.reachability.reason, /unknown/);
    fs.writeFileSync(path.join(dir, 'src', 'Lib.hs'), 'module Lib where\nx :: Int\nx = 1\n');
    const f2 = JSON.parse(scan(dir, extra).stdout).findings.find((x) => x.package === 'xml-conduit');
    assert.equal(f2.reachabilityTier, 'not-imported', 'the same advisory with no import of the package is not import-reachable');
    const by = await mcp(dir, [call(1, 'synthesize_sca_upgrade', { finding_id: f.id }), call(2, 'synthesize_fix', { finding_id: f.id }), call(3, 'apply_sca_upgrade', { finding_id: f.id, confirm: false })], extra);
    const pre = body(by, 1);
    assert.equal(pre.mode, 'source-edit'); assert.equal(pre.verified, false);
    assert.match(pre.languageUpgrade.diff, /xml-conduit >= 1\.9\.1\.0/); assert.match(pre.languageUpgrade.tier, /not re-resolved/);
    assert.equal(fs.readFileSync(path.join(dir, 'demo.cabal'), 'utf8'), cabal, 'the preview writes nothing');
    assert.equal(body(by, 2).languageFix.status, 'use-sca-upgrade', 'synthesize_fix names the right tool instead of answering null');
    assert.equal(body(by, 3).applied, false, 'without confirm nothing is applied');
    const by2 = await mcp(dir, [call(1, 'apply_sca_upgrade', { finding_id: f.id, confirm: true })], extra);
    const done = body(by2, 1);
    assert.equal(done.applied, true); assert.equal(done.verified, false); assert.equal(done.testsRun, false);
    assert.match(fs.readFileSync(path.join(dir, 'demo.cabal'), 'utf8'), /xml-conduit >= 1\.9\.1\.0 && < 2/);
    const undo = spawnSync(process.execPath, [CLI, 'undo', '--root', dir], { cwd: dir, encoding: 'utf8', env: envFor(dir, extra), timeout: 120_000 });
    assert.equal(undo.status, 0, undo.stderr);
    assert.equal(fs.readFileSync(path.join(dir, 'demo.cabal'), 'utf8'), cabal, 'the edit is recorded in the fix history and undo restores it');
  } finally { rm(dir); }
});

// ── Capabilities: the Haskell and Nix toolchains are interpreters ───────────────────────────────
test('[parity] capability enforcement treats the Haskell and Nix toolchains as code-running launchers, and not a linter', () => {
  for (const n of ['ghc', 'ghci', 'runghc', 'runhaskell', 'cabal', 'stack', 'ghc-9.14.1', 'runghc-9.14.1', 'cabal-3.14', 'nix', 'nix-build', 'nix-shell', 'nix-instantiate']) {
    assert.equal(classifyExecutable(path.join('/nonexistent-bin', n)).interpreter, true, `${n} is an interpreter`);
  }
  for (const n of ['hlint', 'ghcid', 'ghc-pkg-notes', 'cabal-fmt', 'stylish-haskell']) {
    assert.equal(classifyExecutable(path.join('/nonexistent-bin', n)).interpreter, false, `${n} is not classified as an interpreter by name`);
  }
});

// ── Attack taxonomy and compliance family names ────────────────────────────────────────────────
test('[parity] Haskell finding families reach the ATT&CK mapping and the compliance families they evidence, and unrelated families stay unmapped', () => {
  const fs_ = [{ family: 'missing-authentication' }, { family: 'weak-randomness' }, { family: 'tls-validation' }, { family: 'hardcoded-credentials' }, { family: 'password-hashing' }, { family: 'weak-hash' }, { family: 'broken-object-authorization' }, { family: 'sensitive-logging' }, { family: 'unsafe-boundary' }, { family: 'weak-crypto' }];
  annotateAttackTaxonomy(fs_);
  const mapped = (fam) => Array.isArray(fs_.find((f) => f.family === fam).attck);
  for (const fam of ['missing-authentication', 'weak-randomness', 'tls-validation', 'hardcoded-credentials', 'password-hashing', 'weak-hash', 'broken-object-authorization']) assert.ok(mapped(fam), `${fam} is mapped`);
  for (const fam of ['sensitive-logging', 'unsafe-boundary']) assert.ok(!mapped(fam), `${fam} has no counterpart and stays unmapped (listed, not hidden)`);
  assert.ok(!mapped('weak-crypto'), 'weak-crypto is shared with other languages and covers hashes too: deliberately not aliased to a cipher technique');
  const emitted = ['hardcoded-credentials', 'tls-validation', 'cookie-attributes', 'sql-injection'];
  assert.deepEqual(resolveFamilyKeys('hardcoded-secret', emitted), ['hardcoded-credentials']);
  assert.deepEqual(resolveFamilyKeys('crypto-tls-no-verify', emitted), ['tls-validation']);
  assert.deepEqual(resolveFamilyKeys('session-cookie-missing-secure-flag', emitted), ['cookie-attributes']);
  assert.deepEqual(resolveFamilyKeys('hardcoded-secret', ['tls-validation', 'sql-injection']), [], 'no cross-talk between unrelated families');
});

// ── Entry-point inventory ───────────────────────────────────────────────────────────────────────
test('[parity] the entry-point inventory names a Haskell route by its handler or its route, never "[object Object]"', () => {
  const routes = [
    { method: 'GET', path: '/orders/:ref', file: 'src/Main.hs', line: 30, hasAuth: false, language: 'haskell', handler: { kind: 'inline', name: '<inline>' } },
    { method: 'POST', path: '/x', file: 'src/Main.hs', line: 34, hasAuth: false, language: 'haskell', handler: { kind: 'named', name: 'createOrder' } },
    { method: 'POST', path: '/hook', file: 'src/Main.hs', line: 40, hasAuth: false, language: 'haskell', handler: { kind: 'named', name: 'onStripeWebhook' } },
    { method: 'GET', path: '/js', file: 'app.js', line: 3, hasAuth: false, handler: 'listJobs' },
  ];
  const inv = buildEntrypointInventory({}, { routes, findings: [] });
  const by = (line, file) => inv.entrypoints.find((e) => e.line === line && e.file === file);
  assert.equal(by(30, 'src/Main.hs').name, 'GET /orders/:ref');
  assert.equal(by(34, 'src/Main.hs').name, 'createOrder');
  assert.equal(by(40, 'src/Main.hs').type, 'webhook', 'the webhook test reads the handler name');
  assert.equal(by(3, 'app.js').name, 'listJobs', 'a string handler is unchanged');
  assert.ok(!JSON.stringify(inv).includes('[object Object]'));
});
