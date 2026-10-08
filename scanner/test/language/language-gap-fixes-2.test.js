// Detection gaps found by the second unseen-shape measurement, fixed as general capabilities and pinned in BOTH directions: the shape
// that was missed or wrongly reported is now right, and its neighbour that must not change still does not. The unseen set is consumed,
// so none of these fixtures is a corpus case: each is written here, and the engine reads no label and no fixture name.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { analyzeNixosHardening } from '../../src/language/nixos-hardening.js';
import { resolveNixosConfig } from '../../src/language/nixos-module-resolver.js';
import { runScan } from '../../src/runScan.js';

const hs = (imports, body) => `module M where\n\n${imports.join('\n')}\n\n${body}\n`;

async function scan(file, text) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gapfix2-')));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    fs.writeFileSync(path.join(dir, file), text);
    const r = await runScan(dir, { deep: true });
    return [...(r.scan.findings || []), ...(r.scan.secrets || [])].filter((f) => f.severity !== 'info');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const cwes = (fs_) => fs_.map((f) => f.cwe);
const count = (fs_, cwe) => fs_.filter((f) => f.cwe === cwe).length;

// ── resource limits: the CWE for a missing limit is 770 ─────────────────────────

test('request body: reading it whole is CWE-770 (a missing limit), like the sibling unbounded-read rules; a visible size limit lowers it', () => {
  const imp = ['import Network.Wai (Request, strictRequestBody)', 'import qualified Data.ByteString.Lazy as BL'];
  const open = analyzeHaskellRules({ 'M.hs': hs(imp, 'receive :: Request -> IO BL.ByteString\nreceive req = strictRequestBody req') }).findings;
  assert.deepEqual(open.map((f) => f.rule), ['hs-unbounded-request-body']);
  assert.equal(open[0].cwe, 'CWE-770');
  assert.equal(open[0].severity, 'medium');
  const limited = analyzeHaskellRules({ 'M.hs': hs([...imp, 'import Network.Wai.Middleware.RequestSizeLimit (requestSizeLimitMiddleware, defaultRequestSizeLimitSettings)'],
    'app :: Request -> IO BL.ByteString\napp req = strictRequestBody req\n\nguarded = requestSizeLimitMiddleware defaultRequestSizeLimitSettings') }).findings;
  assert.ok(limited.length === 0 || limited.every((f) => f.severity === 'low'), 'a size-limit middleware lowers the rating, it is not ignored');
  const none = analyzeHaskellRules({ 'M.hs': hs(['import Network.Wai (Request, requestMethod)'], 'verb :: Request -> String\nverb req = show (requestMethod req)') }).findings;
  assert.equal(none.length, 0, 'a handler that never reads the body is not flagged');
});

// ── SSRF: where the URL sits in a wreq call depends on the function ────────────────

test('wreq: the URL of getWith is its SECOND argument; a tainted URL is SSRF, tainted options on a constant URL are not', async () => {
  const imp = ['import qualified Network.Wreq as W', 'import Control.Lens ((&), (.~))', 'import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import qualified Data.Text.Lazy as TL'];
  const urlTainted = hs(imp, `main :: IO ()
main = scotty 3000 $ get "/proxy" $ do
  target <- param "url"
  _ <- liftIO (W.getWith W.defaults (TL.unpack target))
  text "ok"`);
  assert.ok(cwes(await scan('M.hs', urlTainted)).includes('CWE-918'), 'a tainted URL in getWith is SSRF');
  const optsTainted = hs(imp, `main :: IO ()
main = scotty 3000 $ get "/status" $ do
  tag <- param "tag"
  let opts = W.defaults & W.header "X-Trace" .~ [tag]
  _ <- liftIO (W.getWith opts "https://api.internal.example/status")
  text "ok"`);
  assert.ok(!cwes(await scan('M.hs', optsTainted)).includes('CWE-918'), 'the URL is a constant: tainted options are not a request to an attacker-chosen host');
  const plain = hs(imp, `main :: IO ()
main = scotty 3000 $ get "/proxy" $ do
  target <- param "url"
  _ <- liftIO (W.get (TL.unpack target))
  text "ok"`);
  assert.ok(cwes(await scan('M.hs', plain)).includes('CWE-918'), 'get (URL first) is unchanged');
  const session = hs([...imp, 'import qualified Network.Wreq.Session as S'], `main :: IO ()
main = S.withSession $ \\sess -> scotty 3000 $ get "/proxy" $ do
  target <- param "url"
  _ <- liftIO (S.getWith W.defaults sess (TL.unpack target))
  text "ok"`);
  assert.ok(cwes(await scan('M.hs', session)).includes('CWE-918'), 'the Session form takes the URL as its third argument');
});

// ── one flaw, one finding ─────────────────────────────────────────────────────────

test('command injection: `readCreateProcess (shell cmd)` is one flaw and is reported once; independent sinks on one line stay separate', async () => {
  const nested = hs(['import System.Process'], 'run :: String -> IO String\nrun pat = readCreateProcess (shell ("grep " ++ pat ++ " /var/log/app.log")) ""');
  const f = await scan('M.hs', nested);
  assert.equal(count(f, 'CWE-78'), 1, `one finding for the nested pair, got ${count(f, 'CWE-78')}`);
  assert.ok(f.some((x) => x.cwe === 'CWE-78' && (x.dedupedVulns || []).length >= 1), 'the collapsed sink is recorded on the survivor, not silently dropped');
  const sibling = hs(['import System.Process'], 'run :: Bool -> String -> String -> IO ()\nrun flag a b = if flag then callCommand ("ls " ++ a) else callCommand ("ls " ++ b)');
  assert.equal(count(await scan('M.hs', sibling), 'CWE-78'), 2, 'two separate sinks on one line are two findings');
});

// ── route authentication: a guard written inside the handler ──────────────────────────

const SCOTTY = ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)', 'import Data.Maybe (isNothing)', 'import Control.Monad (when)'];
const route = (guard) => hs(SCOTTY, `main :: IO ()
main = scotty 3000 $
  put "/profile/:id" $ do
${guard}
    rid <- param "id"
    conn <- liftIO (open "app.db")
    liftIO (execute conn "UPDATE profile SET seen = 1 WHERE id = ?" (Only (rid :: Int)))
    text "saved"`);

test('route auth: reading the credential and rejecting inside the handler is a guard, in each way it is commonly written', async () => {
  const forms = {
    'when ... (status >> finish)': '    h <- header "Authorization"\n    when (isNothing h) (status status401 >> finish)',
    'when ... $ do block': '    h <- header "Authorization"\n    when (isNothing h) $ do\n      status status401\n      finish',
    'case on the header': '    h <- header "Authorization"\n    case h of\n      Nothing -> status status401 >> finish\n      Just _ -> return ()',
    'status, then a separate finish': '    h <- header "Authorization"\n    when (isNothing h) $ status status401\n    when (isNothing h) finish',
  };
  for (const [name, guard] of Object.entries(forms)) assert.ok(!cwes(await scan('M.hs', route(guard))).includes('CWE-306'), `${name}: an inline guard authenticates the route`);
});

test('route auth: an inline check that does not actually protect is still reported', async () => {
  const bad = {
    'reads the header but never rejects': '    _ <- header "Authorization"',
    'sets 401 but the handler keeps running': '    h <- header "Authorization"\n    when (isNothing h) (status status401)',
    'a header that is not a credential': '    h <- header "X-Request-Id"\n    when (isNothing h) (status status401 >> finish)',
    'rejects without reading any credential': '    when False (status status401 >> finish)',
  };
  for (const [name, guard] of Object.entries(bad)) assert.ok(cwes(await scan('M.hs', route(guard))).includes('CWE-306'), `${name}: must still be reported`);
  const late = hs(SCOTTY, `main :: IO ()
main = scotty 3000 $
  put "/profile/:id" $ do
    rid <- param "id"
    conn <- liftIO (open "app.db")
    liftIO (execute conn "UPDATE profile SET seen = 1 WHERE id = ?" (Only (rid :: Int)))
    h <- header "Authorization"
    when (isNothing h) (status status401 >> finish)
    text "saved"`);
  assert.ok(cwes(await scan('M.hs', late)).includes('CWE-306'), 'a check that runs after the write is too late to protect it');
});

// ── NixOS firewall: port ranges ───────────────────────────────────────────────────────

const nixMod = (body) => `{ config, lib, ... }: {\n${body.map((l) => `  ${l}`).join('\n')}\n}`;
const harden = (body) => analyzeNixosHardening({ entry: 'configuration.nix', files: { 'configuration.nix': nixMod(body) }, target: { release: '25.05', system: 'x86_64-linux' } });
const rule = (rep, r) => rep.findings.filter((f) => f.rule === r);

test('nixos firewall: a range that opens every port is a finding, a narrow range is not, and a sensitive port inside a range is still caught', () => {
  const all = harden(['networking.firewall.enable = true;', 'networking.firewall.allowedTCPPortRanges = [ { from = 1; to = 65535; } ];']);
  assert.equal(rule(all, 'firewall-wide-port-range').length, 1);
  assert.equal(rule(all, 'firewall-wide-port-range')[0].severity, 'high');
  assert.equal(rule(all, 'firewall-wide-port-range')[0].portRange.everyPort, true);
  const wide = harden(['networking.firewall.allowedUDPPortRanges = [ { from = 20000; to = 40000; } ];']);
  assert.equal(rule(wide, 'firewall-wide-port-range')[0].severity, 'medium', 'a wide but not total range is medium');
  const narrow = harden(['networking.firewall.allowedTCPPortRanges = [ { from = 6881; to = 6999; } ];']);
  assert.equal(rule(narrow, 'firewall-wide-port-range').length, 0, 'a small range for a peer-to-peer client is not flagged');
  assert.equal(rule(narrow, 'firewall-sensitive-port').length, 0);
  const sensitive = harden(['networking.firewall.allowedTCPPortRanges = [ { from = 5400; to = 5500; } ];']);
  const s = rule(sensitive, 'firewall-sensitive-port');
  assert.equal(s.length, 1, 'PostgreSQL 5432 sits inside the range');
  assert.equal(s[0].port, 5432);
});

test('nixos firewall: a range scoped to one interface is not global; an unevaluable range is disclosed, never read as closed', () => {
  const scoped = harden(['networking.firewall.interfaces.eth1.allowedTCPPortRanges = [ { from = 1; to = 65535; } ];']);
  assert.equal(rule(scoped, 'firewall-wide-port-range').length, 0, 'interface-scoped ingress is restrictive');
  const dynamic = harden(['networking.firewall.allowedTCPPortRanges = [ { from = config.networking.lo; to = 65535; } ];']);
  assert.equal(rule(dynamic, 'firewall-wide-port-range').length, 0, 'no finding is invented for a value that cannot be read');
  assert.ok((dynamic.reconciliation?.unanalyzed || dynamic.gaps || []).some((g) => /port-ranges/.test(g.kind || '')) || JSON.stringify(dynamic).includes('firewall-port-ranges-unevaluated'), 'the range that could not be evaluated is disclosed');
});

test('nixos firewall: a service port opened by a RANGE is reported open in the firewall, not closed', () => {
  const viaRange = harden(['services.openssh.enable = true;', 'services.openssh.openFirewall = false;', 'services.openssh.settings.PermitRootLogin = "yes";', 'networking.firewall.allowedTCPPortRanges = [ { from = 20; to = 30; } ];']);
  const f = rule(viaRange, 'ssh-root-login')[0];
  assert.equal(f.exposure.ingress, 'open-in-firewall', 'port 22 is inside 20-30');
  const closed = harden(['services.openssh.enable = true;', 'services.openssh.openFirewall = false;', 'services.openssh.settings.PermitRootLogin = "yes";']);
  assert.equal(rule(closed, 'ssh-root-login')[0].exposure.ingress, 'firewall-closed', 'with no range the firewall is closed, as before');
});

test('nix evaluator: a list of attribute sets is known only when every element is', () => {
  const val = (src) => { const cfg = resolveNixosConfig({ entry: 'configuration.nix', files: { 'configuration.nix': nixMod([src]) } }); const o = cfg.options.find((x) => x.path === 'networking.firewall.allowedTCPPortRanges'); return o && o.valueKnown ? o.value : undefined; };
  assert.deepEqual(val('networking.firewall.allowedTCPPortRanges = [ { from = 1; to = 10; } { from = 20; to = 30; } ];'), [{ from: 1, to: 10 }, { from: 20, to: 30 }]);
  assert.equal(val('networking.firewall.allowedTCPPortRanges = [ { from = config.x; to = 10; } ];'), undefined, 'a reference inside makes the whole value unknown');
  assert.equal(val('networking.firewall.allowedTCPPortRanges = [ (rec { from = 1; to = from; }) ];'), undefined, 'a recursive set is not evaluated');
});
