// Ruby + PHP structural (taint-independent) injection detectors — PRD Tier 1.
// Closes corpus FNs where the value is routed through a local var first
// (params[:x] / $r->query->get), so the existing token-on-sink rules miss it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRuby } from '../src/sast/ruby.js';
import { scanPhp } from '../src/sast/php.js';
import { scanCSRF } from '../src/sast/csrf.js';

const has = (f, cwe) => f.some(x => x.cwe === cwe);
const noneCwe = (f, cwe) => f.filter(x => x.cwe === cwe).length === 0;

test('Ruby SQLi — ActiveRecord .where with #{} interpolation (CWE-89)', () => {
  assert.ok(has(scanRuby('u.rb', 'def i; name = params[:name]; User.where("name = \'#{name}\'"); end'), 'CWE-89'));
  // parameterized → clean
  assert.ok(noneCwe(scanRuby('u.rb', "def i; name = params[:name]; User.where('name = ?', name); end"), 'CWE-89'));
});

test('Ruby cmdi — backtick with #{} interpolation (CWE-78)', () => {
  assert.ok(has(scanRuby('app.rb', 'get("/who"){ user = params[:user]; `finger #{user}` }'), 'CWE-78'));
  // array-form Open3 → clean
  assert.ok(noneCwe(scanRuby('app.rb', "get('/who'){ user = params[:user]; out,_ = Open3.capture2('finger', user); out }"), 'CWE-78'));
});

test('PHP cmdi — shell_exec with concat / $interp (CWE-78)', () => {
  assert.ok(has(scanPhp('C.php', "<?php \$f = \$r->query->get('file'); return shell_exec('gzip ' . \$f);"), 'CWE-78'));
  assert.ok(has(scanPhp('C.php', '<?php $f = $r->query->get("file"); return shell_exec("gzip $f");'), 'CWE-78'));
  // array-form proc_open → clean
  assert.ok(noneCwe(scanPhp('C.php', "<?php \$f = \$r->query->get('file'); proc_open(['gzip', \$f], [], \$p);"), 'CWE-78'));
});

test('PHP SQLi — DB::raw / whereRaw with concat or $interp (CWE-89)', () => {
  assert.ok(has(scanPhp('U.php', '<?php $name = $request->input("name"); return DB::select(DB::raw("SELECT * FROM users WHERE name=\'" . $name . "\'"));'), 'CWE-89'));
  // parameter bindings → clean
  assert.ok(noneCwe(scanPhp('U.php', "<?php \$name = \$request->input('name'); return DB::select('SELECT * FROM users WHERE name=?', [\$name]);"), 'CWE-89'));
});

test('PHP SQLi — deprecated mysql_query with concat (CWE-89)', () => {
  // $_GET routed through a local var, then concatenated into mysql_query — the
  // legacy mysql_* family (no `i`) was previously uncovered.
  assert.ok(has(scanPhp('q.php', `<?php $user = $_GET['user']; $r = mysql_query("SELECT * FROM users WHERE name='" . $user . "'");`), 'CWE-89'));
  // parameterized prepared statement → clean
  assert.ok(noneCwe(scanPhp('q.php', '<?php $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?"); $stmt->execute([$user]);'), 'CWE-89'));
});

test('Symfony CSRF — POST-body controller with no token check; guarded clean', () => {
  const vuln = '<?php class T { public function transfer(Request $r){ $a = $r->request->get("amount"); return new Response("ok " . $a); } }';
  assert.ok(scanCSRF('T.php', vuln).some((f) => f.cwe === 'CWE-352'));
  // isCsrfTokenValid present → suppressed
  const safe = '<?php class T { public function transfer(Request $r){ if(!$this->isCsrfTokenValid("t",$r->request->get("_token"))) throw new Exception(); $a=$r->request->get("amount"); return new Response("ok ".$a); } }';
  assert.ok(scanCSRF('T.php', safe).every((f) => f.cwe !== 'CWE-352'));
  // token-auth (Bearer / Authorization header) controller → CSRF-exempt
  const api = '<?php class T { public function transfer(Request $r){ $t=$r->headers->get("Authorization"); $a=$r->request->get("amount"); return new Response("ok ".$a); } }';
  assert.ok(scanCSRF('T.php', api).every((f) => f.cwe !== 'CWE-352'));
});

test('no false positives on clean Ruby / PHP', () => {
  assert.deepEqual(scanRuby('ok.rb', 'def add(a,b); a + b; end'), []);
  assert.deepEqual(scanPhp('ok.php', '<?php function add($a,$b){ return $a + $b; }'), []);
});
