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

test('PHP path traversal — readfile/file_get_contents with concat; basename-guarded clean', () => {
  assert.ok(has(scanPhp('d.php', `<?php $f = $_GET['file']; readfile("/var/data/" . $f);`), 'CWE-22'));
  assert.ok(has(scanPhp('d.php', `<?php $f = $_GET['file']; $c = file_get_contents("/var/data/" . $f);`), 'CWE-22'));
  // basename containment → dropped by the central guard pass (not asserted here);
  // a bare literal path must not match at all
  assert.ok(noneCwe(scanPhp('d.php', `<?php readfile("/var/data/config.txt");`), 'CWE-22'));
});

test('Ruby path traversal — File.read with interpolation/concat; literal clean', () => {
  assert.ok(has(scanRuby('f.rb', 'def show; name = params[:file]; File.read("/var/data/" + name); end'), 'CWE-22'));
  assert.ok(has(scanRuby('f.rb', 'def show; name = params[:file]; File.read("/var/data/#{name}"); end'), 'CWE-22'));
  assert.ok(noneCwe(scanRuby('f.rb', 'def show; File.read("/var/data/config.txt"); end'), 'CWE-22'));
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

test('CSRF — Go router POST fires; gorilla/csrf + bearer clean', () => {
  const has = (c) => scanCSRF('main.go', c).some((f) => f.cwe === 'CWE-352');
  assert.ok(has('package main\nimport "github.com/gin-gonic/gin"\nfunc main(){ r := gin.Default(); r.POST("/transfer", transfer); r.Run() }'));
  assert.ok(!has('package main\nimport "github.com/gorilla/csrf"\nfunc main(){ r := gin.Default(); r.POST("/transfer", transfer); http.ListenAndServe(":8080", csrf.Protect(key)(r)) }'));
  assert.ok(!has('package main\nfunc main(){ r := gin.Default(); r.GET("/list", list); r.Run() }'));
});

test('CSRF — Rails route POST/resources fires; protect_from_forgery clean', () => {
  const has = (fn, c) => scanCSRF(fn, c).some((f) => f.cwe === 'CWE-352');
  assert.ok(has('routes.rb', 'Rails.application.routes.draw do\n  post "/transfer", to: "transfers#create"\nend\n'));
  assert.ok(has('routes.rb', 'Rails.application.routes.draw do\n  resources :transfers\nend\n'));
  assert.ok(!has('c.rb', 'class T < ApplicationController\n  protect_from_forgery with: :exception\n  def create; post "/x"; end\nend\n'));
  assert.ok(!has('routes.rb', 'Rails.application.routes.draw do\n  get "/list", to: "list#index"\nend\n'));
});

// Stage 1 correctness audit: scanCSRF's whole-file gate
// (`if (csrfInScope || tokenAuthInScope) return [];`) exits before any route
// is even examined. The later per-route ±15-line window check can only ever
// see a SUBSET of what the whole file already contains — by regex-substring
// monotonicity, if the window matches the defence pattern, the whole file
// (a superset string) must already have matched it too, meaning the function
// would have already returned []. So a file with ONE protected route and
// N unprotected routes silently reported ZERO CSRF findings for any of them,
// as long as they're all in the same file as the protected one.
test('CSRF — Express: one route with inline defence does not blanket-suppress a sibling unprotected route more than 15 lines away', () => {
  const filler = Array.from({ length: 20 }, (_, i) => `// filler line ${i}`);
  const code = [
    'const express = require("express");',
    'const app = express();',
    'app.post("/safe-transfer", csrfProtection, (req, res) => { doTransfer(req.body); });',
    ...filler,
    'app.post("/unsafe-transfer", (req, res) => { doTransfer(req.body); });',
  ].join('\n');
  const unsafeLine = 3 + filler.length + 1;
  const findings = scanCSRF('app.js', code);
  assert.ok(findings.some(f => f.cwe === 'CWE-352' && f.line === unsafeLine),
    `expected a CSRF finding on the unprotected sibling route (line ${unsafeLine}), got: ${JSON.stringify(findings)}`);
  assert.ok(!findings.some(f => f.line === 3),
    'the route with inline csrfProtection must not itself be flagged');
});

test('CSRF — C# [HttpPost] fires; [ValidateAntiForgeryToken] / Bearer / [ApiController] clean', () => {
  const has = (c) => scanCSRF('C.cs', c).some((f) => f.cwe === 'CWE-352');
  assert.ok(has('public class T : Controller { [HttpPost] public IActionResult Transfer(decimal amt){ return Ok(); } }'));
  assert.ok(!has('public class T : Controller { [HttpPost] [ValidateAntiForgeryToken] public IActionResult Transfer(decimal amt){ return Ok(); } }'));
  assert.ok(!has('[ApiController]\npublic class T : ControllerBase { [HttpPost] public IActionResult Transfer(decimal amt){ return Ok(); } }'));
  assert.ok(!has('public class T : Controller { [HttpGet] public IActionResult List(){ return Ok(); } }'));
});

test('no false positives on clean Ruby / PHP', () => {
  assert.deepEqual(scanRuby('ok.rb', 'def add(a,b); a + b; end'), []);
  assert.deepEqual(scanPhp('ok.php', '<?php function add($a,$b){ return $a + $b; }'), []);
});
