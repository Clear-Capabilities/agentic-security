// Taint-recall PRD (80%), P4 (Tier 3 command-injection audit): catalog +
// engine fixes found while auditing why command-injection sat at 5/23
// (21.7%) despite catalog coverage existing in some form for all 9
// languages. Root causes fell into three buckets, each covered here:
//
// 1. `literalSkeletonMatchesFamily`'s CWE-78 branch (engine.js) required the
//    STATIC portion of a tainted concat to contain a shell metacharacter —
//    backwards for command injection, whose textbook shape
//    (`exec("ping " + host)`) has the attacker supply the metacharacter via
//    the TAINTED value, not the template. Removed for CWE-78 entirely (the
//    sink catalog's own APIs are already unambiguous shell-execution calls).
// 2. `argIndex: 0` on Go's `exec.Command` and C#'s `Process.Start` — both
//    checking the WRONG argument. The real dangerous shape is
//    `exec.Command("/bin/sh", "-c", tainted)` / `Process.Start("cmd.exe",
//    "/c " + tainted)`, where arg 0 is always the literal interpreter name
//    and the tainted content sits later. Widened to `argIndex: 'all'`,
//    gated by a new `match.requireLiteralArg` precision check (arg 0 must
//    literally be a shell interpreter) so the SAFE array-execve form
//    (`exec.Command("ping", "-c", "1", host)`, `ProcessStartInfo` with
//    `ArgumentList`) does not spuriously fire.
// 3. Uncataloged sinks: PHP's `passthru`/`proc_open`, Ruby's backtick
//    shell-execution operator (parser-rb.js now lowers it to a synthetic
//    `__ruby_backtick_exec__` call so a normal callee-keyed sink can target
//    it).
//
// Go's exec.Command chained form (`exec.Command(...).Output()`) additionally
// needed a "terminal segment shift" catalog fix (same pattern as
// kt-xpath-evaluate/java-spel-getvalue/go-r-uquery-get elsewhere in this
// PRD) — see go-exec-command-output/-run/-combinedoutput/-start below.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-cmdi-p4-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('java-runtime-exec: exec("ping " + host) fires despite no shell metacharacter in the static prefix', async () => {
  const dir = mkTmp('java', 'Ping.java', `
import org.springframework.web.bind.annotation.RequestParam;
class Ping {
  void run(@RequestParam String host) throws Exception {
    Runtime.getRuntime().exec("ping " + host);
  }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected Command Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('go-os-exec-command (3-arg /bin/sh -c form, chained .Output()) fires on the tainted shell-string argument', async () => {
  const dir = mkTmp('go', 'main.go', `
package main
import "os/exec"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.Command("/bin/sh", "-c", "ping -c 1 " + host).Output()
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected Command Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('go-os-exec-command precision: the array-execve form (no shell) does not fire even with a tainted arg', async () => {
  const dir = mkTmp('go-clean', 'main.go', `
package main
import "os/exec"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.Command("ping", "-c", "1", host).Output()
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /command injection/i.test(f.vuln)).length, 0,
    `the argv-array form (no shell interpretation) must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('cs-process-start: Process.Start("cmd.exe", "/c " + tainted) fires on the tainted arguments string', async () => {
  const dir = mkTmp('cs', 'Convert.cs', `
using System.Diagnostics;
public class Convert {
  public void Run() {
    var f = Request.QueryString["file"];
    Process.Start("cmd.exe", "/c convert " + f);
  }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected Command Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-process-start precision: Process.Start(psi) with a ProcessStartInfo.ArgumentList does not fire', async () => {
  const dir = mkTmp('cs-clean', 'Convert.cs', `
using System.Diagnostics;
public class Convert {
  public void Run() {
    var f = Request.QueryString["file"];
    var psi = new ProcessStartInfo("convert") { ArgumentList = { f, "/tmp/out.png" } };
    Process.Start(psi);
  }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /command injection/i.test(f.vuln)).length, 0,
    `the ArgumentList array form must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('php-passthru: passthru("gzip " . $file) fires on $_POST-derived taint', async () => {
  const dir = mkTmp('php', 'send.php', `<?php
$file = $_POST['file'];
passthru("gzip " . $file);
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected Command Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-backtick-exec: `` `finger #{user}` `` fires on params-derived taint', async () => {
  const dir = mkTmp('rb', 'app.rb', `
require 'sinatra'
get '/who' do
  user = params[:user]
  \`finger #{user}\`
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected Command Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-backtick-exec precision: a hardcoded backtick command does not fire', async () => {
  const dir = mkTmp('rb-clean', 'app.rb', `
def run
  \`ls -la\`
end
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /command injection/i.test(f.vuln)).length, 0,
    `a literal-only backtick command must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});
