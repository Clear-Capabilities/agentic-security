// E2-06: the historical cross-language gaps named in the PRD, reproduced against THIS checkout before any patching. Each is already correct here, so nothing was
// patched; this file pins both the vulnerable case and its safe twin so a regression in either direction fails. A grid of PHP/Go/Ruby/TS cases drawn from the
// independent miss mix checks the shapes the baseline misses are concentrated in, and the one gap it found is pinned as a stated gap, not hidden.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';

setStateWritesEnabled(false);
const scan = async (file, code) => (await runFullScan({ fileContents: { [file]: code }, scanRoot: null, deep: true })).findings.filter((f) => f.file === file && f.severity !== 'info' && !/x-powered-by|Missing/i.test(f.vuln || ''));
const has = (fs, re) => fs.some((f) => re.test(f.vuln));

const LDAP_VULN = 'import javax.naming.directory.*;\npublic class A { public void find(javax.servlet.http.HttpServletRequest req, DirContext ctx) throws Exception {\n  String user = req.getParameter("user");\n  String filter = "(uid=" + user + ")";\n  ctx.search("ou=people", filter, new SearchControls());\n} }\n';
const LDAP_CONST = 'import javax.naming.directory.*;\npublic class A { public void find(DirContext ctx) throws Exception {\n  String filter = "(uid=admin)";\n  ctx.search("ou=people", filter, new SearchControls());\n} }\n';
const LDAP_MAP = 'import javax.naming.directory.*; import java.util.*;\npublic class A { static final Map<String,String> ATTRS = Map.of("uid","admin");\n public void find(DirContext ctx) throws Exception {\n  String filter = "(uid=" + ATTRS.get("uid") + ")";\n  ctx.search("ou=people", filter, new SearchControls());\n} }\n';

test('LDAP: attacker-controlled input is flagged; a constant filter and a constant attribute map are not (already correct, not patched)', async () => {
  assert.ok(has(await scan('A.java', LDAP_VULN), /LDAP Injection/));
  assert.deepEqual(await scan('A.java', LDAP_CONST), []); assert.deepEqual(await scan('A.java', LDAP_MAP), []);
});

test('C#: request input into a SQL command is flagged; the same shape built from a static string is not', async () => {
  const vuln = 'using System; using System.Data.SqlClient; using Microsoft.AspNetCore.Mvc;\npublic class C : Controller { public IActionResult Get(string id) {\n  var cmd = new SqlCommand("SELECT * FROM t WHERE id = " + id);\n  return Ok(cmd.ExecuteReader()); } }\n';
  const safe = 'using System; using System.Data.SqlClient; using Microsoft.AspNetCore.Mvc;\npublic class C : Controller { public IActionResult Get() {\n  var id = "42";\n  var cmd = new SqlCommand("SELECT * FROM t WHERE id = " + id);\n  return Ok(cmd.ExecuteReader()); } }\n';
  assert.ok(has(await scan('A.cs', vuln), /SQL Injection/)); assert.deepEqual(await scan('A.cs', safe), []);
});

test('Java: a vulnerable method and a safe method in one class are resolved separately; the later safe one does not suppress the earlier finding', async () => {
  const code = 'import java.sql.*;\npublic class B {\n public void bad(javax.servlet.http.HttpServletRequest req, Connection c) throws Exception {\n  String id = req.getParameter("id");\n  c.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id);\n }\n public void good(Connection c) throws Exception {\n  PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id=?");\n  p.setInt(1, 1); p.executeQuery();\n }\n}\n';
  const f = await scan('B.java', code); assert.ok(has(f, /SQL Injection/)); assert.ok(f.every((x) => x.line <= 5), 'nothing is reported on the safe method (lines 7 to 10)');
});

test('ASYNC: taint survives an await in JavaScript', async () => {
  const code = "const express = require('express'); const app = express(); const db = require('mysql').createConnection({});\nasync function load(req) { const v = await Promise.resolve(req.query.id); return v; }\napp.get('/u', async (req, res) => { const id = await load(req); db.query(\"SELECT * FROM t WHERE id=\" + id); res.end(); });\n";
  assert.ok(has(await scan('a.js', code), /SQL Injection/));
});

// PHP, Go, Ruby and TypeScript: the languages where the independent baseline misses concentrate. Vulnerable twin flagged, parameterised/safe twin silent.
const PAIRS = [
  ['PHP SQL', 'a.php', "<?php\n$id = $_GET['id'];\n$res = mysqli_query($conn, \"SELECT * FROM t WHERE id = \" . $id);\n", "<?php\n$id = $_GET['id'];\n$stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?');\n$stmt->execute([$id]);\n", /SQL Injection/],
  ['Go SQL', 'a.go', 'package main\nimport ("database/sql"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n id := r.URL.Query().Get("id")\n db.Query("SELECT * FROM t WHERE id = " + id)\n}\n', 'package main\nimport ("database/sql"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n id := r.URL.Query().Get("id")\n db.Query("SELECT * FROM t WHERE id = ?", id)\n}\n', /SQL Injection/],
  ['Ruby SQL', 'a.rb', 'class C < ApplicationController\n def show\n  User.where("id = #{params[:id]}")\n end\nend\n', 'class C < ApplicationController\n def show\n  User.where("id = ?", params[:id])\n end\nend\n', /SQL Injection/],
  ['TS SQL', 'a.ts', "import express from 'express';\nconst app = express();\napp.get('/u', async (req: any, res: any) => {\n const id: string = req.query.id as string;\n await db.query(`SELECT * FROM t WHERE id = ${id}`);\n res.end();\n});\n", "import express from 'express';\nconst app = express();\napp.get('/u', async (req: any, res: any) => {\n await db.query('SELECT * FROM t WHERE id = $1', [7]);\n res.end();\n});\n", /SQL Injection/],
];
for (const [name, file, vuln, safe, re] of PAIRS) {
  test(`${name}: vulnerable twin flagged, safe twin silent`, async () => { assert.ok(has(await scan(file, vuln), re)); assert.ok(!has(await scan(file, safe), re)); });
}
const SINGLES = [
  ['PHP command', 'a.php', "<?php\n$f = $_GET['f'];\nsystem('cat ' . $f);\n", /Command Injection/], ['PHP file inclusion', 'a.php', "<?php\n$p = $_GET['page'];\ninclude($p . '.php');\n", /File Inclusion/],
  ['Go command', 'a.go', 'package main\nimport ("os/exec"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request) {\n f := r.FormValue("f")\n exec.Command("sh", "-c", "cat "+f).Run()\n}\n', /Command Injection/],
  ['Go path', 'a.go', 'package main\nimport ("os"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request) {\n f := r.URL.Query().Get("f")\n os.ReadFile("/data/" + f)\n}\n', /Path Traversal/],
  ['Go SSRF', 'a.go', 'package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request) {\n u := r.URL.Query().Get("u")\n http.Get(u)\n}\n', /SSRF/],
  ['Ruby redirect', 'a.rb', 'class C < ApplicationController\n def go\n  redirect_to params[:url]\n end\nend\n', /Open Redirect/],
  ['TS NestJS command', 'a.ts', "import { Controller, Get, Query } from '@nestjs/common';\nimport { exec } from 'child_process';\n@Controller()\nexport class C { @Get('r') run(@Query('d') d: string) { exec('ls ' + d); } }\n", /Command Injection/],
  ['TS SSRF', 'a.ts', "import express from 'express';\nconst app = express();\napp.get('/f', async (req, res) => { const r = await fetch(req.query.u as string); res.send(await r.text()); });\n", /SSRF/],
];
for (const [name, file, code, re] of SINGLES) test(`${name}: flagged`, async () => assert.ok(has(await scan(file, code), re)));

test('A SANITIZED FLOW IS KEPT AND LABELLED, NOT DROPPED: PHP escapeshellarg and htmlspecialchars, and Python shlex.quote, still produce a finding marked sanitized (stated behaviour, the same in every language)', async () => {
  const cases = [['a.php', "<?php\n$f = escapeshellarg($_GET['f']);\nsystem('cat ' . $f);\n", 'escapeshellarg'], ['a.php', "<?php\necho '<div>' . htmlspecialchars($_GET['q']) . '</div>';\n", 'htmlspecialchars'],
    ['a.py', "import subprocess, shlex\nfrom flask import request\ndef h():\n    f = shlex.quote(request.args['f'])\n    subprocess.run('cat ' + f, shell=True)\n", 'shlex.quote']];
  for (const [file, code, san] of cases) {
    const r = (await runFullScan({ fileContents: { [file]: code }, scanRoot: null, deep: true })).findings.filter((f) => f.file === file && f.parser === 'IR-TAINT');
    assert.equal(r.length, 1, san); assert.equal(r[0].sanitized, true, `${san} is recognised as the sanitizer`); assert.ok(JSON.stringify(r[0]._sanitizersOnPath).includes(san.split('.').pop()));
  }
});

test('STATED GAP: Ruby send_file with a request-built path produces no finding (the Ruby path rules look for File/IO operations); a File.read of the same path does', async () => {
  assert.deepEqual(await scan('a.rb', 'class C < ApplicationController\n def get\n  send_file File.join(\'/data\', params[:f])\n end\nend\n'), []);
  assert.deepEqual(await scan('a.rb', 'class C < ApplicationController\n def get\n  send_file "/data/#{params[:f]}"\n end\nend\n'), []);
  assert.ok(has(await scan('a.rb', 'class C < ApplicationController\n def get\n  render plain: File.read("/data/#{params[:f]}")\n end\nend\n'), /Path Traversal/));
});
