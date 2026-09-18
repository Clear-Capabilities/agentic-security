// v0.67 — detection rules for SSTI, LDAP, open-redirect, response-splitting.
//
// Each detector ships a vulnerable + clean shape; both are asserted directly
// against the detector function so a regression surfaces here even if the
// end-to-end runScan pipeline changes around them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSSTI } from '../src/sast/ssti.js';
import { scanLDAPInjection } from '../src/sast/ldap-injection.js';
import { scanOpenRedirect } from '../src/sast/open-redirect.js';
import { scanResponseSplitting } from '../src/sast/response-splitting.js';

// ─── SSTI ──────────────────────────────────────────────────────────────────

test('SSTI — Jinja2 from_string with user input fires', () => {
  const out = scanSSTI('app.py', `
from flask import Flask, request
from jinja2 import Environment
env = Environment()
def r():
    tpl = request.args.get('tpl', '')
    return env.from_string(tpl).render()
`);
  assert.ok(out.length >= 1, 'expected an SSTI finding on Jinja2 from_string');
  assert.equal(out[0].cwe, 'CWE-94');
  assert.equal(out[0].family, 'ssti');
});

test('SSTI — Handlebars.compile with user input fires', () => {
  const out = scanSSTI('app.js', `
const Handlebars = require('handlebars');
function r(req) { return Handlebars.compile(req.query.tpl)({}); }
`);
  assert.ok(out.length >= 1);
  assert.equal(out[0].cwe, 'CWE-94');
});

test('SSTI — constant template body does NOT fire', () => {
  const out = scanSSTI('app.js', `
const Handlebars = require('handlebars');
const TPL = Handlebars.compile('<h1>Hi {{name}}</h1>');
`);
  assert.equal(out.length, 0, 'constant-body compile should be safe');
});

// ─── LDAP (extended) ───────────────────────────────────────────────────────

test('LDAP — Java indirect filter via local var fires', () => {
  const out = scanLDAPInjection('Auth.java', `
import javax.naming.directory.*;
public class Auth {
  public NamingEnumeration<SearchResult> find(DirContext ctx, String name) throws Exception {
    String filter = "(uid=" + name + ")";
    return ctx.search("ou=users,dc=corp,dc=com", filter, null);
  }
}
`);
  assert.ok(out.length >= 1, 'expected an LDAP finding on indirect filter shape');
  assert.equal(out[0].cwe, 'CWE-90');
  assert.equal(out[0].family, 'ldap-injection');
});

test('LDAP — Python search_s with concatenated filter fires', () => {
  const out = scanLDAPInjection('app.py', `
import ldap
def find(name):
    conn = ldap.initialize('ldap://corp')
    return conn.search_s('ou=users,dc=corp', ldap.SCOPE_SUBTREE, '(uid=' + name + ')')
`);
  assert.ok(out.length >= 1, 'expected an LDAP finding on search_s');
  assert.equal(out[0].cwe, 'CWE-90');
});

// SARD_80_F1 W4.J13: Juliet's own convention keeps the IDENTICAL
// `"(cn=" + data + ")"` filter line in bad() and goodG2B(), only swapping
// `data`'s source (System.getenv(...) vs a hardcoded literal) — confirmed
// via the public Juliet mirror, CWE90_LDAP_Injection__Environment_01.java.
test('LDAP — Java local var whose nearest assignment is a hardcoded literal does NOT fire; a tainted one still does', () => {
  const bad = scanLDAPInjection('Auth.java', `
import javax.naming.directory.*;
public class Auth {
  public void bad(DirContext directoryContext) throws Throwable {
    String data = System.getenv("ADD");
    String search = "(cn=" + data + ")";
    directoryContext.search("", search, null);
  }
}
`);
  assert.ok(bad.length >= 1, 'expected a finding when data comes from System.getenv');
  const good = scanLDAPInjection('Auth.java', `
import javax.naming.directory.*;
public class Auth {
  public void goodG2B(DirContext directoryContext) throws Throwable {
    String data = "foo";
    String search = "(cn=" + data + ")";
    directoryContext.search("", search, null);
  }
}
`);
  assert.equal(good.length, 0, 'expected no finding when data is a hardcoded literal');
});

// SARD_80_F1 W4.C13 — same bug class as the Java test above, found in
// FILTER_INLINE_RE.cs (not FILTER_VAR_RE.cs): C#'s real Juliet corpus shape
// is `search.Filter = "..." + data + "...";`, a property ASSIGNMENT that
// Path A matches directly (confirmed via the public mirror,
// CWE90_LDAP_Injection__Connect_tcp_01.cs, which keeps this exact line
// verbatim in bad() and GoodG2B()).
test('LDAP — C# DirectorySearcher.Filter whose nearest local assignment is a hardcoded literal does NOT fire; a tainted one still does', () => {
  const bad = scanLDAPInjection('Auth.cs', `
class Auth {
  void Bad() {
    string data = Environment.GetEnvironmentVariable("ADD");
    DirectorySearcher search = new DirectorySearcher();
    search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
  }
}
`);
  assert.ok(bad.length >= 1, 'expected a finding when data comes from an environment variable');
  const good = scanLDAPInjection('Auth.cs', `
class Auth {
  void GoodG2B() {
    string data = "foo";
    DirectorySearcher search = new DirectorySearcher();
    search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
  }
}
`);
  assert.equal(good.length, 0, 'expected no finding when data is a hardcoded literal');
});

// SARD_80_F1 W4.C17 — Juliet's "make a copy of data within the same
// method" flow variant (confirmed via the public mirror,
// CWE90_LDAP_Injection__Environment_31.cs): the literal source is copied to
// a second variable, then copied BACK into a fresh same-named redeclaration
// before the sink — a one-hop bare-identifier RHS that the old
// `_nearestAssignIsLiteral` (only recognizing a direct `"literal"` string)
// could not resolve, so GoodG2B() wrongly fired.
test('LDAP — C# copy-of-a-copy: a literal reaching the sink through an intermediate variable does NOT fire; a tainted one still does', () => {
  const bad = scanLDAPInjection('Auth.cs', `
class Auth {
  void Bad() {
    string dataCopy;
    { string data; data = Environment.GetEnvironmentVariable("ADD"); dataCopy = data; }
    { string data = dataCopy; DirectorySearcher search = new DirectorySearcher(); search.Filter = "(&(objectClass=user)(employeename=" + data + "))"; }
  }
}
`);
  assert.ok(bad.length >= 1, 'expected a finding when the copied value ultimately comes from an environment variable');
  const good = scanLDAPInjection('Auth.cs', `
class Auth {
  void GoodG2B() {
    string dataCopy;
    { string data; data = "foo"; dataCopy = data; }
    { string data = dataCopy; DirectorySearcher search = new DirectorySearcher(); search.Filter = "(&(objectClass=user)(employeename=" + data + "))"; }
  }
}
`);
  assert.equal(good.length, 0, 'expected no finding when the copied value ultimately traces back to a hardcoded literal');
});

// SARD_80_F1 W4.C37 — Juliet's own "if (CONST) { data = <literal-or-
// source> } else { data = null; }" dead-code idiom (confirmed via the
// public C# Juliet mirror's own CWE90_LDAP_Injection__Connect_tcp_04.cs) —
// `null` was being treated as a disqualifying non-literal assignment,
// which is wrong independent of any dead-code question: `null` can never
// be attacker-controlled data. This bug predates and is independent of
// this session's parser-cs.js CFG work (confirmed via a direct standalone
// call bypassing runScan entirely).
test('LDAP — C# a dead `data = null;` branch does not disqualify an otherwise-all-literal value from being recognized as safe', () => {
  const good = scanLDAPInjection('Auth.cs', `
class Auth {
  void GoodG2B1() {
    string data;
    if (PRIVATE_CONST_FALSE) {
      data = null;
    } else {
      data = "foo";
    }
    DirectorySearcher search = new DirectorySearcher();
    search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
  }
}
`);
  assert.equal(good.length, 0, 'expected no finding — every REAL assignment to data is a hardcoded literal; null is never attacker-controlled');
});

test('LDAP — a genuinely non-literal assignment alongside an unrelated `null` branch still fires', () => {
  const bad = scanLDAPInjection('Auth.cs', `
class Auth {
  void Bad() {
    string data;
    if (PRIVATE_CONST_TRUE) {
      data = Environment.GetEnvironmentVariable("ADD");
    } else {
      data = null;
    }
    DirectorySearcher search = new DirectorySearcher();
    search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
  }
}
`);
  assert.ok(bad.length >= 1, 'expected a finding — data is genuinely sourced from an environment variable on the live path');
});

test('LDAP — unrelated string concat WITHOUT LDAP context does NOT fire', () => {
  const out = scanLDAPInjection('util.js', `
function key(name) { return "(uid=" + name + ")"; }
`);
  // No LDAP context, no .search call — should be silent.
  assert.equal(out.length, 0, 'context-less concat should not be flagged');
});

// ─── LDAP (cross-language: PHP / Go / C# / Ruby / Kotlin) ───────────────────

const ldapFires = (fp, code) => scanLDAPInjection(fp, code).some((f) => f.cwe === 'CWE-90');
const ldapClean = (fp, code) => scanLDAPInjection(fp, code).every((f) => f.cwe !== 'CWE-90');

test('LDAP — PHP ldap_search concat fires; ldap_escape clean', () => {
  assert.ok(ldapFires('dir.php', '<?php $u=$_GET["u"]; ldap_search($ds, $base, "(uid=" . $u . ")");'));
  assert.ok(ldapClean('dir.php', '<?php $u=ldap_escape($_GET["u"], "", LDAP_ESCAPE_FILTER); ldap_search($ds, $base, "(uid=" . $u . ")");'));
  assert.ok(ldapClean('dir.php', '<?php ldap_search($ds, $base, "(objectClass=person)");'));
});

test('LDAP — Go go-ldap concat fires; EscapeFilter clean', () => {
  assert.ok(ldapFires('dir.go', 'package main\nimport "github.com/go-ldap/ldap/v3"\nfunc s(u string){ ldap.NewSearchRequest("b",0,0,0,0,false,"(uid="+u+")",nil,nil) }'));
  assert.ok(ldapClean('dir.go', 'package main\nimport "github.com/go-ldap/ldap/v3"\nfunc s(u string){ ldap.NewSearchRequest("b",0,0,0,0,false,"(uid="+ldap.EscapeFilter(u)+")",nil,nil) }'));
});

test('LDAP — C# DirectorySearcher concat and interpolation fire; literal clean', () => {
  assert.ok(ldapFires('Dir.cs', 'using System.DirectoryServices;\nclass D { void s(string u){ var d = new DirectorySearcher(); d.Filter = "(uid=" + u + ")"; } }'));
  assert.ok(ldapFires('Dir.cs', 'using System.DirectoryServices;\nclass D { void s(string u){ var d = new DirectorySearcher(); d.Filter = $"(uid={u})"; } }'));
  assert.ok(ldapClean('Dir.cs', 'using System.DirectoryServices;\nclass D { void s(){ var d = new DirectorySearcher(); d.Filter = "(objectClass=person)"; } }'));
});

test('LDAP — Ruby net-ldap interpolation fires; literal clean', () => {
  assert.ok(ldapFires('dir.rb', 'require "net/ldap"\ndef s(u)\n  conn.search(filter: "(uid=#{u})")\nend\n'));
  assert.ok(ldapClean('dir.rb', 'require "net/ldap"\ndef s\n  conn.search(filter: "(objectClass=person)")\nend\n'));
});

test('LDAP — Kotlin JNDI concat/interpolation fires', () => {
  assert.ok(ldapFires('Dir.kt', 'import javax.naming.directory.*\nclass D { fun s(u: String, ctx: DirContext) { ctx.search("ou=users", "(uid=" + u + ")", SearchControls()) } }'));
  assert.ok(ldapFires('Dir.kt', 'import javax.naming.directory.*\nclass D { fun s(u: String, ctx: DirContext) { val f = "(uid=${u})"; ctx.search("ou=users", f, SearchControls()) } }'));
});

// ─── Open redirect ─────────────────────────────────────────────────────────

test('open-redirect — Express res.redirect with req.query fires', () => {
  const out = scanOpenRedirect('app.js', `
const express = require('express');
const app = express();
app.get('/r', (req, res) => {
  res.redirect(req.query.next);
});
`);
  assert.ok(out.length >= 1);
  assert.equal(out[0].cwe, 'CWE-601');
});

test('open-redirect — allow-list check above suppresses the finding', () => {
  const out = scanOpenRedirect('app.js', `
const express = require('express');
const app = express();
const ALLOWED = new Set(['/home', '/login']);
app.get('/r', (req, res) => {
  const target = req.query.next || '/';
  if (!ALLOWED.has(target)) return res.status(400).end();
  res.redirect(target);
});
`);
  assert.equal(out.length, 0, 'allow-list check should suppress the open-redirect flag');
});

test('open-redirect — Flask redirect with request.args fires', () => {
  const out = scanOpenRedirect('app.py', `
from flask import Flask, request, redirect
app = Flask(__name__)
def r():
    return redirect(request.args.get('next'))
`);
  assert.ok(out.length >= 1);
  assert.equal(out[0].cwe, 'CWE-601');
});

// ─── HTTP response splitting ───────────────────────────────────────────────

test('response-splitting — Java setHeader with raw param fires', () => {
  const out = scanResponseSplitting('Headers.java', `
import javax.servlet.http.*;
public class Headers {
  public void set(HttpServletResponse response, String name) {
    response.setHeader("X-User", request.getParameter(name));
  }
}
`);
  assert.ok(out.length >= 1);
  assert.equal(out[0].cwe, 'CWE-113');
  assert.equal(out[0].family, 'response-splitting');
});

test('response-splitting — Node res.setHeader with sanitization does NOT fire', () => {
  const out = scanResponseSplitting('app.js', `
app.get('/h', (req, res) => {
  const clean = req.query.x.replace(/[\\r\\n]/g, "");
  res.setHeader('X-User', clean);
});
`);
  // The .replace stripping CR/LF should suppress the flag.
  assert.equal(out.length, 0, 'CRLF strip should suppress the response-splitting flag');
});

// ─── HTTP response splitting (cross-language: PHP/Go/Ruby/C#/Kotlin) ─────────

const rsFires = (fp, code) => scanResponseSplitting(fp, code).some((f) => f.cwe === 'CWE-113');
const rsClean = (fp, code) => scanResponseSplitting(fp, code).every((f) => f.cwe !== 'CWE-113');

test('response-splitting — PHP header() with $_GET fires; literal clean', () => {
  assert.ok(rsFires('h.php', '<?php header("X-Custom: " . $_GET["v"]);'));
  assert.ok(rsClean('h.php', '<?php header("X-Custom: HIT");'));
});

test('response-splitting — Go w.Header().Set with query fires; literal clean', () => {
  assert.ok(rsFires('h.go', 'package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request){ w.Header().Set("X-Custom", r.URL.Query().Get("v")) }'));
  assert.ok(rsClean('h.go', 'package main\nimport "net/http"\nfunc h(w http.ResponseWriter){ w.Header().Set("X-Custom", "HIT") }'));
});

test('response-splitting — Ruby response.headers[…] = params fires; literal clean', () => {
  assert.ok(rsFires('h.rb', 'def show\n  response.headers["X-Custom"] = params[:v]\nend\n'));
  assert.ok(rsClean('h.rb', 'def show\n  response.headers["X-Custom"] = "HIT"\nend\n'));
});

test('response-splitting — C# Response.Headers.Add with param fires; local literal clean', () => {
  assert.ok(rsFires('H.cs', 'class H { void Set(string v){ Response.Headers.Add("X-Custom", v); } }'));
  assert.ok(rsClean('H.cs', 'class H { void Set(){ var v = "static"; Response.Headers.Add("X-Custom", v); } }'));
});

test('response-splitting — Kotlin setHeader with param fires; literal clean', () => {
  assert.ok(rsFires('H.kt', 'fun h(v: String, resp: HttpServletResponse) { resp.setHeader("X-Custom", v) }'));
  assert.ok(rsClean('H.kt', 'fun h(resp: HttpServletResponse) { resp.setHeader("X-Custom", "HIT") }'));
});
