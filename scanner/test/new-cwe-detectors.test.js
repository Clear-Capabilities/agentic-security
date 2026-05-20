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

test('LDAP — unrelated string concat WITHOUT LDAP context does NOT fire', () => {
  const out = scanLDAPInjection('util.js', `
function key(name) { return "(uid=" + name + ")"; }
`);
  // No LDAP context, no .search call — should be silent.
  assert.equal(out.length, 0, 'context-less concat should not be flagged');
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
