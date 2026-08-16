// Taint-recall PRD (80%): LDAP-injection sink catalog entries added across
// all languages the corpus's ldap-injection family covers — previously
// only java+cs had entries, so this family measured 0/10 despite the vuln
// class existing across every one of these languages. Also exercises a
// real parser-rb.js fix (keyword-argument lowering) this family surfaced.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-ldap-catalog-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('kt-ldap-search: DirContext.search(base, concatenated, controls) fires LDAP Injection via IR-TAINT', async () => {
  const dir = mkTmp('kt', 'Directory.kt', `
import javax.naming.directory.*
import javax.servlet.http.HttpServletRequest

class Directory {
    fun find(ctx: DirContext, uid: String): NamingEnumeration<SearchResult> {
        return ctx.search("ou=users,dc=corp", "(uid=" + uid + ")", SearchControls())
    }
    fun handler(ctx: DirContext, request: HttpServletRequest): NamingEnumeration<SearchResult> {
        return find(ctx, request.getParameter("uid"))
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(f.vuln)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-ldap-search: ldapjs client.search(base, {filter: concatenated}, cb) fires LDAP Injection via IR-TAINT', async () => {
  const dir = mkTmp('js', 'lookup.js', `
const ldap = require('ldapjs');
module.exports = (req, res) => {
  const client = ldap.createClient({ url: 'ldap://corp' });
  client.search('ou=users', { filter: '(uid=' + req.query.user + ')' }, (e, r) => res.send(r));
};
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(f.vuln)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('py-ldap-search-s: python-ldap search_s(base, scope, concatenated) fires LDAP Injection via IR-TAINT', async () => {
  const dir = mkTmp('py', 'lookup.py', `
import ldap

def search(conn, uid):
    return conn.search_s('ou=users', ldap.SCOPE_SUBTREE, '(uid=' + uid + ')')

def handler(conn, request):
    return search(conn, request.args.get("uid"))
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(f.vuln)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-net-ldap-search: net/ldap Connection#search(base:, filter:) fires LDAP Injection via IR-TAINT (keyword-argument shape)', async () => {
  const dir = mkTmp('rb', 'directory.rb', `
require "net/ldap"

class Directory
  def find(conn, uid)
    conn.search(base: "ou=users,dc=corp", filter: "(uid=#{uid})")
  end

  def handler(conn, params)
    find(conn, params[:uid])
  end
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(f.vuln)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-ldap-search: ldap_search($ds, $base, concatenated) fires LDAP Injection via IR-TAINT', async () => {
  const dir = mkTmp('php', 'lookup.php', `<?php
$ds = ldap_connect("ldap://corp");
$uid = $_GET["uid"];
$result = ldap_search($ds, "ou=users,dc=corp", "(uid=" . $uid . ")");
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(f.vuln)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('go-ldap-newsearchrequest: ldap.NewSearchRequest(..., concatenated, ...) fires LDAP Injection via IR-TAINT', async () => {
  const dir = mkTmp('go', 'directory.go', `
package directory

import (
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

func search(conn *ldap.Conn, uid string) (*ldap.SearchResult, error) {
	req := ldap.NewSearchRequest("ou=users,dc=corp", ldap.ScopeWholeSubtree, 0, 0, 0, false, "(uid="+uid+")", nil, nil)
	return conn.Search(req)
}

func Handler(w http.ResponseWriter, r *http.Request, conn *ldap.Conn) (*ldap.SearchResult, error) {
	return search(conn, r.URL.Query().Get("uid"))
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(f.vuln)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('parser-rb keyword-argument regression: a ternary is not MIS-parsed as a keyword arg (ternary support itself is a separate, pre-existing gap — unchanged either way)', async () => {
  const { parseRubyFile } = await import('../src/ir/parser-rb.js');
  const ir = parseRubyFile('t.rb', `
def f(cond, a, b)
  x = cond ? a : b
  return x
end
`);
  const fn = ir.functions.find(f => f.name === 'f');
  assert.ok(fn, 'expected function f to parse');
  const assigns = Object.values(fn.cfg.nodes).filter(n => n.kind === 'assign');
  const xAssign = assigns.find(a => a.target === 'x');
  assert.ok(xAssign, `expected an assign to x, got: ${JSON.stringify(assigns)}`);
  // The new kwarg regex requires the colon to immediately follow the
  // identifier (no space) — "cond ? a : b" has a space before its colon,
  // so it must not be split into a bogus {key: "cond ? a", value: "b"}
  // pair. Confirms the regex's anchoring is safe, not that ternaries parse
  // (they don't, before or after this change — a separate, untouched gap).
  assert.equal(xAssign.source.kind, 'unknown');
});

test('parser-rb keyword-argument regression: multiple keyword args in one call each keep their own value', async () => {
  const { parseRubyFile } = await import('../src/ir/parser-rb.js');
  const ir = parseRubyFile('t.rb', `
def f(a, b)
  conn.search(base: a, filter: b)
end
`);
  const fn = ir.functions.find(f => f.name === 'f');
  const call = Object.values(fn.cfg.nodes).find(n => n.kind === 'call' && n.callee === 'conn.search');
  assert.ok(call, 'expected the conn.search call node');
  assert.deepEqual(call.args.map(a => a.kind), ['ident', 'ident']);
  assert.equal(call.args[0].name, 'a');
  assert.equal(call.args[1].name, 'b');
});
