// Java + C# structural detectors — PRD Tier 1 (closes corpus FNs where the
// flow engine sees no source on a standalone DAO/handler method).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJavaStructural } from '../src/sast/java-structural.js';
import { scanCsharpStructural } from '../src/sast/csharp-structural.js';

const has = (f, cwe) => f.some(x => x.cwe === cwe);
const none = (f, cwe) => f.filter(x => x.cwe === cwe).length === 0;

test('Java SQLi — executeQuery with string concat (CWE-89)', () => {
  assert.ok(has(scanJavaStructural('UserDao.java', 'ResultSet find(Connection c, String name){ return c.createStatement().executeQuery("SELECT * FROM u WHERE name=\'" + name + "\'"); }'), 'CWE-89'));
  assert.ok(none(scanJavaStructural('UserDao.java', 'ResultSet find(Connection c, String name){ PreparedStatement p = c.prepareStatement("SELECT * FROM u WHERE name=?"); p.setString(1,name); return p.executeQuery(); }'), 'CWE-89'));
});

// SARD_80_F1 W4.J12: Juliet's own convention keeps the IDENTICAL sink line
// in bad() and goodG2B(), only swapping a bare local variable's source
// (System.getenv(...) vs a hardcoded literal) — this taint-independent
// detector previously fired on both, since it never examined what the
// concatenated identifier actually held. Confirmed via the public Juliet
// mirror (CWE89_SQL_Injection__Environment_execute_01.java).
test('Java SQLi — a hardcoded-literal local variable is suppressed; a tainted one still fires (CWE-89)', () => {
  const bad = scanJavaStructural('S.java', 'void bad(){ String data = System.getenv("ADD"); Statement s = null; s.execute("insert into users (status) values (\'updated\') where name=\'"+data+"\'"); }');
  assert.ok(has(bad, 'CWE-89'), 'expected a finding when data comes from System.getenv');
  const good = scanJavaStructural('S.java', 'void goodG2B(){ String data = "foo"; Statement s = null; s.execute("insert into users (status) values (\'updated\') where name=\'"+data+"\'"); }');
  assert.ok(none(good, 'CWE-89'), 'expected no finding when data is a hardcoded literal');
});

test('Java SQLi — a second tainted term after a suppressible one still fires (CWE-89)', () => {
  const f = scanJavaStructural('S.java', 'void m(){ String data = "foo"; String other = System.getenv("X"); Statement s = null; s.execute("insert into t (a) values (\'"+data+"\') where name=\'"+other+"\'"); }');
  assert.ok(has(f, 'CWE-89'), 'a safe FIRST term must not suppress a genuinely tainted second term');
});

test('Java path traversal — new File concat, guard suppresses (CWE-22)', () => {
  assert.ok(has(scanJavaStructural('F.java', 'byte[] read(String name){ return new FileInputStream(new File("/var/data/" + name)).readAllBytes(); }'), 'CWE-22'));
  assert.ok(none(scanJavaStructural('F.java', 'byte[] read(String name){ Path w = base.resolve(name).normalize().toRealPath(); if(!w.startsWith(base)) throw new Exception(); return Files.readAllBytes(w); }'), 'CWE-22'));
});

test('Java SSRF — new URL(var), host guard suppresses (CWE-918)', () => {
  assert.ok(has(scanJavaStructural('P.java', 'String fetch(String url){ return new String(new URL(url).openStream().readAllBytes()); }'), 'CWE-918'));
  assert.ok(none(scanJavaStructural('P.java', 'String fetch(String url){ URL u = new URL(url); if(DENY.contains(u.getHost())) throw new Exception(); return read(u); }'), 'CWE-918'));
});

// SARD_80_F1 W4.J24: `new URI(data)` used ONLY to validate syntax before
// doing something else entirely (e.g. Juliet's own CWE-601 Open Redirect
// test cases: reject a malformed redirect target, then
// response.sendRedirect(data), never opening a connection) is not SSRF —
// confirmed against the public Juliet mirror
// (CWE601_Open_Redirect__Servlet_File_53d.java).
test('Java SSRF — new URI(var) with no outbound connection call anywhere in the file does not fire (CWE-918)', () => {
  const f = scanJavaStructural('R.java', 'void badSink(String data, HttpServletResponse response) throws Throwable { if (data != null) { URI uri; try { uri = new URI(data); } catch (URISyntaxException e) { return; } response.sendRedirect(data); } }');
  assert.ok(none(f, 'CWE-918'), 'a URI built purely to validate syntax, never connected to, is not SSRF');
});

test('C# hardcoded secret — split-concat literals in a credential field (CWE-798)', () => {
  assert.ok(has(scanCsharpStructural('Config.cs', 'public const string ApiKey = "sk_" + "live_1234567890abcdef1234567890abcdef";'), 'CWE-798'));
  // env-var lookup → clean
  assert.ok(none(scanCsharpStructural('Config.cs', 'public static string ApiKey => System.Environment.GetEnvironmentVariable("API_KEY");'), 'CWE-798'));
  // header-name constant (short, no secret prefix) → not flagged
  assert.ok(none(scanCsharpStructural('H.cs', 'const string ApiKeyHeader = "X-Api-Key";'), 'CWE-798'));
});

test('C# SSRF — DownloadString(var), host guard suppresses (CWE-918)', () => {
  assert.ok(has(scanCsharpStructural('Proxy.cs', 'string Fetch(){ var url = Request.QueryString["url"]; return new WebClient().DownloadString(url); }'), 'CWE-918'));
  assert.ok(none(scanCsharpStructural('Proxy.cs', 'string Fetch(){ var u = new Uri(Request.QueryString["url"]); if(u.Host=="169.254.169.254") throw new Exception(); return new WebClient().DownloadString(u); }'), 'CWE-918'));
});

test('no false positives on clean Java / C#', () => {
  assert.deepEqual(scanJavaStructural('Ok.java', 'int add(int a, int b){ return a + b; }'), []);
  assert.deepEqual(scanCsharpStructural('Ok.cs', 'int Add(int a, int b){ return a + b; }'), []);
});
