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

// SARD_80_F1 W4.J35 — Juliet's own "if(true){data="foo";}else{data=null;}"
// dead-code idiom (Flow Variant 02, confirmed via the public mirror's
// CWE89_SQL_Injection__connect_tcp_executeUpdate_02.java's goodG2B2())
// defeated the SAME literal-check above: the textually-later dead
// `data = null;` in the else branch made the "nearest assignment" scan
// land on it instead of the live literal, so this shape was never
// recognized as safe.
// deadBranchRanges needs a full, parseable compilation unit (java-parser
// requires at least one class declaration) — unlike this file's other
// bare-method-snippet tests above, which only exercise the plain-literal
// path and never touch dead-branch resolution at all.
test('Java SQLi — a literal set inside if(true){...} followed by a dead else{ x = null; } branch is suppressed (CWE-89)', () => {
  const good = scanJavaStructural('S.java', `
    public class Bad {
      void goodG2B2() throws Throwable {
        String data;
        if (true) {
          data = "foo";
        } else {
          data = null;
        }
        Statement s = null;
        s.execute("insert into users (status) values ('updated') where name='"+data+"'");
      }
    }
  `);
  assert.ok(none(good, 'CWE-89'), 'expected no finding — the else branch is provably dead, data is always "foo"');
});

// Precision control: a genuine RUNTIME-conditional reassignment (not a
// constant-folded dead branch) must still fire.
test('Java SQLi — a REAL runtime-conditional reassignment (not dead code) still fires (CWE-89)', () => {
  const f = scanJavaStructural('S.java', `
    public class Bad {
      void notActuallyGood(boolean flag) throws Throwable {
        String data = "foo";
        if (flag) {
          data = System.getenv("ADD");
        }
        Statement s = null;
        s.execute("insert into users (status) values ('updated') where name='"+data+"'");
      }
    }
  `);
  assert.ok(has(f, 'CWE-89'), 'the reassignment is genuinely live, not dead code — must not be suppressed');
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

// SARD_80_F1 W4.C23: "Password=" appearing as plain TEXT inside an unrelated
// connection-string literal (Juliet's own `"...;Password=" + password`
// shape, real BadSink()/GoodG2BSink() code) must not be read as a credential
// FIELD assignment — confirmed against the public Juliet mirror
// (CWE256_Unprotected_Storage_of_Credentials__basic_54e.cs and
// CWE319_Cleartext_Tx_Sensitive_Info__listen_tcp_SqlConnection_52c.cs).
// Before the fix, the literal's own closing quote was read as this rule's
// opening quote, and the unbounded capture group spanned across the
// following newline into unrelated code (a whole try/catch block), which
// still satisfied the length gate and fired as a fabricated "secret".
test('C# hardcoded secret — "Password=" as text inside a connection-string literal does not fire (CWE-798)', () => {
  const src = 'public static void BadSink(string password) { using (SqlConnection c = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + password)) { c.Open(); } }';
  assert.ok(none(scanCsharpStructural('BadSink.cs', src), 'CWE-798'), '"Password=" inside a literal, concatenated with a variable (not another literal), is not a hardcoded secret');
});

// SARD_80_F1 W4.C23 (part 2): a literal reaching a credential-labeled sink
// through a one-hop variable copy — Juliet's own CWE256/259 shape, where the
// variable is deliberately named generically (`data`, not `password`) to
// test detection independent of naming convention. Confirmed against the
// public Juliet mirror (CWE259_Hard_Coded_Password__SqlConnection_01.cs).
test('C# hardcoded secret — literal reaches a "Password=" sink through a one-hop variable copy (CWE-798/259)', () => {
  const src = 'class T { public override void Bad() { string data; data = "7e5tc4s3"; using (SqlConnection connection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + data)) { connection.Open(); } } }';
  assert.ok(has(scanCsharpStructural('Bad.cs', src), 'CWE-798'));
  // a variable reaching the same sink WITHOUT ever being assigned a literal
  // (a real parameter/tainted value) must not fire.
  const clean = 'class T { public static void GoodSink(string data) { using (SqlConnection connection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + data)) { connection.Open(); } } }';
  assert.ok(none(scanCsharpStructural('Good.cs', clean), 'CWE-798'));
  // the SAME generic variable name used with an UNRELATED, non-literal
  // meaning in a sibling method must not borrow the other method's literal
  // (Juliet's own Bad()/GoodG2B() collision shape, confirmed against the
  // real corpus — see the method-scoping comment above).
  const sibling = [
    'class T {',
    '  public void Bad() {',
    '    string data;',
    '    data = "7e5tc4s3";',
    '    Sink(data);',
    '  }',
    '  public void GoodG2B() {',
    '    string data;',
    '    data = Console.ReadLine();',
    '    using (SqlConnection connection = new SqlConnection(@"User ID=" + "sa" + ";Password=" + data)) {',
    '      connection.Open();',
    '    }',
    '  }',
    '}',
  ].join('\n');
  assert.ok(none(scanCsharpStructural('Sibling.cs', sibling), 'CWE-798'));
});

test('no false positives on clean Java / C#', () => {
  assert.deepEqual(scanJavaStructural('Ok.java', 'int add(int a, int b){ return a + b; }'), []);
  assert.deepEqual(scanCsharpStructural('Ok.cs', 'int Add(int a, int b){ return a + b; }'), []);
});
