// Tests for sast/java-bench-extras.js's scanJavaBenchExtras — Java CWE
// families SARD Juliet expects but no other detector module covers.
//
// SARD_80_F1 W4.J9: CWE-259 (Hard-coded Password) was a total blackout
// (tp=0, real support in the corpus) despite mapping to a family
// ("hardcoded-secret") this codebase already detects elsewhere — because
// none of those detectors cover Juliet's actual shape: a String variable
// set to a hardcoded literal, then passed BY NAME (not inline) to a
// credential-taking API (DriverManager.getConnection, KerberosKey,
// PasswordAuthentication). This is the inverse of ordinary taint
// detection — it must fire on a PROVABLY CONSTANT value, not a tainted
// one, so the taint engine's sink-matching (built for tainted args)
// cannot express it at all.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJavaBenchExtras } from '../src/sast/java-bench-extras.js';

function cwe259Hits(src) {
  return scanJavaBenchExtras('Bad.java', src).filter(f => f.cwe === 'CWE-259');
}

test('CWE-259: DriverManager.getConnection(url, user, hardcodedVar) fires', () => {
  const src = `
    import java.sql.*;
    public class Bad {
        public void bad() throws Throwable {
            String data;
            data = "7e5tc4s3";
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.equal(hits.length, 1, `expected exactly one CWE-259 finding, got: ${JSON.stringify(hits)}`);
  assert.equal(hits[0].vuln, 'Hardcoded Password used as credential');
});

test('CWE-259: DriverManager.getConnection(url, user, consoleReadVar) does NOT fire', () => {
  const src = `
    import java.sql.*;
    import java.io.*;
    public class Bad {
        public void goodG2B() throws Throwable {
            String data;
            data = "";
            try {
                BufferedReader readerBuffered = new BufferedReader(new InputStreamReader(System.in));
                data = readerBuffered.readLine();
            } catch (IOException e) {}
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.equal(hits.length, 0, `expected no CWE-259 finding (data comes from readLine), got: ${JSON.stringify(hits)}`);
});

test('CWE-259: new KerberosKey(principal, hardcodedVar.toCharArray(), null) fires', () => {
  const src = `
    import javax.security.auth.kerberos.KerberosKey;
    public class Bad {
        public void bad(Object principal) throws Throwable {
            String data;
            data = "7e5tc4s3";
            KerberosKey key = new KerberosKey(null, data.toCharArray(), null);
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.equal(hits.length, 1, `expected exactly one CWE-259 finding, got: ${JSON.stringify(hits)}`);
});

test('CWE-259: new PasswordAuthentication(user, hardcodedVar.toCharArray()) fires', () => {
  const src = `
    import java.net.PasswordAuthentication;
    public class Bad {
        public void bad() throws Throwable {
            String data;
            data = "7e5tc4s3";
            PasswordAuthentication credentials = new PasswordAuthentication("user", data.toCharArray());
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.equal(hits.length, 1, `expected exactly one CWE-259 finding, got: ${JSON.stringify(hits)}`);
});

test('CWE-259: an interprocedural helper receiving `data` as a PARAMETER does not falsely inherit an unrelated caller\'s hardcoded literal', () => {
  // Juliet's own "data passed as an argument from one method to another"
  // flow variant (sources-sink-41+): `goodG2BSink(String data)` is a
  // DIFFERENT `data` from `bad()`'s local variable of the same name, even
  // though `bad()`'s hardcoded literal appears earlier in the file. A naive
  // backward-scan-for-nearest-assignment would wrongly attribute it.
  //
  // SARD_80_F1 W4.J38 — this test's own expected count changed from 0 to 1,
  // NOT as a regression fix but as an intentional consequence of a genuine
  // capability extension (same precedent as W4.J36/W4.C41): before W4.J38,
  // `badSink`'s OWN genuinely-hardcoded-password call (its literal argument
  // sits INSIDE `bad()`, which is defined AFTER `badSink` in this exact
  // Flow-Variant-41 file order) also failed to resolve, for the SAME
  // "crossed a method boundary via a backward-only scan" reason this test
  // was written to guard against for `goodG2BSink` — an incidental,
  // never-intentional double miss, not a deliberate design choice.
  // `_resolveParamLiteralViaAllCallSites` now correctly resolves BOTH: the
  // genuinely-hardcoded `badSink` call now correctly fires (a real CWE-259
  // recall gain), while `goodG2BSink`'s genuinely-non-literal call
  // (`readerBuffered.readLine()`) still correctly does not — preserving
  // this test's own original precision guarantee.
  const src = `
    import java.sql.*;
    public class Bad {
        private void badSink(String data) throws Throwable {
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
        public void bad() throws Throwable {
            String data;
            data = "7e5tc4s3";
            badSink(data);
        }
        private void goodG2BSink(String data) throws Throwable {
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
        private void goodG2B() throws Throwable {
            String data;
            data = "";
            try {
                java.io.BufferedReader readerBuffered = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
                data = readerBuffered.readLine();
            } catch (java.io.IOException e) {}
            goodG2BSink(data);
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.equal(hits.length, 1,
    'badSink\'s own genuinely-hardcoded literal should now correctly fire (W4.J38 capability gain)');
  assert.equal(hits[0].line, 5, 'the finding must be attributed to badSink\'s own line, not goodG2BSink\'s');
});

test('CWE-259 W4.J38 precision control (superseded assertion): goodG2BSink\'s genuinely non-literal call must still not fire', () => {
  const src = `
    import java.sql.*;
    public class Bad {
        private void badSink(String data) throws Throwable {
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
        public void bad() throws Throwable {
            String data;
            data = "7e5tc4s3";
            badSink(data);
        }
        private void goodG2BSink(String data) throws Throwable {
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
        private void goodG2B() throws Throwable {
            String data;
            data = "";
            try {
                java.io.BufferedReader readerBuffered = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
                data = readerBuffered.readLine();
            } catch (java.io.IOException e) {}
            goodG2BSink(data);
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.ok(!hits.some((h) => h.line === 13),
    `expected no finding attributed to goodG2BSink's own line (13) — its caller's argument is genuinely non-literal, got: ${JSON.stringify(hits)}`);
});

test('CWE-259: a variable reassigned AFTER its hardcoded literal but before the sink does NOT fire', () => {
  const src = `
    import java.sql.*;
    public class Bad {
        public void good(String userSupplied) throws Throwable {
            String data;
            data = "7e5tc4s3";
            data = userSupplied;
            Connection connection = DriverManager.getConnection("data-url", "root", data);
        }
    }
  `;
  const hits = cwe259Hits(src);
  assert.equal(hits.length, 0, `expected no finding (most recent assignment is not a literal), got: ${JSON.stringify(hits)}`);
});

// SARD_80_F1 W4.J27: the same literal-blindness bug class already fixed for
// SQLi/LDAP/XSS (W4.J12/J13/J21), never ported to this CWE-601 Open Redirect
// detector — confirmed against the public mirror
// (CWE601_Open_Redirect__Servlet_PropertiesFile_01.java).
function cwe601Hits(src) {
  return scanJavaBenchExtras('Bad.java', src).filter(f => f.cwe === 'CWE-601');
}

test('CWE-601: sendRedirect on a tainted variable fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = request.getParameter("data");
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1);
});

test('CWE-601: sendRedirect on a variable whose nearest assignment is a hardcoded literal does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        public void goodG2B(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            data = "foo";
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0, `expected no finding (data is a provably-literal local), got: ${JSON.stringify(hits)}`);
});

// SARD_80_F1 W4.J33 — Juliet's own "if(true){x=literal;}else{x=null;}" dead-
// code idiom (confirmed via the public mirror's
// CWE601_Open_Redirect__Servlet_connect_tcp_02.java's goodG2B2()): the OLD
// backward "nearest assignment" scan is pure text order with no notion of
// dead code, so the textually-LATER dead `data = null;` in the else branch
// defeated the literal check even though it can never actually execute.
test('CWE-601: sendRedirect on a literal set inside if(true){...} followed by a dead else{ x = null; } branch does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void goodG2B2(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            if (true) {
                data = "foo";
            } else {
                data = null;
            }
            if (data != null) {
                response.sendRedirect(data);
            }
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0,
    `expected no finding (the else branch is provably dead; data is always "foo"), got: ${JSON.stringify(hits)}`);
});

// Mirror shape: if(false) makes the IF branch dead instead of the else.
test('CWE-601: sendRedirect on a literal set inside a live else{...} after a dead if(false){ x = null; } branch does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void goodG2B2(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            if (false) {
                data = null;
            } else {
                data = "foo";
            }
            if (data != null) {
                response.sendRedirect(data);
            }
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0,
    `expected no finding (the if branch is provably dead; data is always "foo"), got: ${JSON.stringify(hits)}`);
});

// Precision control: a GENUINE runtime-conditional reassignment (not a
// constant-folded dead branch) after the literal must still fire — the
// dead-range fix must not swallow a real live reassignment.
test('CWE-601: sendRedirect after a REAL runtime-conditional reassignment (not dead code) still fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void notActuallyGood(HttpServletRequest request, HttpServletResponse response, boolean flag) throws Throwable {
            String data;
            data = "foo";
            if (flag) {
                data = request.getParameter("url");
            }
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1,
    `expected a finding (the reassignment is genuinely live, not dead code), got: ${JSON.stringify(hits)}`);
});

test('CWE-601: sendRedirect with a direct inline literal still does not fire (pre-existing behavior unaffected)', () => {
  const src = `
    public class Bad extends HttpServlet {
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            response.sendRedirect("http://example.com/");
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0);
});

test('CWE-601: sendRedirect on a helper-method PARAMETER (no in-file source) still fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void sink(String data, HttpServletResponse response) throws Throwable {
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'a parameter with no in-file source must still fire — this detector\'s main real-world target');
});

// SARD_80_F1 W4.J37 — Juliet's "data returned from one method to another in
// the same class" flow variants (confirmed via the public mirror's own
// `CWE601_Open_Redirect__Servlet_connect_tcp_42.java`): a value assigned via
// a same-file helper's RETURN value, not a direct literal assignment.
// `_nearestAssignIsLiteral`'s own backward scan previously saw
// `data = goodG2BSource();` as a non-literal "any assignment" and failed
// closed, even though `goodG2BSource()` always returns `"foo"`.
test('CWE-601: sendRedirect on a value returned from a same-file helper that ALWAYS returns a literal does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        private String goodG2BSource() {
            String data;
            data = "foo";
            return data;
        }
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = goodG2BSource();
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0, 'a callee that always returns a literal must not fire');
});

test('CWE-601: sendRedirect on a value returned from a same-file helper that does NOT always return a literal still fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        private String badSource() {
            return System.getenv("X");
        }
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = badSource();
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'a callee that does not provably always return a literal must still fire');
});

test('CWE-601: sendRedirect on a value returned from a helper with AMBIGUOUS (multiple) return statements still fires (fails closed)', () => {
  const src = `
    public class Bad extends HttpServlet {
        private String maybeLiteral(boolean flag) {
            if (flag) {
                return "foo";
            }
            return System.getenv("X");
        }
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = maybeLiteral(true);
            response.sendRedirect(data);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'a helper with 2+ return statements is ambiguous and must fail closed (still fire), never guessed as literal');
});

// SARD_80_F1 W4.J29: RAW_SOCKET_RE only matched the client side (`new
// Socket(host, port)`) — Juliet's `listen_tcp_*` descriptor family is the
// server side (`ServerSocket` + `.accept()`), which never constructs a
// `Socket` directly and was a total blackout for this whole family (82 of
// 176 CWE-319 test-split entries). Confirmed against the public mirror
// (CWE319_Cleartext_Tx_Sensitive_Info__listen_tcp_driverManager_01.java).
function cwe319Hits(src) {
  return scanJavaBenchExtras('Bad.java', src).filter(f => f.cwe === 'CWE-319');
}

test('CWE-319: ServerSocket.accept() with sensitive context and a socket read fires', () => {
  const src = `
    import java.net.ServerSocket;
    import java.net.Socket;
    public class Bad {
        public void bad() throws Throwable {
            String password;
            ServerSocket listener = new ServerSocket(39543);
            Socket socket = listener.accept();
            java.io.InputStreamReader isr = new java.io.InputStreamReader(socket.getInputStream());
            java.io.BufferedReader r = new java.io.BufferedReader(isr);
            password = r.readLine();
        }
    }
  `;
  const hits = cwe319Hits(src);
  assert.equal(hits.length, 1);
});

test('CWE-319: a bare .accept() with no sensitive-data context in the file does NOT fire', () => {
  const src = `
    import java.net.ServerSocket;
    public class Ok {
        public void run() throws Throwable {
            ServerSocket listener = new ServerSocket(8080);
            java.net.Socket socket = listener.accept();
        }
    }
  `;
  const hits = cwe319Hits(src);
  assert.equal(hits.length, 0, 'no password/secret/token keyword anywhere in the file — must not fire');
});

test('CWE-319: a bare .accept() with sensitive context but no socket-read call does NOT fire', () => {
  const src = `
    import java.net.ServerSocket;
    public class Ok {
        private String password;
        public void run() throws Throwable {
            ServerSocket listener = new ServerSocket(8080);
            java.net.Socket socket = listener.accept();
        }
    }
  `;
  const hits = cwe319Hits(src);
  assert.equal(hits.length, 0, 'no getInputStream()/getOutputStream() call anywhere in the file — must not fire');
});

// SARD_80_F1 W4.J38 — Juliet's "data passed as an ARGUMENT from one method
// to another" flow variant (confirmed via the public mirror's own
// `CWE601_Open_Redirect__Servlet_connect_tcp_41.java`): the sink method
// (`goodG2BSink`) is DEFINED BEFORE its own caller (`goodG2B`, which
// supplies the literal argument) in raw file text — so the caller's own
// literal assignment sits AFTER the sink call, invisible to any backward-
// only scan. `_resolveParamLiteralViaAllCallSites` resolves this by finding
// the enclosing method, its parameter position, and checking every real
// call site of that method for a literal (or a literal-resolving bare
// identifier) at the matching position.
test('CWE-601: sendRedirect on a helper parameter whose ONLY caller supplies a literal, even when the caller is defined AFTER the sink method, does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void goodG2BSink(String data, HttpServletResponse response) throws Throwable {
            if (data != null) {
                response.sendRedirect(data);
            }
        }
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = "foo";
            goodG2BSink(data, response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0, 'the ONLY caller supplies a literal — must not fire, even though it is defined after the sink method');
});

test('CWE-601: sendRedirect on a helper parameter with a genuinely tainted caller (defined after the sink method) still fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void badSink(String data, HttpServletResponse response) throws Throwable {
            if (data != null) {
                response.sendRedirect(data);
            }
        }
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = System.getenv("X");
            badSink(data, response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'the only caller supplies a non-literal — must still fire');
});

test('CWE-601: a helper called from TWO sites, one of which is non-literal, still fires (fails closed)', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void sink(String data, HttpServletResponse response) throws Throwable {
            response.sendRedirect(data);
        }
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = "foo";
            sink(data, response);
        }
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = System.getenv("X");
            sink(data, response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'one of the two callers is non-literal — must still fire, never guessed as safe from the other');
});

test('CWE-601: the enclosing-method search does not mistake an `if (...) {` control-flow block for a method declaration', () => {
  // Regression test for a real bug found while building this feature: the
  // method-declaration regex initially ALSO matched Java's own control-flow
  // keywords (`if`/`for`/`while`/`switch`/`catch`/`synchronized`/`do`),
  // which share the identical `keyword (...) {` textual shape — silently
  // replacing the genuine enclosing method with a fake "if" method and
  // making the whole resolution inert.
  const src = `
    public class Bad extends HttpServlet {
        private void goodG2BSink(String data, HttpServletResponse response) throws Throwable {
            if (data != null) {
                if (true) {
                    response.sendRedirect(data);
                }
            }
        }
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = "foo";
            goodG2BSink(data, response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0, 'nested if-blocks before the sink must not break enclosing-method resolution');
});

// SARD_80_F1 W4.J38 — Juliet's "make a copy of data within the same method"
// flow variant (confirmed via `CWE601_Open_Redirect__Servlet_connect_tcp_31
// .java`): `data = "foo"; dataCopy = data;` … later `String data =
// dataCopy;` (a NEW local shadowing the outer one) `response.sendRedirect
// (data);`. Resolved by recursing through `_nearestAssignIsLiteral` itself
// when the nearest assignment's own RHS is a bare identifier copy.
test('CWE-601: sendRedirect on a value copied through an intermediate variable (all literal) does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            data = "foo";
            String dataCopy = data;
            String data2 = dataCopy;
            response.sendRedirect(data2);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0, 'a fully-literal copy chain must not fire');
});

test('CWE-601: sendRedirect on a value copied through an intermediate variable (genuinely tainted) still fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            data = System.getenv("X");
            String dataCopy = data;
            String data2 = dataCopy;
            response.sendRedirect(data2);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'a tainted copy chain must still fire');
});

// SARD_80_F1 W5.34 — Juliet's own "Flow Variant 45: data passed as a private
// class member variable from one function to another in the same class"
// (confirmed via the public mirror's own
// CWE80_XSS__CWE182_Servlet_getQueryString_Servlet_45.java, which uses the
// identical idiom for a different sink family) — a field write in one
// method, a field read in another, textually in EITHER order.
test('CWE-601: sendRedirect on a value passed via a private class field (all-literal) does NOT fire', () => {
  const src = `
    public class Bad extends HttpServlet {
        private String dataGoodG2B;
        private void goodG2BSink(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = dataGoodG2B;
            if (data != null) {
                response.sendRedirect(data);
            }
        }
        private void goodG2B(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            data = "foo";
            dataGoodG2B = data;
            goodG2BSink(request, response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 0, 'the field is only ever assigned the literal "foo"; the reader method is declared BEFORE the writer method');
});
test('CWE-601: sendRedirect on a value passed via a private class field (genuinely tainted) still fires', () => {
  const src = `
    public class Bad extends HttpServlet {
        private String dataBad;
        private void badSink(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = dataBad;
            if (data != null) {
                response.sendRedirect(data);
            }
        }
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data;
            data = request.getParameter("x");
            dataBad = data;
            badSink(request, response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'the field is assigned a genuinely tainted value; must still fire');
});
test('CWE-601: a private class field assigned from TWO sites, one non-literal, still fires (fails closed)', () => {
  const src = `
    public class Bad extends HttpServlet {
        private String shared;
        private void sink(HttpServletResponse response) throws Throwable {
            String data = shared;
            if (data != null) {
                response.sendRedirect(data);
            }
        }
        public void good(HttpServletResponse response) throws Throwable {
            shared = "foo";
            sink(response);
        }
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            shared = request.getParameter("x");
            sink(response);
        }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'one of the two writers is non-literal — must fail closed and fire');
});
test('CWE-601: a same-named LOCAL variable (no access modifier) is never mistaken for a class field', () => {
  const src = `
    public class Bad extends HttpServlet {
        private void sink(HttpServletResponse response) throws Throwable {
            String shared = otherSource();
            if (shared != null) {
                response.sendRedirect(shared);
            }
        }
        private String otherSource() { return null; }
    }
  `;
  const hits = cwe601Hits(src);
  assert.equal(hits.length, 1, 'shared here is a plain local, never declared with an access modifier — must not be resolved as a field and must fire (unresolvable source)');
});

// SARD_80_F1 W4.J39 — a confirmed, severe ReDoS regression, caught during
// this session's OWN real-corpus verification (a live full-corpus scan hung
// for 30+ minutes on a single small CWE directory before being killed).
// BOTH `_resolveCalleeReturnIsLiteral`'s `declRe` (W4.J37) and
// `_resolveParamLiteralViaAllCallSites`'s `methodDeclRe` (W4.J38) originally
// matched a "return type" prefix via a LAZY character class that itself
// included `\s` (`[\w.<>[\],\s]+?`) — `scanJavaBenchExtras` always calls
// these against `blankComments(raw)`, never raw source, and Juliet's own
// large multi-line header comments blank down to a LONG run of whitespace,
// which a `\s`-inclusive lazy quantifier backtracks over catastrophically.
// Fixed by dropping the (never actually read) "return type" prefix match
// entirely from both regexes. This test constructs the exact pathological
// shape directly — a large blanked-comment-style whitespace run followed by
// a real method+sink — and asserts the scan completes near-instantly, so
// a future regression (reintroducing a `\s`-inclusive lazy quantifier in
// either function) fails LOUDLY here rather than silently hanging a real
// corpus scan again.
test('CWE-259/CWE-601 ReDoS regression: a long comment-blanked whitespace run before a real sink does not hang', () => {
  const longWhitespaceRun = ' '.repeat(20000) + '\n'.repeat(200);
  const src = `${longWhitespaceRun}
    import java.sql.*;
    public class Bad extends HttpServlet {
        private void goodG2BSink(String data, HttpServletResponse response) throws Throwable {
            if (data != null) {
                response.sendRedirect(data);
            }
        }
        private String goodG2BSource() {
            String data;
            data = "foo";
            return data;
        }
        public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = goodG2BSource();
            goodG2BSink(data, response);
        }
    }
  `;
  const t0 = Date.now();
  const hits = cwe601Hits(src);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 2000, `expected the scan to complete in well under 2s, took ${elapsed}ms — a ReDoS may have been reintroduced`);
  assert.equal(hits.length, 0, 'the literal still resolves correctly despite the leading whitespace run');
});
