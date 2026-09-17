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
  assert.equal(hits.length, 0,
    `expected no finding (data is a helper-method PARAMETER in both sinks, not a provably-literal local), got: ${JSON.stringify(hits)}`);
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
