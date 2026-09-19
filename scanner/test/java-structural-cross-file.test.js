// SARD_80_F1 W5.41 — cross-file literal-resolution suppression for
// java-structural.js's own structural SQLi/cmdi detectors. See
// java-structural-cross-file.js's own header comment for the full design
// and bench/sard/EXECUTION_STATUS.md's W5.40/W5.41 entries for the
// root-cause investigation (Juliet's Flow Variant 51+ "data passed as an
// argument to a method in a DIFFERENT class, split across two files").

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJavaStructural } from '../src/sast/java-structural.js';
import { computeJavaStructuralCrossFileSuppressions } from '../src/sast/java-structural-cross-file.js';

test('cross-file: a sink method always called with a hardcoded literal across a sibling file is suppressed', () => {
  const fileA = `
public class CWE89_SQL_Injection__database_executeQuery_51a {
    public void bad() throws Throwable {
        String data;
        data = getUntrustedInput();
        (new CWE89_SQL_Injection__database_executeQuery_51b()).badSink(data);
    }
    public void good() throws Throwable { goodG2B(); }
    private void goodG2B() throws Throwable {
        String data;
        data = "foo";
        (new CWE89_SQL_Injection__database_executeQuery_51b()).goodG2BSink(data);
    }
}`;
  const fileB = `
public class CWE89_SQL_Injection__database_executeQuery_51b {
    public void badSink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
    public void goodG2BSink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fc = {
    '/proj/CWE89_SQL_Injection__database_executeQuery_51a.java': fileA,
    '/proj/CWE89_SQL_Injection__database_executeQuery_51b.java': fileB,
  };
  const findingsB = scanJavaStructural('/proj/CWE89_SQL_Injection__database_executeQuery_51b.java', fileB);
  assert.equal(findingsB.length, 2, 'both sinks fire in isolation (no cross-file awareness yet)');

  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  const survivors = findingsB.filter((f) => !drop.has(`${f.file}:${f.line}`));
  assert.equal(survivors.length, 1, 'only the genuinely tainted badSink finding should survive');
  assert.ok(/badSink/.test(survivors[0].snippet) || survivors[0].line < findingsB[1].line, 'the surviving finding is badSink, not goodG2BSink');
});

test('cross-file: a genuinely tainted caller in ANY sibling file blocks suppression, even if another sibling passes a literal', () => {
  const fileA = `
public class A {
    public void one() {
        String data = "foo";
        (new B()).sink(data);
    }
}`;
  const fileA2 = `
public class A2 {
    public void two() {
        String data = getUntrustedInput();
        (new B()).sink(data);
    }
}`;
  const fileB = `
public class B {
    public void sink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fc = { '/proj/A.java': fileA, '/proj/A2.java': fileA2, '/proj/B.java': fileB };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.equal(drop.size, 0, 'must fail closed: not every known caller passes a literal');
});

test('cross-file: no suppression when there are no sibling files in the same directory', () => {
  const fileB = `
public class Solo {
    public void sink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const drop = computeJavaStructuralCrossFileSuppressions({ '/proj/Solo.java': fileB });
  assert.equal(drop.size, 0);
});

test('cross-file: a sibling file in a DIFFERENT directory is never consulted', () => {
  const fileB = `
public class B {
    public void sink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fileAOtherDir = `
public class A {
    public void one() {
        String data = "foo";
        (new B()).sink(data);
    }
}`;
  const fc = {
    '/proj/dirOne/B.java': fileB,
    '/proj/dirTwo/A.java': fileAOtherDir,
  };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.equal(drop.size, 0, 'a same-named caller in a different directory must not be treated as a sibling');
});

test('cross-file: a same-directory sibling with zero call sites at all leaves the finding unsuppressed', () => {
  const fileB = `
public class B {
    public void sink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fileUnrelated = `
public class Unrelated {
    public void noop() { System.out.println("hi"); }
}`;
  const fc = { '/proj/B.java': fileB, '/proj/Unrelated.java': fileUnrelated };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.equal(drop.size, 0, 'no caller anywhere resolves the parameter — must not guess a suppression');
});

test('cross-file: name collisions from unrelated same-named sink methods in the same directory do not cause a false negative or a false suppression', () => {
  // Juliet reuses generic method names (bad/badSink/goodG2B/goodG2BSink/…)
  // identically across thousands of otherwise-unrelated flow-variant files
  // in the SAME directory, and --scramble-identifiers preserves this
  // collision by design (same original word -> same opaque token
  // everywhere). A bare method-name search across siblings would wrongly
  // pick up unrelated classes' own same-named methods; requiring the call
  // site to construct THIS sink's own class name disambiguates correctly.
  const fileA = `
public class A {
    public void one() {
        String data = "foo";
        (new B()).sink(data);
    }
}`;
  const fileB = `
public class B {
    public void sink(String data) throws Throwable {
        Statement sqlStatement = null;
        ResultSet resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fc = { '/proj/A.java': fileA, '/proj/B.java': fileB };
  for (let i = 0; i < 50; i++) {
    fc[`/proj/OtherCaller${i}.java`] = `
public class OtherCaller${i} {
    public void call() {
        String data = getUntrustedInput();
        (new OtherSink${i}()).sink(data);
    }
}`;
    fc[`/proj/OtherSink${i}.java`] = `
public class OtherSink${i} {
    public void sink(String data) {
        Statement s = null;
        s.executeQuery("select * from x where y='"+data+"'");
    }
}`;
  }
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.deepEqual([...drop], ['/proj/B.java:5'], 'only B.sink (called exclusively with a literal) should be suppressed');
});

test('cross-file: java-bench-extras.js CWE-601 open-redirect sendRedirect sink also benefits from cross-file literal resolution', () => {
  const fileA = `
public class Redir51a {
    public void bad() {
        String data = getUntrustedInput();
        (new Redir51b()).badSink(data);
    }
    public void goodG2B() {
        String data = "foo";
        (new Redir51b()).goodG2BSink(data);
    }
}`;
  const fileB = `
public class Redir51b {
    public void badSink(String data) {
        response.sendRedirect(data);
    }
    public void goodG2BSink(String data) {
        response.sendRedirect(data);
    }
}`;
  const fc = { '/proj/s01/Redir51a.java': fileA, '/proj/s01/Redir51b.java': fileB };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.deepEqual([...drop], ['/proj/s01/Redir51b.java:7'], 'only goodG2BSink (always called with a literal) should be suppressed');
});
