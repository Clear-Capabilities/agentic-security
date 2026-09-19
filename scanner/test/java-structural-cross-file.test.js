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

// SARD_80_F1 W5.45 — Juliet's own abstract-dispatch caller convention uses a
// TWO-STATEMENT pattern (`<BaseType> <var> = new <ConcreteClass>();` then
// later `<var>.<method>(...)`), not the inline `(new X()).method()` shape
// W5.41 already handles — confirmed via a direct fetch of the public
// mirror's own CWE89_SQL_Injection__Environment_executeQuery_81a.java.
// Found while investigating a real-corpus regression W5.43/44's own scorer
// fix exposed: 30 Java files where our detector fires on Juliet's "good
// source, structurally bad-shaped sink" test convention (a deliberate
// imprecision trap, not a real vulnerability) because this calling
// convention was invisible to the cross-file literal check.
test('cross-file: the two-statement "BaseType var = new Concrete(); var.method(...)" caller pattern is resolved', () => {
  const fileA = `
public class Caller {
    public void bad() {
        String data = getUntrustedInput();
        Base baseObject = new Bad();
        baseObject.action(data);
    }
    public void goodG2B() {
        String data = "foo";
        Base baseObject = new GoodG2B();
        baseObject.action(data);
    }
}`;
  const fileBad = `
public class Bad extends Base {
    public void action(String data) throws Throwable {
        Statement sqlStatement = null;
        sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fileGoodG2B = `
public class GoodG2B extends Base {
    public void action(String data) throws Throwable {
        Statement sqlStatement = null;
        sqlStatement.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fc = {
    '/proj/s01/Caller.java': fileA,
    '/proj/s01/Bad.java': fileBad,
    '/proj/s01/GoodG2B.java': fileGoodG2B,
  };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.deepEqual([...drop], ['/proj/s01/GoodG2B.java:5'], 'only GoodG2B (always called with a literal) should be suppressed; Bad (genuinely tainted) must survive');
});

test('cross-file: reused local variable name across SIBLING methods in the caller does not cause a false negative', () => {
  // The exact collision Juliet's own real corpus hits: bad()/goodG2B()/
  // goodB2G() each declare their OWN local variable named "baseObject" for
  // a DIFFERENT concrete class — an unscoped whole-file search for
  // "baseObject.action(" would wrongly pick up bad()'s own genuinely
  // tainted call when resolving goodG2B()'s completely unrelated one.
  const fileCaller = `
public class Caller {
    public void bad() {
        String data = getUntrustedInput();
        Base baseObject = new Bad();
        baseObject.action(data);
    }
    public void goodG2B() {
        String data = "foo";
        Base baseObject = new GoodG2B();
        baseObject.action(data);
    }
    public void goodB2G() {
        String data = getUntrustedInput();
        Base baseObject = new GoodB2G();
        baseObject.action(data);
    }
}`;
  const fileBad = `
public class Bad extends Base {
    public void action(String data) throws Throwable {
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fileGoodG2B = `
public class GoodG2B extends Base {
    public void action(String data) throws Throwable {
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fileGoodB2G = `
public class GoodB2G extends Base {
    public void action(String data) throws Throwable {
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fc = {
    '/proj/s01/Caller.java': fileCaller,
    '/proj/s01/Bad.java': fileBad,
    '/proj/s01/GoodG2B.java': fileGoodG2B,
    '/proj/s01/GoodB2G.java': fileGoodB2G,
  };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.deepEqual([...drop], ['/proj/s01/GoodG2B.java:5'], 'GoodG2B must be suppressed (always literal); Bad and GoodB2G (both genuinely tainted) must survive despite sharing the "baseObject" variable name');
});

// SARD_80_F1 W5.47 — Juliet Flow Variant 65-68 ("data passed as a member
// variable in the 'a' class, used by a method in another class in the same
// package"): a public static field is written in one file, read via a
// QUALIFIED `OtherClass.field` reference in a sibling file's sink method.
// Independently identified 3 times this session (W3.4/PHP, W4.C24/C#,
// W4.J27/Java) as needing "call-site-sensitive field-value tracking" — but
// Juliet's own convention turns out narrower: each sink method is UNIQUELY
// named per flow branch with EXACTLY ONE real caller, so this reduces to
// the same "declare-then-call, one writer per callee" shape W5.45 already
// solved, just via a static field instead of a method argument.
test('cross-file: a qualified static field read (ClassName.field) resolves via the field-writing method that calls THIS specific sink method', () => {
  const fileA = `
public class Caller {
    public static String data;
    public void bad() {
        data = getUntrustedInput();
        (new Sink()).badSink();
    }
    public void goodG2B() {
        data = "foo";
        (new Sink()).goodG2BSink();
    }
    public void goodB2G() {
        data = getUntrustedInput();
        (new Sink()).goodB2GSink();
    }
}`;
  const fileSink = `
public class Sink {
    public void badSink() {
        String data = Caller.data;
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
    public void goodG2BSink() {
        String data = Caller.data;
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
    public void goodB2GSink() {
        String data = Caller.data;
        PreparedStatement s = null;
        s.executeQuery();
    }
}`;
  const fc = { '/proj/s01/Caller.java': fileA, '/proj/s01/Sink.java': fileSink };
  const findings = scanJavaStructural('/proj/s01/Sink.java', fileSink);
  const badSinkFinding = findings.find((f) => /badSink/.test(f.snippet) || f.line < findings[findings.length - 1].line);
  assert.ok(findings.length >= 2, 'badSink and goodG2BSink both fire structurally in isolation');
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.equal(drop.size, 1, 'exactly one finding (goodG2BSink) should be suppressed');
  const suppressedFinding = findings.find((f) => [...drop].some((k) => k.endsWith(`:${f.line}`)));
  assert.ok(suppressedFinding, 'the suppressed finding must be a real finding from this scan');
  const survivingFindings = findings.filter((f) => f !== suppressedFinding);
  assert.ok(survivingFindings.length >= 1, 'badSink must still survive (genuinely tainted)');
});

test('cross-file: a static field with NO writer calling this specific sink method is never suppressed (fail closed)', () => {
  // Only ONE writer method exists, and it calls a DIFFERENT sink method
  // than the one being resolved — the field-literal check must find no
  // RELEVANT writer at all and correctly refuse to suppress.
  const fileA = `
public class Caller {
    public static String data;
    public void unrelated() {
        data = "foo";
        (new Sink()).otherMethod();
    }
}`;
  const fileSink = `
public class Sink {
    public void realSink() {
        String data = Caller.data;
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
    public void otherMethod() {
        System.out.println("noop");
    }
}`;
  const fc = { '/proj/s01/Caller.java': fileA, '/proj/s01/Sink.java': fileSink };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.equal(drop.size, 0, 'no writer method calls realSink specifically — must not guess a suppression');
});

test('cross-file: a static field written non-literally by the SAME method that calls this sink still fires (fail closed)', () => {
  const fileA = `
public class Caller {
    public static String data;
    public void bad() {
        data = getUntrustedInput();
        (new Sink()).badSink();
    }
}`;
  const fileSink = `
public class Sink {
    public void badSink() {
        String data = Caller.data;
        Statement s = null;
        s.executeQuery("select * from users where name='"+data+"'");
    }
}`;
  const fc = { '/proj/s01/Caller.java': fileA, '/proj/s01/Sink.java': fileSink };
  const drop = computeJavaStructuralCrossFileSuppressions(fc);
  assert.equal(drop.size, 0, 'the one real caller supplies a genuinely tainted value — must never be suppressed');
});
