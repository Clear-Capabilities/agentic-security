// SARD_80_F1_SCANNER_PRD.md Juliet Java audit: scanJavaDeserialization's
// bare `\w+.readObject()` branch fired on 122 unrelated dev-split FPs
// because it required only file-wide "an ObjectInputStream exists
// somewhere" rather than correlating the CALL's own receiver with a
// variable actually constructed as one. See src/sast/java-deserialization.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJavaDeserialization } from '../src/sast/java-deserialization.js';

test('fires on a direct new ObjectInputStream(x).readObject() chain', () => {
  const findings = scanJavaDeserialization('A.java', `
class A {
  void bad() throws Exception {
    Object o = new ObjectInputStream(rawStream).readObject();
  }
}`);
  assert.ok(findings.some(f => f.cwe === 'CWE-502'));
});

test('fires on a bare call whose receiver was actually constructed as an ObjectInputStream', () => {
  const findings = scanJavaDeserialization('A.java', `
class A {
  void bad() throws Exception {
    ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
    Object o = ois.readObject();
  }
}`);
  assert.ok(findings.some(f => f.cwe === 'CWE-502'));
});

test('does NOT fire on an unrelated bare readObject() call merely because the file constructs an OIS elsewhere', () => {
  const findings = scanJavaDeserialization('A.java', `
class A {
  void badSqli(java.sql.Statement stmt) throws Exception {
    // this method has nothing to do with deserialization
    java.sql.ResultSet unrelated = stmt.executeQuery("SELECT 1");
    someOtherThing.readObject();
  }
  void badDeser() throws Exception {
    ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
    ois.readObject();
  }
}`);
  const bad = findings.filter(f => (f.snippet || '').includes('someOtherThing'));
  assert.equal(bad.length, 0, `expected no finding on the uncorrelated receiver, got ${JSON.stringify(bad)}`);
  assert.ok(findings.some(f => (f.snippet || '').includes('ois.readObject')), 'the genuinely correlated call must still fire');
});
