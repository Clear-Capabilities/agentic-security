// PRD SARD_80_F1_SCANNER_PRD.md §9.1 "Build flow-aware vulnerability matching"
// + §9.2 "Prevent scorer inflation".
//
// bench-realworld.js's strict per-method Juliet GT previously credited a
// finding ONLY when its line fell inside the expected Bad() method's own
// [startLine, endLine] span. A finding correctly relocated by the scanner's
// call-graph fix to a same-file helper Bad() calls scored as a simultaneous
// FN (nothing in Bad()'s span) + FP (an "unexplained" finding elsewhere) —
// see bench/sard/IMPLEMENTATION_STATUS.md's LDAP (CWE90) writeup for the
// real-world case this was discovered from.
//
// These tests exercise the exported reachability helpers directly, then the
// full `score()` integration against on-disk fixtures (score() now does its
// own fs.readFile for call-graph resolution, so a pure in-memory unit test
// can't cover the integration path).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  findEnclosingMethod,
  buildSameFileCallGraph,
  reachableFrom,
  findCsharpMethodSpans,
  findJavaMethodSpans,
  _isDelegateOnlyBadMethod,
  score,
  scoreLegacy,
} from './benchmark/realworld/bench-realworld.js';

test('findEnclosingMethod: picks the smallest containing span', () => {
  const methods = [
    { name: 'Outer', startLine: 1, endLine: 20 },
    { name: 'Inner', startLine: 5, endLine: 10 },
  ];
  assert.equal(findEnclosingMethod(methods, 7)?.name, 'Inner');
  assert.equal(findEnclosingMethod(methods, 15)?.name, 'Outer');
  assert.equal(findEnclosingMethod(methods, 100), null);
});

// SARD_80_F1 W4.C22 (fix for the regression found and reverted at W4.C21):
// a "bad"-shaped method whose entire body is a delegating call to another
// bad-shaped method (Juliet's own multi-file flow-variant convention) has
// no sink of its own, so buildJulietExpected/buildJulietCsExpected must not
// emit an unsatisfiable expected entry for it — see _isDelegateOnlyBadMethod's
// header comment for the full incident writeup.
// NOTE: `delegateTargetRe` below is deliberately NARROWER than the
// `isBad`-style pattern used to decide which methods get their own
// expected entry (see _isDelegateOnlyBadMethod's header comment,
// incident (2)) — it must EXCLUDE `*Source`-shaped names, since a call to
// a same-class `BadSource()`/`badSource()` helper only supplies data and
// never completes the flaw.
const CS_DELEGATE_TARGET_RE = /^Bad(?:Sink)?\d*$/;
const JAVA_DELEGATE_TARGET_RE = /^(?:bad|badSink|bad\d+)$/;

test('_isDelegateOnlyBadMethod: a C# Bad() that only calls a sibling BadSink is a delegate', () => {
  const src = `
class Caller : AbstractTestCaseWeb {
    public override void Bad(HttpRequest req, HttpResponse resp) {
        string data;
        data = "";
        if (req.QueryString["id"] != null) { data = req.QueryString["id"]; }
        Sink.BadSink(data , req, resp );
    }
}
`;
  const methods = findCsharpMethodSpans(src);
  const bad = methods.find((m) => m.name === 'Bad');
  assert.ok(bad, 'expected to find the Bad() method span');
  assert.ok(_isDelegateOnlyBadMethod(bad, CS_DELEGATE_TARGET_RE), 'a method that only calls Sink.BadSink(...) must be recognized as a delegate');
});

test('_isDelegateOnlyBadMethod: a C# BadSink that directly contains the sink is NOT a delegate', () => {
  const src = `
class Sink {
    public static void BadSink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
            resp.Redirect(data);
        }
    }
}
`;
  const methods = findCsharpMethodSpans(src);
  const badSink = methods.find((m) => m.name === 'BadSink');
  assert.ok(badSink, 'expected to find the BadSink() method span');
  assert.equal(_isDelegateOnlyBadMethod(badSink, CS_DELEGATE_TARGET_RE), false, 'a method with its own direct sink call must NOT be flagged as a delegate');
});

// Regression test for a real bug this fix's OWN first attempt introduced
// (found via a real corpus A/B before landing, see W4.C22's ledger entry):
// Juliet's generated sink lines embed a diagnostic STRING LITERAL that
// unconditionally labels itself "Bad()" regardless of the enclosing
// method's real name (`resp.Write("<br>Bad(): data = " + data);`) — a raw
// text scan for "Bad(" matches THIS literal exactly as readily as a real
// delegate call, wrongly flagging a BadSink()/BadSource() method (whose own
// name differs from "Bad", so the anti-recursion guard doesn't protect it)
// as a delegate even though it directly contains the real sink.
test('_isDelegateOnlyBadMethod: a diagnostic string literal naming "Bad()" inside a DIFFERENT method must NOT be mistaken for a delegate call', () => {
  const src = `
class C : AbstractTestCaseWeb {
    public override void BadSink(HttpRequest req, HttpResponse resp) {
        string data = req.QueryString["id"];
        if (data != null) {
            resp.Write("<br>Bad(): data = " + data);
        }
    }
}
`;
  const methods = findCsharpMethodSpans(src);
  const badSink = methods.find((m) => m.name === 'BadSink');
  assert.ok(badSink, 'expected to find the BadSink() method span');
  assert.equal(_isDelegateOnlyBadMethod(badSink, CS_DELEGATE_TARGET_RE), false,
    'a "Bad():" diagnostic label embedded in a string literal must not be mistaken for a delegate call to a method literally named Bad');
});

// Second regression test (found via the SAME real corpus A/B, a second,
// distinct false positive after fix (1) landed): Juliet's "data returned
// from one method to another in the SAME CLASS" flow variant (confirmed
// via the public mirror, CWE90_LDAP_Injection__Environment_42.cs) has
// Bad() call a private, same-file `BadSource()` helper purely to fetch
// tainted data, then directly build and reach the real sink itself. A
// call to a `*Source`-shaped name must never count as delegation.
test('_isDelegateOnlyBadMethod: a C# Bad() that calls a same-class BadSource() helper (but has its own sink) is NOT a delegate', () => {
  const src = `
class C : AbstractTestCase {
    private static string BadSource() {
        string data;
        data = Environment.GetEnvironmentVariable("ADD");
        return data;
    }
    public override void Bad() {
        string data = BadSource();
        using (DirectoryEntry de = new DirectoryEntry()) {
            using (DirectorySearcher search = new DirectorySearcher(de)) {
                search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
            }
        }
    }
}
`;
  const methods = findCsharpMethodSpans(src);
  const bad = methods.find((m) => m.name === 'Bad');
  assert.ok(bad, 'expected to find the Bad() method span');
  assert.equal(_isDelegateOnlyBadMethod(bad, CS_DELEGATE_TARGET_RE), false,
    'a call to a same-class BadSource() data helper must not be mistaken for delegating the flaw — Bad() here directly contains the real sink');
});

test('_isDelegateOnlyBadMethod: a Java bad() that only calls badSink is a delegate; recursion into itself does not count', () => {
  const delegating = findJavaMethodSpans(`
class Caller {
    public void bad(String data) throws Throwable {
        data = System.getenv("ADD");
        (new Sink()).badSink(data);
    }
}
`).find((m) => m.name === 'bad');
  assert.ok(delegating);
  assert.ok(_isDelegateOnlyBadMethod(delegating, JAVA_DELEGATE_TARGET_RE));

  const direct = findJavaMethodSpans(`
class Sink {
    public void badSink(String data) throws Throwable {
        if (data != null) {
            Runtime.getRuntime().exec(data);
        }
    }
}
`).find((m) => m.name === 'badSink');
  assert.ok(direct);
  assert.equal(_isDelegateOnlyBadMethod(direct, JAVA_DELEGATE_TARGET_RE), false);
});

// SARD_80_F1 W4.J32 — a middle-of-chain hop whose OWN method is named
// identically to its delegate target (Juliet's Flow Variant 54: `badSink`
// calling a DIFFERENT class's own `badSink`) must still be recognized as a
// delegate. Before this fix, the anti-recursion guard's bare name
// comparison (`callee !== meth.name`) treated this as self-recursion since
// both the caller and the receiver-qualified callee are named "badSink".
test('_isDelegateOnlyBadMethod: a Java badSink() that delegates to a DIFFERENT class\'s identically-named badSink() is a delegate, not self-recursion', () => {
  const midHop = findJavaMethodSpans(`
class Hop3 {
    public void badSink(String data) throws Throwable {
        (new Hop4()).badSink(data);
    }
}
`).find((m) => m.name === 'badSink');
  assert.ok(midHop);
  assert.ok(_isDelegateOnlyBadMethod(midHop, JAVA_DELEGATE_TARGET_RE),
    'a receiver-qualified call to a same-named method on a DIFFERENT object must count as delegation');

  // A genuine BARE self-recursive call (no receiver at all) must still be
  // exempted — this is real same-object recursion, not delegation.
  const trueRecursion = findJavaMethodSpans(`
class Hop3 {
    public void badSink(String data, int depth) throws Throwable {
        if (depth > 0) {
            badSink(data, depth - 1);
        } else {
            Runtime.getRuntime().exec(data);
        }
    }
}
`).find((m) => m.name === 'badSink');
  assert.ok(trueRecursion);
  assert.equal(_isDelegateOnlyBadMethod(trueRecursion, JAVA_DELEGATE_TARGET_RE), false,
    'a bare, unqualified self-recursive call must NOT be mistaken for delegation');
});

test('_isDelegateOnlyBadMethod: a Java bad() that calls a same-class badSource() helper (but has its own sink) is NOT a delegate', () => {
  const bad = findJavaMethodSpans(`
class C {
    private static String badSource() throws Throwable {
        String data;
        data = System.getenv("ADD");
        return data;
    }
    public void bad() throws Throwable {
        String data = badSource();
        Runtime.getRuntime().exec(data);
    }
}
`).find((m) => m.name === 'bad');
  assert.ok(bad, 'expected to find the bad() method span');
  assert.equal(_isDelegateOnlyBadMethod(bad, JAVA_DELEGATE_TARGET_RE), false,
    'a call to a same-class badSource() data helper must not be mistaken for delegating the flaw');
});

test('buildSameFileCallGraph + reachableFrom: resolves a same-file call edge', () => {
  const content = [
    /* 1 */ 'public void Bad()',
    /* 2 */ '{',
    /* 3 */ '    Helper(x);',
    /* 4 */ '}',
    /* 5 */ 'private void Helper(string data)',
    /* 6 */ '{',
    /* 7 */ '    Sink(data);',
    /* 8 */ '}',
  ].join('\n');
  const methods = [
    { name: 'Bad', startLine: 1, endLine: 4 },
    { name: 'Helper', startLine: 5, endLine: 8 },
  ];
  const graph = buildSameFileCallGraph(content, methods);
  const reachable = reachableFrom(graph, 'Bad');
  assert.equal(reachable.has('Helper'), true);
  assert.equal(reachable.has('Bad'), false); // reachableFrom excludes the start node itself
});

test('reachableFrom: unrelated methods are not reachable', () => {
  const content = [
    'public void Bad() { Helper(); }',
    'private void Helper() { }',
    'public void Unrelated() { }',
  ].join('\n');
  const methods = [
    { name: 'Bad', startLine: 1, endLine: 1 },
    { name: 'Helper', startLine: 2, endLine: 2 },
    { name: 'Unrelated', startLine: 3, endLine: 3 },
  ];
  const graph = buildSameFileCallGraph(content, methods);
  const reachable = reachableFrom(graph, 'Bad');
  assert.equal(reachable.has('Unrelated'), false);
});

async function writeFixture(rel, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'sard-flow-score-'));
  const abs = path.join(root, rel);
  await fs.mkdir(path.dirname(abs), { recursive: true });
  await fs.writeFile(abs, content, 'utf8');
  return root;
}

const CS_REL = 'src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__test_01.cs';

function csContent({ sharedWithGood }) {
  const goodCall = sharedWithGood ? '        Helper(safe);\n' : '';
  return [
    'public class CWE90_LDAP_Injection__test_01',
    '{',
    '    public void Bad()',
    '    {',
    '        string tainted = GetInput();',
    '        Helper(tainted);',
    '    }',
    '',
    '    private void Helper(string data)',
    '    {',
    '        DirectorySearcher searcher = new DirectorySearcher();',
    '        searcher.Filter = data;',
    '    }',
    '',
    '    public void GoodG2B()',
    '    {',
    '        string safe = "constant";',
    goodCall.replace(/\n$/, ''),
    '    }',
    '}',
    '',
  ].filter((l, idx, arr) => !(l === '' && arr[idx - 1] === '')).join('\n');
}

test('score(): credits a finding relocated to a same-file helper the expected Bad() method calls', async () => {
  const content = csContent({ sharedWithGood: false });
  const root = await writeFixture(CS_REL, content);
  try {
    const methods = findCsharpMethodSpans(content);
    const bad = methods.find(m => m.name === 'Bad');
    const helper = methods.find(m => m.name === 'Helper');
    assert.ok(bad && helper, 'fixture must parse Bad() and Helper() spans');
    const sinkLine = content.split('\n').findIndex(l => l.includes('searcher.Filter = data')) + 1;
    assert.ok(sinkLine > helper.startLine && sinkLine < helper.endLine, 'sink line must sit inside Helper(), not Bad()');

    const expected = [{
      file: CS_REL, line: bad.startLine, lineEnd: bad.endLine,
      lineTolerance: 0, matchAny: true, family: 'ldap-injection', cwe: 'CWE90', method: 'Bad',
    }];
    const actual = [{ file: path.join(root, CS_REL), line: sinkLine, vuln: 'ldap-injection' }];

    const { tps, fps, fns } = await score(actual, expected, {}, root, [], root);
    assert.equal(tps.length, 1, 'the relocated finding should be credited as a TP');
    assert.equal(fps.length, 0, 'the same finding must not ALSO count as an FP');
    assert.equal(fns.length, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

// PRD §9.4 "Separate score-only delta from scanner delta": scoreLegacy is
// the strict, pre-§9.1 matcher, deliberately kept callable so a report can
// show both numbers from ONE scan. This is the isolation proof: the EXACT
// same actual[]/expected[] that score() credits (test just above) must be
// an FN+FP under scoreLegacy — if it weren't, the scorer-delta diagnostic
// would be measuring nothing.
test('scoreLegacy(): does NOT credit the same relocated finding score() credits — same actual/expected, no call-graph fallback', () => {
  const content = csContent({ sharedWithGood: false });
  const methods = findCsharpMethodSpans(content);
  const bad = methods.find(m => m.name === 'Bad');
  const sinkLine = content.split('\n').findIndex(l => l.includes('searcher.Filter = data')) + 1;

  const expected = [{
    file: CS_REL, line: bad.startLine, lineEnd: bad.endLine,
    lineTolerance: 0, matchAny: true, family: 'ldap-injection', cwe: 'CWE90', method: 'Bad',
  }];
  // Absolute path doesn't matter here — scoreLegacy never reads the
  // filesystem (no call-graph lookup at all), unlike score().
  const actual = [{ file: `/fake/${CS_REL}`, line: sinkLine, vuln: 'ldap-injection' }];

  const { tps, fps, fns } = scoreLegacy(actual, expected, {}, []);
  assert.equal(tps.length, 0, 'scoreLegacy must not apply the flow-aware fallback');
  assert.equal(fps.length, 1, 'the relocated finding is a real FP under strict line-range matching');
  assert.equal(fns.length, 1, 'and the expected Bad() entry is a real FN under strict line-range matching');
});

test('scoreLegacy() and score() agree on a DIRECT match (both credit a finding inside Bad()\'s own span)', () => {
  const content = csContent({ sharedWithGood: false });
  const methods = findCsharpMethodSpans(content);
  const bad = methods.find(m => m.name === 'Bad');
  const expected = [{
    file: CS_REL, line: bad.startLine, lineEnd: bad.endLine,
    lineTolerance: 0, matchAny: true, family: 'ldap-injection', cwe: 'CWE90', method: 'Bad',
  }];
  const actual = [{ file: `/fake/${CS_REL}`, line: bad.startLine + 1, vuln: 'ldap-injection' }];
  const { tps, fps } = scoreLegacy(actual, expected, {}, []);
  assert.equal(tps.length, 1);
  assert.equal(fps.length, 0);
});

test('score(): does NOT credit a helper that is also reachable from a Good*() method (PRD §9.2)', async () => {
  const content = csContent({ sharedWithGood: true });
  const root = await writeFixture(CS_REL, content);
  try {
    const methods = findCsharpMethodSpans(content);
    const bad = methods.find(m => m.name === 'Bad');
    const helper = methods.find(m => m.name === 'Helper');
    const good = methods.find(m => m.name === 'GoodG2B');
    assert.ok(bad && helper && good, 'fixture must parse Bad(), Helper(), GoodG2B() spans');
    const sinkLine = content.split('\n').findIndex(l => l.includes('searcher.Filter = data')) + 1;

    const expected = [{
      file: CS_REL, line: bad.startLine, lineEnd: bad.endLine,
      lineTolerance: 0, matchAny: true, family: 'ldap-injection', cwe: 'CWE90', method: 'Bad',
    }];
    const actual = [{ file: path.join(root, CS_REL), line: sinkLine, vuln: 'ldap-injection' }];

    const { tps, fps, fns } = await score(actual, expected, {}, root, [], root);
    assert.equal(tps.length, 0, 'a helper shared with the safe path must not be credited');
    assert.equal(fps.length, 1, 'the unmatched finding remains a (conservative) FP');
    assert.equal(fns.length, 1, 'the expected Bad() entry remains an (conservative) FN');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('score(): unrelated same-file finding with no call-graph path from Bad() is still an FP, not credited', async () => {
  const content = [
    'public class CWE90_LDAP_Injection__test_01',
    '{',
    '    public void Bad()',
    '    {',
    '        Helper(GetInput());',
    '    }',
    '',
    '    private void Helper(string data)',
    '    {',
    '        DirectorySearcher searcher = new DirectorySearcher();',
    '        searcher.Filter = data;',
    '    }',
    '',
    '    private void Unrelated()',
    '    {',
    '        DirectorySearcher other = new DirectorySearcher();',
    '        other.Filter = "unrelated";',
    '    }',
    '}',
    '',
  ].join('\n');
  const root = await writeFixture(CS_REL, content);
  try {
    const methods = findCsharpMethodSpans(content);
    const bad = methods.find(m => m.name === 'Bad');
    const unrelatedLine = content.split('\n').findIndex(l => l.includes('other.Filter')) + 1;

    const expected = [{
      file: CS_REL, line: bad.startLine, lineEnd: bad.endLine,
      lineTolerance: 0, matchAny: true, family: 'ldap-injection', cwe: 'CWE90', method: 'Bad',
    }];
    const actual = [{ file: path.join(root, CS_REL), line: unrelatedLine, vuln: 'ldap-injection' }];

    const { tps, fps, fns } = await score(actual, expected, {}, root, [], root);
    assert.equal(tps.length, 0, 'a method never called from Bad() must not be credited');
    assert.equal(fps.length, 1);
    assert.equal(fns.length, 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('score(): unchanged behavior — a finding directly inside Bad()\'s own span still matches without touching the fallback', async () => {
  const content = csContent({ sharedWithGood: false });
  const root = await writeFixture(CS_REL, content);
  try {
    const methods = findCsharpMethodSpans(content);
    const bad = methods.find(m => m.name === 'Bad');

    const expected = [{
      file: CS_REL, line: bad.startLine, lineEnd: bad.endLine,
      lineTolerance: 0, matchAny: true, family: 'ldap-injection', cwe: 'CWE90', method: 'Bad',
    }];
    const actual = [{ file: path.join(root, CS_REL), line: bad.startLine + 1, vuln: 'ldap-injection' }];

    const { tps, fps } = await score(actual, expected, {}, root, [], root);
    assert.equal(tps.length, 1);
    assert.equal(fps.length, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
