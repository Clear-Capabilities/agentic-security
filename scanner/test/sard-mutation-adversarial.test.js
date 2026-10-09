// SARD_AGENTIC_SECURITY_PRD.md adversarial-premortem remediation, Round 2 F6
// — bench/sard/scripts/mutate.mjs previously only measured the METAMORPHIC
// side of Semantic Robustness Rate (a behavior-preserving rewrite must not
// move the verdict). PRD §26's own "safe-code mutation stability" and
// bench/mutation/runner.mjs's own established two-sided design (metamorphic
// must HOLD, adversarial must FLIP) were never built for the SARD corpus.
//
// This unit-tests the new `mutateAdversarialLiteralization` pure function
// directly — the mechanical text transform, offline and fast — reusing the
// real exported function, never a reimplementation. The full end-to-end
// proof (does the SCANNER's verdict actually flip on real code) is proven
// separately, once, in `test/java-taint-flow.test.js`-adjacent style below,
// and documented in bench/sard/IMPLEMENTATION_STATUS.md with the real,
// measured result this discovered: the mutation correctly severs real taint
// (IR-TAINT stops firing) but a structural Java SQL-injection detector
// still fires on the same concatenation SHAPE regardless of whether the
// concatenated value is genuinely tainted — a real, disclosed precision
// gap this new mutation type exists specifically to surface, not a bug in
// the mutator itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mutateAdversarialLiteralization } from '../../bench/sard/scripts/mutate.mjs';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';

test('mutateAdversarialLiteralization: replaces a String initializer with a hardcoded literal, keeping the variable name', () => {
  const content = [
    'public class A {',
    '  public void bad(javax.servlet.http.HttpServletRequest req) {',
    '    String data = req.getParameter("cmd");',
    '    Runtime.getRuntime().exec(data);',
    '  }',
    '}',
  ].join('\n');
  const span = { startLine: 1, endLine: 6 };
  const result = mutateAdversarialLiteralization(content, span);
  assert.ok(result, 'expected a mutation to be produced');
  assert.match(result.content, /String data = "sard_adversarial_literal";/);
  // The sink call site is UNCHANGED — only the initializer moved, proving
  // this severs taint at the SOURCE, not by touching the sink at all.
  assert.match(result.content, /Runtime\.getRuntime\(\)\.exec\(data\);/);
});

test('mutateAdversarialLiteralization: non-String primitive types get a type-appropriate literal, never a string', () => {
  const content = [
    'public class A {',
    '  public void bad() {',
    '    int count = getUntrustedCount();',
    '    doSomething(count);',
    '  }',
    '}',
  ].join('\n');
  const span = { startLine: 1, endLine: 5 };
  const result = mutateAdversarialLiteralization(content, span);
  assert.ok(result);
  assert.match(result.content, /int count = 0;/);
});

test('mutateAdversarialLiteralization: no matching declaration shape returns null, never fabricates one', () => {
  const content = 'public class A { public void bad() { sink(source()); } }';
  const span = { startLine: 1, endLine: 1 };
  assert.equal(mutateAdversarialLiteralization(content, span), null);
});

test('mutateAdversarialLiteralization: only the FIRST matching declaration in the span is touched', () => {
  const content = [
    'public class A {',
    '  public void bad() {',
    '    String first = source1();',
    '    String second = source2();',
    '    sink(first, second);',
    '  }',
    '}',
  ].join('\n');
  const span = { startLine: 1, endLine: 6 };
  const result = mutateAdversarialLiteralization(content, span);
  assert.ok(result);
  assert.match(result.content, /String first = "sard_adversarial_literal";/);
  assert.match(result.content, /String second = source2\(\);/, 'the second declaration must be left untouched');
});

// ── End-to-end proof: the mutation genuinely severs real IR-TAINT flow. ────
// (Mirrors test/java-taint-flow.test.js's own AGENTIC_SECURITY_DEEP*
// env-var pattern exactly — the file MUST be named to match its public
// class, or Java parsing silently fails and produces zero findings, a real
// footgun found while building this test.)

function mkTmp(name, javaSource, className) {
  const dir = mkTestTmp(`as-sard-adv-mut-${name}-`);
  fs.writeFileSync(path.join(dir, `${className}.java`), javaSource);
  return dir;
}

async function deepScan(dir) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  }
}

test('adversarial mutation end-to-end: severing the source removes the IR-TAINT finding (verdict correctly flips for the real taint engine)', async () => {
  const original = [
    'public class A {',
    '  public void bad(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {',
    '    String q = req.getParameter("q");',
    '    stmt.executeUpdate("SELECT * FROM t WHERE a = \'" + q + "\'");',
    '  }',
    '}',
  ].join('\n');
  const span = { startLine: 1, endLine: 6 };
  const mutated = mutateAdversarialLiteralization(original, span);
  assert.ok(mutated);

  const origFindings = await deepScan(mkTmp('orig', original, 'A'));
  assert.ok(origFindings.some((f) => f.parser === 'IR-TAINT'),
    `expected the ORIGINAL to fire via IR-TAINT, got: ${JSON.stringify(origFindings.map((f) => f.parser))}`);

  const mutatedFindings = await deepScan(mkTmp('mutated', mutated.content, 'A'));
  assert.equal(mutatedFindings.filter((f) => f.parser === 'IR-TAINT').length, 0,
    `expected the IR-TAINT finding to disappear once the source is a hardcoded literal, got: ${JSON.stringify(mutatedFindings)}`);
});
