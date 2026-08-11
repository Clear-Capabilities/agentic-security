// Kotlin deep-taint recall.
//
// `bench/layer-recall` measured Kotlin at 0/20 IR-TAINT recall while all 20 of
// its corpus entries passed on other layers. The cause is not the parser and not
// the sources: Kotlin IR lowers assignments correctly and the catalog carries 5
// Kotlin sources (getParameter/getHeader/ktor receive/parameters/getenv). It
// carried **zero Kotlin sinks**, so a tainted value had nowhere to terminate and
// no flow could ever be reported.
//
// Kotlin runs on the JVM and calls the same JDBC/Runtime/File APIs as Java, for
// which sinks already exist — the catalog is language-scoped (`_languageAllowed`),
// so Java's entries never applied to a .kt file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', n);

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

test('IR-TAINT: kotlin request param flowing into executeUpdate is reported', async () => {
  const findings = await deepScan(FIX('kt-taint-flow/vulnerable'));
  const taint = findings.filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected an IR-TAINT SQL finding for Kotlin, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: the same kotlin sink with a constant does not fire', async () => {
  // The precision half. A sink entry that fires regardless of taint would pass
  // the test above while making every Kotlin JDBC call a finding.
  const findings = await deepScan(FIX('kt-taint-flow/clean'));
  const taint = findings.filter(f => f.parser === 'IR-TAINT');
  assert.equal(taint.filter(f => /sql/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `constant-built SQL must not produce an IR-TAINT finding, got: ${taint.map(f => f.vuln).join(', ')}`);
});
