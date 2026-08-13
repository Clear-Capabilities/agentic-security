// PRD R5 (docs/DETECTION_GAP_REMEDIATION_PRD.md): two more Java bench-shape
// mechanisms were opt-OUT (disabled only when AGENTIC_SECURITY_BLIND_BENCH=1
// is explicitly set) rather than opt-IN (enabled only when
// AGENTIC_SECURITY_BENCH_SHAPE=1 is explicitly set) — inverted from the
// documented default the root CLAUDE.md's "Bench-shape isolation" bullet
// describes, and from the correctly-gated @WebServlet/juliet-path
// mechanisms elsewhere in this same file.
//
// (a) OWASP_BENCH_PROPS hardcodes OWASP Benchmark's own benchmark.properties
//     answer key (hashAlg1 -> MD5, cryptoAlg1 -> DES/ECB...). A real project
//     whose properties file is missing or unparsed got a fabricated weak-
//     algorithm finding purely because a property KEY happened to be named
//     the same as OWASP's own key.
// (b) The Juliet-shape collection-parameter taint source (badSink/badSource/
//     goodG2B/goodB2G naming convention) treated ANY container-typed
//     parameter in a file using that naming convention as tainted, useful
//     only for scoring OWASP's own fixtures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-benchshape-${name}-`));
  fs.writeFileSync(path.join(dir, 'Bad.java'), content);
  return dir;
}

test('(a) OWASP_BENCH_PROPS answer-key fallback does not fire by default (no BENCH_SHAPE set)', async () => {
  delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  const dir = mkTmp('props', `
import java.security.MessageDigest;
import java.util.Properties;
public class Bad {
  static Properties props = new Properties();
  public void hash(byte[] b) throws Exception {
    String alg = props.getProperty("hashAlg1", "SHA-256");
    MessageDigest md = MessageDigest.getInstance(alg);
    md.update(b);
  }
}
`);
  const { scan } = await runScan(dir);
  const weakCrypto = (scan.findings || []).filter((f) => /Weak Cryptographic Hash/i.test(f.vuln || ''));
  assert.equal(weakCrypto.length, 0,
    `expected no finding from OWASP's own answer-key fallback without opt-in, got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
});

test('(a) OWASP_BENCH_PROPS answer-key fallback DOES fire under explicit opt-in (mechanism still works)', async () => {
  process.env.AGENTIC_SECURITY_BENCH_SHAPE = '1';
  try {
    const dir = mkTmp('props-optin', `
import java.security.MessageDigest;
import java.util.Properties;
public class Bad {
  static Properties props = new Properties();
  public void hash(byte[] b) throws Exception {
    String alg = props.getProperty("hashAlg1", "SHA-256");
    MessageDigest md = MessageDigest.getInstance(alg);
    md.update(b);
  }
}
`);
    const { scan } = await runScan(dir);
    const weakCrypto = (scan.findings || []).filter((f) => /Weak Cryptographic Hash/i.test(f.vuln || ''));
    assert.ok(weakCrypto.length >= 1, 'expected the answer-key fallback to still work under explicit BENCH_SHAPE=1');
  } finally {
    delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  }
});

test('(b) Juliet-shape collection-parameter taint source does not fire by default (no BENCH_SHAPE set)', async () => {
  delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  const dir = mkTmp('collection', `
import java.util.Vector;
public class Bad {
  public static void badSink(Vector<String> data) throws Exception {
    Runtime.getRuntime().exec((String) data.get(0));
  }
}
`);
  const { scan } = await runScan(dir);
  const cmdi = (scan.findings || []).filter((f) => /Command Injection/i.test(f.vuln || ''));
  assert.equal(cmdi.length, 0,
    `expected no finding from the Juliet-shape collection-parameter source without opt-in, got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
});

test('(b) Juliet-shape collection-parameter taint source DOES fire under explicit opt-in (mechanism still works)', async () => {
  process.env.AGENTIC_SECURITY_BENCH_SHAPE = '1';
  try {
    const dir = mkTmp('collection-optin', `
import java.util.Vector;
public class Bad {
  public static void badSink(Vector<String> data) throws Exception {
    Runtime.getRuntime().exec((String) data.get(0));
  }
}
`);
    const { scan } = await runScan(dir);
    const cmdi = (scan.findings || []).filter((f) => /Command Injection/i.test(f.vuln || ''));
    assert.ok(cmdi.length >= 1, 'expected the Juliet-shape collection source to still work under explicit BENCH_SHAPE=1');
  } finally {
    delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  }
});
