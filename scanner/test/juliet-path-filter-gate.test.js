// PRD R5 (docs/DETECTION_GAP_REMEDIATION_PRD.md): the root CLAUDE.md's
// documented convention is that bench-shape answer-key reading is off by
// default, gated behind AGENTIC_SECURITY_BENCH_SHAPE=1. The `@WebServlet`
// category-reading variant (_javaWebServletCategory, engine.js) correctly
// honors that gate. The `juliet-cwe<N>/` PATH-PREFIX variant did not: any
// Java file under such a path had off-family findings silently deleted
// unconditionally, in the default pipeline, with no way to opt out short of
// renaming the directory. A real repository with a directory that happens to
// be named `juliet-cwe89/` (or similar) would lose real, off-family findings
// silently.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkJavaFixture() {
  // MessageDigest.getInstance("MD5") fires a weak-crypto-family finding
  // (`_javaFamilyForFinding` maps "Weak Cryptographic Hash (MD5/SHA1) —
  // Java" to 'weak-crypto'). Placed under a `juliet-cwe89/` path, whose
  // declared family per _JULIET_CWE_TO_FAMILY is 'sql-injection' — an
  // unrelated family, so this finding is exactly the "off-family" shape the
  // filter targets.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-julietgate-'));
  const sub = path.join(dir, 'juliet-cwe89', 'src');
  fs.mkdirSync(sub, { recursive: true });
  fs.writeFileSync(path.join(sub, 'Bad.java'), `
import java.security.MessageDigest;
public class Bad {
  public void hash(String pw) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(pw.getBytes());
  }
}
`);
  return dir;
}

test('an off-family finding under a juliet-cwe*/ path survives by default (bench-shape filter is opt-in)', async () => {
  delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  const dir = mkJavaFixture();
  const { scan } = await runScan(dir);
  const weakCrypto = (scan.findings || []).filter((f) => /Weak Cryptographic Hash/i.test(f.vuln || ''));
  assert.ok(weakCrypto.length >= 1,
    `expected the weak-crypto finding to survive by default (no AGENTIC_SECURITY_BENCH_SHAPE set) — the juliet-cwe path filter must not run unconditionally. Findings: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
});

test('the same off-family finding IS suppressed when AGENTIC_SECURITY_BENCH_SHAPE=1 is explicitly set (mechanism still works)', async () => {
  process.env.AGENTIC_SECURITY_BENCH_SHAPE = '1';
  try {
    const dir = mkJavaFixture();
    const { scan } = await runScan(dir);
    const weakCrypto = (scan.findings || []).filter((f) => /Weak Cryptographic Hash/i.test(f.vuln || ''));
    assert.equal(weakCrypto.length, 0,
      `expected the off-family finding to be suppressed under explicit opt-in BENCH_SHAPE=1, got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
  } finally {
    delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  }
});
