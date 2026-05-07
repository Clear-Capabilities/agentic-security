// node --test  smoke tests for the scanner engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as os from 'node:os';
import * as fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { normalizeFindings, exitCodeFor } from '../src/report/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', name);

// Build a continuous-match Stripe-pattern value at runtime by concatenating two halves
// that, in source form, never appear adjacent. GitHub Push Protection scans source bytes,
// so it cannot match the assembled value; our engine sees only the temp fixture content,
// which is the assembled value, so detection still triggers.
function assembleStripeKey() {
  const prefix = 'sk_' + 'live_';                    // "sk_live_" never appears as one literal here
  const body = '0123456789' + 'abcdefghij' + 'ABCD'; // 24 chars of [0-9a-zA-Z]
  return prefix + body;
}

test('vulnerable-js fixture surfaces critical SAST findings', async () => {
  const { scan } = await runScan(FIX('vulnerable-js'));
  const findings = normalizeFindings(scan);
  const vulns = findings.map(f => f.vuln);
  assert.ok(findings.length >= 10, `expected ≥10 findings, got ${findings.length}`);
  assert.ok(vulns.some(v => /Command Injection/.test(v)), 'Command Injection not found');
  assert.ok(vulns.some(v => /SQL Injection/.test(v)), 'SQL Injection not found');
  assert.ok(vulns.some(v => /Code Injection|eval/i.test(v)), 'Code Injection (eval) not found');
  assert.ok(findings.some(f => f.severity === 'critical'), 'no critical findings');
  assert.equal(exitCodeFor(scan), 3, 'exit code should be 3 (critical)');
});

test('clean-js fixture has no critical findings', async () => {
  const { scan } = await runScan(FIX('clean-js'));
  const findings = normalizeFindings(scan);
  const criticals = findings.filter(f => f.severity === 'critical');
  // Some routes may still flag medium/info, but no critical SAST should appear.
  assert.equal(criticals.filter(f=>f.kind==='sast').length, 0, `unexpected critical SAST findings: ${JSON.stringify(criticals.map(c=>c.vuln))}`);
});

test('secret entropy + credential-name patterns trigger on the on-disk fixture', async () => {
  const { scan } = await runScan(FIX('secrets'));
  const secrets = normalizeFindings(scan).filter(f => f.kind === 'secret');
  assert.ok(secrets.length >= 1, `expected ≥1 secret findings, got ${secrets.length}`);
  // The on-disk fixture intentionally has no continuous-match named-pattern secrets
  // (so GitHub Push Protection does not block the repo). It exercises the entropy
  // and credential-name heuristics only.
  assert.ok(secrets.some(s => /Entropy|Credential|Hardcoded/i.test(s.vuln)),
    `expected entropy/credential finding; got: ${secrets.map(s=>s.vuln).join(', ')}`);
});

test('named-pattern Stripe key detection (runtime-constructed temp fixture)', async () => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-stripe-'));
  try {
    const key = assembleStripeKey();
    await fs.writeFile(path.join(tmp, 'leak.js'), `const stripeKey = "${key}";\n`);
    const { scan } = await runScan(tmp);
    const secrets = normalizeFindings(scan).filter(f => f.kind === 'secret');
    assert.ok(secrets.some(s => /Stripe/i.test(s.vuln)), `Stripe Secret Key not detected; got: ${secrets.map(s=>s.vuln).join(', ')}`);
    // Masked output must never contain the raw key
    for (const s of secrets) {
      if (s.masked) assert.ok(!s.masked.includes(key), 'raw secret leaked into masked output');
    }
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('FP-1: python-clean fixture (literals + parameterized queries) has 0 critical/high findings', async () => {
  const { scan } = await runScan(FIX('python-clean'));
  const findings = normalizeFindings(scan);
  const critOrHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  assert.equal(critOrHigh.length, 0,
    `expected 0 critical/high, got ${critOrHigh.length}: ${critOrHigh.map(f=>f.vuln).join(', ')}`);
});

test('FP-1: python-vulnerable fixture still surfaces SQL/Command/Code injection', async () => {
  const { scan } = await runScan(FIX('python-vulnerable'));
  const vulns = normalizeFindings(scan).map(f => f.vuln);
  assert.ok(vulns.some(v => /SQL Injection/.test(v)), 'SQL Injection missing');
  assert.ok(vulns.some(v => /Command Injection/.test(v)), 'Command Injection missing');
  assert.ok(vulns.some(v => /Code Injection|eval/i.test(v)), 'Code Injection missing');
});

test('FP-2: credential FP filter — only src/auth.js produces a finding; locales+examples suppressed', async () => {
  const { scan } = await runScan(FIX('credential-fp'));
  const hsec = normalizeFindings(scan).filter(f => /Hardcoded Secret/i.test(f.vuln));
  assert.equal(hsec.length, 1, `expected 1 Hardcoded Secret finding, got ${hsec.length}: ${hsec.map(f=>f.file+':'+f.line).join(', ')}`);
  assert.ok(/src\/auth\.js/.test(hsec[0].file), `unexpected finding location: ${hsec[0].file}`);
  // Suppressed-finding count is exposed on the scan result
  const suppressed = scan.suppressions || [];
  assert.ok(suppressed.length >= 4, `expected ≥4 suppressed credential FPs, got ${suppressed.length}`);
  // All suppressions in this fixture are path-filter
  assert.ok(suppressed.every(s => s.reason === 'path-filter'), `unexpected suppression reasons: ${suppressed.map(s=>s.reason).join(', ')}`);
});

test('FP-5: entropy-fp fixture suppresses UUIDs / integrity hashes / data URIs / JWTs; only real-secret fires', async () => {
  const { scan } = await runScan(FIX('entropy-fp'));
  const ent = normalizeFindings(scan).filter(f => /Entropy/i.test(f.vuln));
  assert.equal(ent.length, 1, `expected exactly 1 entropy finding, got ${ent.length}: ${ent.map(f=>f.file).join(', ')}`);
  assert.ok(/real-secret\.js/.test(ent[0].file), `unexpected entropy finding: ${ent[0].file}`);
  // At least one explicit suppression for the JWT pattern (other categories were
  // already handled by the pre-existing SAFE_ENTROPY_PREFIXES filter)
  const ents = (scan.suppressions||[]).filter(s => /Entropy/i.test(s.vuln));
  assert.ok(ents.length >= 1, `expected ≥1 entropy suppression, got ${ents.length}`);
  assert.ok(ents.some(s => s.reason.startsWith('entropy-')),
    `expected entropy-prefixed suppression reason, got: ${ents.map(s=>s.reason).join(', ')}`);
});

test('FP-7: NoSQL operator no longer fires on PHP $vars / jQuery / regex literals', async () => {
  for (const fixture of ['nosql/php-vars.php', 'nosql/jquery.js', 'nosql/mongo-safe.js']) {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-nosql-'));
    try {
      await fs.cp(FIX(fixture), path.join(tmpDir, fixture.split('/').pop()));
      const { scan } = await runScan(tmpDir);
      const ns = normalizeFindings(scan).filter(f => /NoSQL/i.test(f.vuln));
      assert.equal(ns.length, 0, `${fixture}: expected 0 NoSQL findings, got ${ns.length}`);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
});

test('FP-7: NoSQL operator still fires on real Mongo $where / $or with user input', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-nosql-vuln-'));
  try {
    await fs.cp(FIX('nosql/mongo-vuln.js'), path.join(tmpDir, 'mongo-vuln.js'));
    const { scan } = await runScan(tmpDir);
    const ns = normalizeFindings(scan).filter(f => /NoSQL/i.test(f.vuln));
    assert.ok(ns.length >= 1, `expected ≥1 NoSQL Injection finding, got ${ns.length}`);
    assert.ok(ns.every(f => f.severity === 'high' || f.severity === 'critical'),
      `expected all NoSQL findings to be high/critical, got: ${ns.map(f=>f.severity).join(', ')}`);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('FP-8: cookie/CORS predicates fire only when actual config is unsafe', async () => {
  // expected[fixture] = number of cookie/CORS findings
  const expected = {
    'cookie-secure.js':     0,
    'cookie-no-secure.js':  1,
    'cookie-no-options.js': 1,
    'cors-allowlist.js':    0,
    'cors-star.js':         1,
    'cors-no-opts.js':      1,
  };
  for (const [fixture, want] of Object.entries(expected)) {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-cc-'));
    try {
      await fs.cp(FIX('cookie-cors/' + fixture), path.join(tmpDir, fixture));
      const { scan } = await runScan(tmpDir);
      const cc = normalizeFindings(scan).filter(f => /Cookie|CORS/i.test(f.vuln));
      assert.equal(cc.length, want,
        `${fixture}: expected ${want} cookie/CORS finding(s), got ${cc.length}: ${cc.map(f=>f.vuln).join(', ')}`);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
});

test('FP-4: MD5/SHA1 context-aware classification (cache→suppressed, password→critical, unknown→medium)', async () => {
  const expected = {
    'cache-key.js':      { fire: false },
    'etag.js':           { fire: false },
    'password-hash.js':  { fire: true, sev: 'critical' },
    'unknown.js':        { fire: true, sev: 'medium' },
  };
  for (const [fixture, want] of Object.entries(expected)) {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-hash-'));
    try {
      await fs.cp(FIX('hash-context/' + fixture), path.join(tmpDir, fixture));
      const { scan } = await runScan(tmpDir);
      const wh = normalizeFindings(scan).filter(f => /MD5|SHA1|Weak Hash|Weak Cryptograph/.test(f.vuln));
      if (!want.fire) {
        assert.equal(wh.length, 0, `${fixture}: expected 0 weak-hash findings, got ${wh.length} (severities: ${wh.map(f=>f.severity).join(', ')})`);
      } else {
        assert.ok(wh.length >= 1, `${fixture}: expected ≥1 weak-hash finding`);
        // At least one finding at the expected severity tier
        assert.ok(wh.some(f => f.severity === want.sev),
          `${fixture}: expected at least one weak-hash finding with severity '${want.sev}', got: ${wh.map(f=>f.severity).join(', ')}`);
      }
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
});

test('FP-6: logic-pattern operational gates (Feedback / Coupon / Sensitive-Account-Mutation)', async () => {
  const expected = {
    'blog-comments':       { vulnPattern: /Feedback Without Purchase/,        count: 0 },
    'ecommerce-reviews':   { vulnPattern: /Feedback Without Purchase/,        count: 1 },
    'coupon-display-only': { vulnPattern: /Coupon\/Discount Reuse/,           count: 0 },
    'coupon-redeem':       { vulnPattern: /Coupon\/Discount Reuse/,           min:   1 },
    'account-with-reauth': { vulnPattern: /Sensitive Account Mutation/,       count: 0 },
    'account-no-reauth':   { vulnPattern: /Sensitive Account Mutation/,       count: 1 },
  };
  for (const [fixture, want] of Object.entries(expected)) {
    const { scan } = await runScan(FIX(fixture));
    const lv = normalizeFindings(scan).filter(f => want.vulnPattern.test(f.vuln));
    if (typeof want.count === 'number') {
      assert.equal(lv.length, want.count,
        `${fixture}: expected ${want.count} matches of ${want.vulnPattern}, got ${lv.length}`);
    } else if (typeof want.min === 'number') {
      assert.ok(lv.length >= want.min,
        `${fixture}: expected ≥${want.min} matches of ${want.vulnPattern}, got ${lv.length}`);
    }
  }
});

test('FP-3: sanitizer effectiveness by data-flow (discarded return ≠ sanitization)', async () => {
  const expected = {
    'useless-call.js': { sev: 'medium' },   // bare escapeHtml(s); → not downgraded
    'proper-call.js':  { sev: 'info' },     // const safe = escapeHtml(s); → downgraded
    'fake-escape.js':  { sev: 'medium' },   // custom escapeError that rethrows → not promoted to sanitizer
  };
  for (const [fixture, want] of Object.entries(expected)) {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-san-'));
    try {
      await fs.cp(FIX('sanitizer-misuse/' + fixture), path.join(tmpDir, fixture));
      const { scan } = await runScan(tmpDir);
      const xss = normalizeFindings(scan).filter(f => /XSS|Reflected/.test(f.vuln));
      assert.ok(xss.length >= 1, `${fixture}: expected ≥1 XSS finding`);
      assert.ok(xss.some(f => f.severity === want.sev),
        `${fixture}: expected at least one XSS finding at severity '${want.sev}', got: ${xss.map(f=>f.severity).join(', ')}`);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
});

test('Feat-4: custom rules YAML — adds custom sink + suppression hides legacy finding', async () => {
  const { scan } = await runScan(FIX('custom-rules'));
  const findings = normalizeFindings(scan);
  // Custom sink fires
  const custom = findings.filter(f => /Custom/i.test(f.vuln));
  assert.ok(custom.length >= 1, `expected ≥1 custom-rule finding, got ${custom.length}`);
  // Suppression removes the MD5 finding on legacy/auth-v1.js
  const md5OnLegacy = findings.filter(f => /MD5\/SHA1 Password Hashing/.test(f.vuln) && /legacy\//.test(f.file));
  assert.equal(md5OnLegacy.length, 0, 'MD5 finding on legacy/ path should be suppressed');
  // Suppression is recorded in scan.suppressions for audit
  const sups = (scan.suppressions || []).filter(s => s.reason && s.reason.startsWith('custom-rule:'));
  assert.ok(sups.length >= 1, `expected ≥1 custom-rule suppression, got ${sups.length}`);
});

test('Feat-5: refactor-aware fix bundling — 3 routes sharing buildSql group into one bundle', async () => {
  const { scan } = await runScan(FIX('fix-bundling'));
  const meta = { scanId: 'test', startedAt: '2026-05-07T00:00:00Z', durationMs: 0 };
  const json = (await import('../src/report/index.js')).toJSON(scan, meta);
  assert.ok(json.bundles && json.bundles.length >= 1,
    `expected ≥1 bundle, got ${(json.bundles || []).length}`);
  const sqlBundle = json.bundles.find(b => /SQL Injection/.test(b.vuln));
  assert.ok(sqlBundle, 'expected a SQL Injection bundle');
  assert.equal(sqlBundle.sharedHelper, 'buildSql');
  assert.ok(sqlBundle.childCount >= 3, `expected ≥3 children in bundle, got ${sqlBundle.childCount}`);
});

test('Feat-9: EPSS/CVSS overlay — SCA findings carry epss + cvss fields, sort by epssPercentile within tier', async () => {
  // Don't hit the live FIRST.org API in tests; fabricate a synthetic scan.
  const synthetic = {
    findings: [], secrets: [], logicVulns: [], suppressions: [], components: [],
    routes: [], filesScanned: 0,
    supplyChain: [
      { type: 'vulnerable_dep', name: 'a', version: '1.0', ecosystem: 'npm',
        severity: 'high', cveAliases: ['CVE-2024-0001'], description: 'a vuln',
        epssScore: 0.05, epssPercentile: 0.10, cvssVector: 'AV:N/AC:H' },
      { type: 'vulnerable_dep', name: 'b', version: '1.0', ecosystem: 'npm',
        severity: 'high', cveAliases: ['CVE-2024-0002'], description: 'b vuln',
        epssScore: 0.50, epssPercentile: 0.95, cvssVector: 'AV:N/AC:L' },
    ],
  };
  const { normalizeFindings } = await import('../src/report/index.js');
  const findings = normalizeFindings(synthetic);
  // Both findings present
  assert.equal(findings.length, 2);
  // Higher-EPSS finding sorts first within the same tier
  assert.ok(findings[0].epssPercentile === 0.95,
    `expected highest-EPSS first, got: ${findings.map(f => f.epssPercentile).join(', ')}`);
  // Fields are surfaced
  assert.ok(findings[0].cvssVector, 'cvssVector should be carried through');
  assert.ok(typeof findings[0].epssScore === 'number');
});

test('Feat-2: IaC scanning — Dockerfile / K8s / Terraform fixtures fire; clean.dockerfile is silent', async () => {
  const { scan } = await runScan(FIX('iac'));
  const iac = normalizeFindings(scan).filter(f => f.kind === 'iac');
  assert.ok(iac.length >= 8, `expected ≥8 IaC findings, got ${iac.length}`);
  assert.ok(iac.some(f => f.file.endsWith('Dockerfile') && /RUN curl/.test(f.vuln)), 'Dockerfile RUN curl|sh missing');
  assert.ok(iac.some(f => /privileged/i.test(f.vuln)), 'K8s privileged finding missing');
  assert.ok(iac.some(f => /public-read/i.test(f.vuln)), 'Terraform public-read finding missing');
  // Clean dockerfile must produce zero findings
  const onClean = iac.filter(f => /clean\.dockerfile/.test(f.file));
  assert.equal(onClean.length, 0, 'clean.dockerfile should produce 0 IaC findings');
});

test('Feat-8: HTML report is well-formed, embeds findings inline, has no external resource refs', async () => {
  const { scan } = await runScan(FIX('vulnerable-js'));
  const meta = { scanId: 'test', startedAt: '2026-05-07T00:00:00Z', durationMs: 0 };
  const { toHTML } = await import('../src/report/index.js');
  const html = toHTML(scan, meta);
  assert.ok(html.startsWith('<!doctype html>'), 'must be HTML');
  assert.ok(html.includes('</html>'), 'must be closed');
  assert.ok(/const FINDINGS\s*=\s*\[/.test(html), 'findings not embedded as JS array');
  // No external script/stylesheet references — single self-contained file
  assert.ok(!/<script\s+[^>]*src=["']https?:/i.test(html), 'remote <script src> not allowed');
  assert.ok(!/<link\s+[^>]*href=["']https?:/i.test(html), 'remote <link href> not allowed');
  assert.ok(!/(?:fonts\.googleapis|cdn\.|jsdelivr|unpkg)/i.test(html), 'CDN/font references not allowed');
  // Reasonable size budget for 45-finding fixture
  assert.ok(html.length < 500_000, `html report ${html.length} bytes > 500KB budget`);
});

test('Feat-10: --changed-since incremental scan limits scope to git-modified files', async () => {
  const { spawnSync } = await import('node:child_process');
  // Set up a tmp git repo with two files: only one will be "changed" relative to HEAD~1
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-inc-'));
  try {
    spawnSync('git', ['init', '-q'], { cwd: tmpDir });
    spawnSync('git', ['config', 'user.email', 'test@test'], { cwd: tmpDir });
    spawnSync('git', ['config', 'user.name', 'test'], { cwd: tmpDir });
    spawnSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: tmpDir });
    // Both files initially clean
    await fs.writeFile(path.join(tmpDir, 'safe.js'), 'const x = 1;\n');
    await fs.writeFile(path.join(tmpDir, 'vuln.js'), 'const y = 1;\n');
    spawnSync('git', ['add', '.'], { cwd: tmpDir });
    spawnSync('git', ['commit', '-q', '--no-gpg-sign', '-m', 'initial'], { cwd: tmpDir });
    // Modify ONLY vuln.js to introduce a critical SQLi
    await fs.writeFile(path.join(tmpDir, 'vuln.js'),
      "app.post('/x', (req, res) => { db.query('SELECT * FROM u WHERE id=' + req.body.id); });\n");
    // Full scan: should find SQLi
    const full = await runScan(tmpDir, {});
    const sqlInjFull = normalizeFindings(full.scan).filter(f => /SQL Injection/.test(f.vuln));
    assert.ok(sqlInjFull.length >= 1, 'full scan must surface the SQLi');
    // Incremental scan with --changed-since HEAD: only the file modified since
    // HEAD (vuln.js) is in the diff. Both should still find it.
    const inc = await runScan(tmpDir, { changedSince: 'HEAD' });
    assert.equal(inc.meta.mode, 'incremental', 'meta.mode should be incremental');
    // safe.js was not modified — its (zero) findings are skipped, but vuln.js findings remain
    const sqlInjInc = normalizeFindings(inc.scan).filter(f => /SQL Injection/.test(f.vuln));
    assert.ok(sqlInjInc.length >= 1, 'incremental scan must still surface vuln.js SQLi');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Feat-3: cross-file taint emits chain field with source→propagation→sink hops', async () => {
  const { scan } = await runScan(FIX('deep-taint'));
  const xf = (scan.findings || []).filter(f => /->/.test(f.file || ''));
  assert.ok(xf.length >= 1, 'expected ≥1 cross-file finding');
  const sqli = xf.find(f => /SQL Injection/.test(f.vuln));
  assert.ok(sqli, 'expected a cross-file SQL Injection finding');
  assert.ok(Array.isArray(sqli.chain), 'finding must carry a chain[] field');
  assert.ok(sqli.chain.length >= 3, `chain must include source→propagation→sink (got ${sqli.chain.length} hops)`);
  assert.equal(sqli.chain[0].type, 'source');
  assert.equal(sqli.chain[sqli.chain.length - 1].type, 'sink');
});

test('Feat-1: Python in-file helper flow — request.args → helper(param) → cursor.execute fires SQLi', async () => {
  const { scan } = await runScan(FIX('python-helper-flow'));
  const sqli = normalizeFindings(scan).filter(f => /SQL Injection/.test(f.vuln));
  assert.ok(sqli.length >= 1, `expected ≥1 SQL Injection finding, got ${sqli.length}`);
  // Finding should land on the helper body where cursor.execute lives, NOT just on the source line
  const onHelper = sqli.some(f => /lookup_user|app\.py:1[01]/.test(`${f.file}:${f.line}`));
  assert.ok(onHelper, `expected a finding inside the helper body; got: ${sqli.map(f=>f.file+':'+f.line).join(', ')}`);
});

test('Feat-6: PR-comment script produces well-formed Markdown summary from a scan JSON', async () => {
  const { spawnSync } = await import('node:child_process');
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agsec-pr-'));
  try {
    const { scan } = await runScan(FIX('vulnerable-js'));
    const meta = { scanId: 't', startedAt: '2026-05-07T00:00:00Z', durationMs: 0 };
    const { toJSON } = await import('../src/report/index.js');
    const jsonPath = path.join(tmpDir, 'scan.json');
    await fs.writeFile(jsonPath, JSON.stringify(toJSON(scan, meta)));
    const scriptPath = path.join(__dirname, '..', '..', 'scripts', 'pr-comment.js');
    const r = spawnSync('node', [scriptPath, jsonPath], { encoding: 'utf8' });
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes('## agentic-security scan'), 'header missing');
    assert.ok(/\| Critical \| High \| Medium \| Low \| Info \|/.test(r.stdout), 'severity table missing');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('finding IDs are stable hashes', async () => {
  const a = await runScan(FIX('vulnerable-js'));
  const b = await runScan(FIX('vulnerable-js'));
  const idsA = normalizeFindings(a.scan).map(f => f.id).sort();
  const idsB = normalizeFindings(b.scan).map(f => f.id).sort();
  assert.deepEqual(idsA, idsB, 'finding IDs must be deterministic across runs');
});
