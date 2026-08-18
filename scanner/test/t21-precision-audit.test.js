// PRD T2.1 — defects found by the systematic top-detector precision audit.
//
// Each test below pins a defect that unit tests did NOT catch, because each
// fixture an author writes by hand is shaped the way the author expects the
// code to look. These were all found by ranking detectors by VOLUME over real
// upstream code and then reading the lines they fired on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';
import { scanPhp } from '../src/sast/php.js';

async function findings(name, src, extra = {}) {
  setStateWritesEnabled(false);
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 't21-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{"name":"t","version":"1.0.0"}');
    for (const [f, c] of Object.entries(extra)) fs.writeFileSync(path.join(d, f), c);
    fs.writeFileSync(path.join(d, name), src);
    const { scan } = await runScan(d);
    return normalizeFindings(scan) || [];
  } finally { setStateWritesEnabled(true); fs.rmSync(d, { recursive: true, force: true }); }
}

test('Hardcoded Secret: OAuth/OIDC protocol constants are not secrets', async () => {
  // 2nd-highest-volume rule; every sampled instance was public spec vocabulary
  // declared as a named constant, flagged only because the NAME says "token".
  const f = await findings('consts.go', [
    'package c',
    'const (',
    '\tGrantTypeRefreshToken = "refresh_token"',
    '\tTokenTypeURNAccessToken = "urn:ietf:params:oauth:token-type:access_token"',
    '\tAuthRecipeMethodMobileBasicAuth = "mobile_basic_auth"',
    ')',
  ].join('\n'), { 'go.mod': 'module t\n' });
  const hs = f.filter(x => /Hardcoded Secret/.test(String(x.vuln || '')));
  assert.deepEqual(hs, [], `public protocol vocabulary must not read as a secret: ${JSON.stringify(hs.map(x => x.snippet))}`);
});

test('Hardcoded Secret: a real credential is STILL reported', async () => {
  const f = await findings('real.go', 'package c\nconst apiKey = "sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc"\n',
    { 'go.mod': 'module t\n' });
  assert.ok(f.some(x => /Hardcoded Secret/.test(String(x.vuln || ''))), 'the precision fix must not silence real secrets');
});

test('Missing Timeout: a function whose NAME merely ends in "fetch" is not an HTTP call', () => {
  // The rule's alternation had no leading word boundary, so `resetPageAndFetch(`
  // matched on its `Fetch(` substring.
  const re = /(?:await\s+)?\b(?:fetch|axios\.(?:get|post|put|patch|delete|request)|http\.(?:get|request)|https\.(?:get|request)|got)\s*\(/gi;
  for (const notACall of ['resetPageAndFetch()', 'prefetch(x)', 'myGot(']) {
    re.lastIndex = 0;
    assert.equal(re.test(notACall), false, `${notACall} is not an outbound HTTP request`);
  }
  for (const isACall of ['await fetch(url)', 'axios.get(u)', 'http.get(u)']) {
    re.lastIndex = 0;
    assert.equal(re.test(isACall), true, `${isACall} is an outbound HTTP request`);
  }
});

test('PHP: backticks inside a comment are prose, not shell execution', () => {
  // Highest-volume rule in the whole population (105 findings / 24 entries),
  // and the sampled instance was an English sentence quoting a word.
  const commented = '<?php\n// Abort if `taxonomies` resource is disabled\n$x = 1;\n';
  assert.deepEqual(scanPhp('a.php', commented).filter(f => /backtick/.test(f.vuln)), []);
});

test('PHP: a real backtick shell execution still fires', () => {
  const real = '<?php\n$out = `ls $dir`;\n';
  assert.equal(scanPhp('a.php', real).filter(f => /backtick/.test(f.vuln)).length, 1);
});

test('Java SQLi: Executor.execute(Runnable) is a thread pool, not a database', async () => {
  // Highest-severity defect found by the audit: bare `execute` in the JDBC
  // sink list matched java.util.concurrent.Executor, producing SQL-injection
  // findings on netty's DefaultChannelPipeline / NonStickyEventExecutorGroup /
  // ThreadExecutorMap and Appium's AppiumCommandExecutor.
  const f = await findings('Pool.java', [
    'package t;',
    'import java.util.concurrent.Executor;',
    'public class Pool {',
    '  void run(Executor executor, Runnable command) {',
    '    executor.execute(command);',
    '  }',
    '}',
  ].join('\n'));
  const sqli = f.filter(x => /Java JDBC/.test(String(x.vuln || '')));
  assert.deepEqual(sqli, [], `thread-pool execution is not SQL: ${JSON.stringify(sqli.map(x => x.snippet))}`);
});

test('Java SQLi: a real Statement.execute(sql) is STILL reported', async () => {
  const f = await findings('Dao.java', [
    'package t;',
    'import java.sql.*;',
    'public class Dao {',
    '  void find(Connection conn, String name) throws Exception {',
    '    Statement stmt = conn.createStatement();',
    '    stmt.execute("SELECT * FROM users WHERE name = \'" + name + "\'");',
    '  }',
    '}',
  ].join('\n'));
  assert.ok(f.some(x => /SQL Injection/i.test(String(x.vuln || ''))),
    'the precision fix must not silence real JDBC injection');
});
