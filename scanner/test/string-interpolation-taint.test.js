// Stage 3 correctness audit (detection depth, per-language-IR): PHP and C#
// both mis-modeled their native string-interpolation syntax.
//
// PHP double-quoted strings interpolate variables directly
// ("id=$id", "hi {$user->name}") — single-quoted strings never do.
// parser-php.js treated ANY quoted string, including a double-quoted one
// containing a live variable, as an opaque clean literal — silently
// dropping the interpolated variable's taint. Exactly
// `"SELECT ... WHERE id=$id"`, one of the most common real PHP
// SQL-injection shapes.
//
// C# interpolated strings ($"id={id}", $@"...") were entirely
// unrecognized by parser-cs.js's _lowerExpr — not even treated as an
// opaque literal, since nothing tested for the leading `$` — so they fell
// through to {kind:'unknown'}. Exactly
// `new SqlCommand($"SELECT ... WHERE id={id}", conn)`, one of the most
// common real C# SQL-injection shapes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-strinterp-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('PHP: a variable interpolated into a double-quoted string reaches a SQL sink', async () => {
  const dir = mkTmp('php-simple', {
    'app.php': `<?php
function handler() {
  $id = $_GET['id'];
  $sql = "SELECT * FROM users WHERE id=$id";
  mysqli_query($conn, $sql);
}
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    `expected a PHP double-quoted-string interpolated variable to propagate taint, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('PHP: a single-quoted string never interpolates and does not fire (control)', async () => {
  const dir = mkTmp('php-single-quote', {
    'app.php': `<?php
function handler() {
  $id = $_GET['id'];
  $sql = 'SELECT * FROM users WHERE id=$id';
  mysqli_query($conn, $sql);
}
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter(f => /sql/i.test(f.vuln || ''));
  assert.equal(sqlFindings.length, 0,
    'a single-quoted PHP string must never be treated as interpolating $id');
});

test('C#: a variable interpolated into a $"..." string reaches a SQL sink', async () => {
  const dir = mkTmp('cs-interp', {
    'App.cs': `
public class App {
  public void Handle() {
    string id = Request.QueryString["id"];
    var cmd = new SqlCommand($"SELECT * FROM users WHERE id={id}", conn);
    cmd.ExecuteReader();
  }
}
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    `expected a C# interpolated-string variable to propagate taint, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('C#: an interpolated string with a clean literal value does not fire (control)', async () => {
  const dir = mkTmp('cs-clean', {
    'App.cs': `
public class App {
  public void Handle() {
    string id = "42";
    var cmd = new SqlCommand($"SELECT * FROM users WHERE id={id}", conn);
    cmd.ExecuteReader();
  }
}
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const sqlFindings = irFindings.filter(f => /sql/i.test(f.vuln || ''));
  assert.equal(sqlFindings.length, 0, 'a clean literal interpolated value must not trigger a finding');
});
