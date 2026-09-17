// Auth/AuthZ deep-analysis detector — F1 over labelled fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { evaluateF1 } from './helpers/f1.js';
import { scanAuthZ } from '../src/sast/authz.js';
import { runScan } from '../src/runScan.js';

const LABELS = [
  { file: 'vuln-jwt-alg-none.js',           positive: true,  matcher: /JWT alg:none/i },
  { file: 'vuln-jwt-hardcoded-secret.js',   positive: true,  matcher: /hardcoded JWT secret/i },
  { file: 'vuln-jwt-verify-no-algs.js',     positive: true,  matcher: /jwt\.verify.*algorithms/i },
  { file: 'vuln-oauth-no-pkce.js',          positive: true,  matcher: /OAuth2.*PKCE/i },
  { file: 'vuln-oauth-redirect-from-req.js',positive: true,  matcher: /redirect_uri from request/i },
  { file: 'vuln-session-fixation.js',       positive: true,  matcher: /session.*regenerated|session fixation/i },
  { file: 'vuln-multi-tenant-no-scope.js',  positive: true,  matcher: /tenant.*scoped query missing|tenantId\/orgId/i },
  { file: 'safe-jwt-explicit-algs.js',      positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-oauth-pkce.js',             positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-redirect-allowlist.js',     positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-session-regenerate.js',     positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-multi-tenant-scoped.js',    positive: false, matcher: /^AuthZ:/i },
];

test('AuthZ detector — F1 evaluation', async () => {
  await evaluateF1({
    name: 'AuthZ-detector',
    fixtureDir: 'authz',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});

// Stage 1 correctness audit: `!A && !B === false || C` — operator precedence
// makes `!B === false` reduce to `B`, and `C` (val.length >= 4) is always
// true given the capture group's own {4,64} quantifier, so the whole
// "suppress only template/env placeholders" condition was a tautology —
// every match was flagged regardless, including literal env-var
// placeholders the comment explicitly says should be suppressed.
test('hardcoded-JWT-secret does not flag a template/env-var placeholder', () => {
  const src = 'const JWT_SECRET = "${process.env.JWT_SECRET}";\n';
  const findings = scanAuthZ('app.js', src);
  assert.equal(findings.filter(f => /hardcoded JWT secret/i.test(f.vuln)).length, 0,
    `expected no finding for an env-var placeholder, got: ${JSON.stringify(findings)}`);
});

test('hardcoded-JWT-secret still flags a real literal secret', () => {
  const src = 'const JWT_SECRET = "supersecretvalue123";\n';
  const findings = scanAuthZ('app.js', src);
  assert.equal(findings.filter(f => /hardcoded JWT secret/i.test(f.vuln)).length, 1);
});

test('hardcoded-JWT-secret still flags well-known placeholder values (changeme/secret/example)', () => {
  const src = 'const JWT_SECRET = "changeme";\n';
  const findings = scanAuthZ('app.js', src);
  assert.equal(findings.filter(f => /hardcoded JWT secret/i.test(f.vuln)).length, 1,
    'well-known bad placeholders must still be flagged per the module\'s own stated intent');
});

// SARD_80_F1 W5.13 — PHP IDOR/missing-authorization (CWE-862), confirmed
// against the public generator source (stivalet/PHP-Vuln-test-suite-
// generator, pinned 84b4cccf05598c74b052111804954eac19f259b6): the "safe"
// fix appends the ownership check as a SEPARATE, subsequent `.=` statement,
// never inside the same string literal as the WHERE clause.
test('PHP IDOR — raw SQL where-by-id from $_GET with no ownership check fires (CWE-862)', () => {
  const src = "<?php\n$tainted = $_GET['id'];\n$query = \"SELECT * FROM student where id='$tainted'\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 1);
});

test('PHP IDOR — dot-concatenation form also fires (CWE-862)', () => {
  const src = "<?php\n$tainted = $_GET['id'];\n$query = \"SELECT * FROM student where id='\" . $tainted . \"'\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 1);
});

test('PHP IDOR — a $_SESSION ownership check appended as a later statement suppresses the finding', () => {
  const src = "<?php\n$tainted = $_GET['id'];\n$query = \"SELECT * FROM COURSE, USER WHERE courseID='$tainted'\";\n$query .= \"AND course.allowed=$_SESSION[userid]\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

test('PHP IDOR — no request superglobal anywhere in the file (e.g. a plain function parameter with no $_GET/$_POST/etc in sight) does not fire', () => {
  const src = "<?php\nfunction lookup($tainted) {\n  $query = \"SELECT * FROM student where id='$tainted'\";\n  return mysql_query($query);\n}\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

// The public generator's own combinatorics route the same $_GET read through
// many indirections a single-line "$var = $_GET[...]" trace could never
// enumerate (a getter method, an array element, an object property set in
// the constructor — confirmed via input.xml). The check is deliberately
// file-scoped co-occurrence, not a traced assignment, so this must still fire.
test('PHP IDOR — a $_GET read reaching the query through an object getter (not a direct assignment) still fires (CWE-862)', () => {
  const src = "<?php\nclass Input{\n  public function getInput(){\n    return $_GET['UserData'];\n  }\n}\n$temp = new Input();\n$tainted = $temp->getInput();\n$query = \"SELECT * FROM student where id='$tainted'\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 1);
});

// SARD_80_F1 W5.13, second bug found while verifying against the real corpus:
// the detector fired with the correct CWE-862, but scored ZERO tp on the real
// corpus anyway — every OTHER authz.js finding's vuln text also starts with
// "AuthZ:", and engine.js's `_VULN_FAMILY_PREFIX` table (a THIRD, separate
// family map from finding-defaults.js's own CWE-862 -> 'missing-authz' entry)
// had a blanket `['AuthZ:', 'idor']` catch-all that ran FIRST (dedup runs
// before the finding-defaults backfill) and swept this finding into 'idor'
// too, so it could never match a CWE-862 gold entry's 'missing-authz' family.
// This is an end-to-end pipeline test, not a `scanAuthZ`-only unit test,
// because the bug lived entirely in a LATER annotation stage this file's
// other tests never exercise.
test('PHP IDOR — the finding\'s scoring family is missing-authz, not the generic authz.js idor catch-all', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-idor-family-'));
  try {
    fs.writeFileSync(path.join(dir, 'lookup.php'),
      "<?php\n$tainted = $_GET['id'];\n$query = \"SELECT * FROM student where id='$tainted'\";\nmysql_query($query);\n");
    const { scan } = await runScan(dir, {});
    const f = (scan.findings || []).find(x => x.cwe === 'CWE-862');
    assert.ok(f, 'expected a CWE-862 finding from the full scan pipeline');
    assert.equal(f.family, 'missing-authz');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// SARD_80_F1 W5.13, third bug found while verifying against the real corpus:
// once the family bug was fixed, the real corpus scan showed 10 NEW false
// positives — the generator's OTHER safe path never touches $_SESSION at
// all. It instead constrains the tainted value to a fixed allow-list BEFORE
// the query (sanitize.xml's "ternary_white_list" / "whitelist_using_array"
// samples), which the $_SESSION-only suppression window could never see.
test('PHP IDOR — a ternary compare-and-substitute allow-list suppresses the finding', () => {
  const src = "<?php\n$tainted = $_GET['UserData'];\n$tainted = $tainted == 'safe1' ? 'safe1' : 'safe2';\n$query = \"SELECT * FROM student where id='$tainted'\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

test('PHP IDOR — an in_array() allow-list guard suppresses the finding', () => {
  const src = "<?php\n$tainted = $_GET['UserData'];\n$legal_table = array('safe1', 'safe2');\nif (in_array($tainted, $legal_table, true)) {\n  $tainted = $tainted;\n} else {\n  $tainted = $legal_table[0];\n}\n$query = \"SELECT * FROM student where id='$tainted'\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

// A residual real-corpus false-positive family, per the same generator's
// sanitize.xml: an OWASP ESAPI validator call.
test('PHP IDOR — an ESAPI validator call suppresses the finding', () => {
  const src = "<?php\n$tainted = $_GET['UserData'];\n$ESAPI = new ESAPI();\nif ($ESAPI->validator->isValidNumber('Course ID', $tainted, 18, 25, false)) {\n  $tainted = $tainted;\n} else {\n  $tainted = 0;\n}\n$query = \"SELECT * FROM student where id='$tainted'\";\nmysql_query($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

// SARD_80_F1 W5.14 — a structurally distinct sibling of the SQL where-by-id
// shape, from the SAME generator (construction.xml's "fopen" sample):
// `$var = fopen($tainted, "r")` has no "where"/"id=" text at all, so
// PHP_IDOR_WHERE_ID_RE could never match it — CWE-862's test-split fn bucket
// showed a total blackout (0 tp) even after W5.13's fix, traced to this gap.
test('PHP IDOR — fopen() on a request-supplied id/path with no ownership check fires', () => {
  const src = "<?php\n$fileId = $_GET['id'];\n$var = fopen($fileId, \"r\");\n";
  const findings = scanAuthZ('lookup.php', src);
  const f = findings.find(x => x.cwe === 'CWE-862');
  assert.ok(f, 'expected a CWE-862 finding');
  assert.equal(f.vuln, 'AuthZ: fopen() on request-supplied path/id without an ownership check');
});

test('PHP IDOR — fopen() with a $_SESSION ownership check nearby does not fire', () => {
  const src = "<?php\n$fileId = $_GET['id'];\nif ($_SESSION['userid'] == $fileId) {\n  $var = fopen($fileId, \"r\");\n}\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

test('PHP IDOR — fopen() on a non-tainted (no superglobal in file) path does not fire', () => {
  const src = "<?php\n$path = \"/var/data/fixed.txt\";\n$var = fopen($path, \"r\");\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

test('PHP IDOR — fopen() finding scores family missing-authz, not the generic idor catch-all', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-fopen-idor-family-'));
  try {
    fs.writeFileSync(path.join(dir, 'lookup.php'),
      "<?php\n$fileId = $_GET['id'];\n$var = fopen($fileId, \"r\");\n");
    const { scan } = await runScan(dir, {});
    const f = (scan.findings || []).find(x => x.cwe === 'CWE-862');
    assert.ok(f, 'expected a CWE-862 finding from the full scan pipeline');
    assert.equal(f.family, 'missing-authz');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// SARD_80_F1 W5.15 — a THIRD structurally distinct sibling from the SAME
// generator's getType() list (SQL/Fopen/XPath): an XPath attribute predicate
// (`[@username=…]`/`[@id=…]`) built by concatenating a raw request-supplied
// value. Confirmed via construction.xml's unsafe sample, and that the
// query is executed via SimpleXMLElement's `->xpath()` method — a
// different API from the existing xpath-injection.js detector's
// `->query()`/`->evaluate()`-only PHP pattern, so this shape was invisible
// to both the CWE-643 and CWE-862 detectors before this fix.
test('PHP IDOR — an XPath attribute predicate built from a request superglobal fires', () => {
  const src = "<?php\n$tainted = $_GET['username'];\n$query = \"//User[@username='\". $tainted . \"']\";\n$xml = simplexml_load_file(\"users.xml\");\n$res = $xml->xpath($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  const f = findings.find(x => x.cwe === 'CWE-862');
  assert.ok(f, 'expected a CWE-862 finding');
  assert.equal(f.vuln, 'AuthZ: XPath query built from request input without an ownership check');
});

test('PHP IDOR — an XPath query with an inline @allowed=$_SESSION clause does not fire', () => {
  const src = "<?php\n$tainted = $_GET['id'];\n$query = \"//Course[@id=\". $tainted . \"and @allowed=\". $_SESSION['userid'] . \"]\";\n$xml = simplexml_load_file(\"courses.xml\");\n$res = $xml->xpath($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

test('PHP IDOR — an XPath query built from a non-tainted (no superglobal in file) value does not fire', () => {
  const src = "<?php\n$fixed = \"Testing.test\";\n$query = \"//User[@username='\". $fixed . \"']\";\n$xml = simplexml_load_file(\"users.xml\");\n$res = $xml->xpath($query);\n";
  const findings = scanAuthZ('lookup.php', src);
  assert.equal(findings.filter(f => f.cwe === 'CWE-862').length, 0);
});

test('PHP IDOR — XPath finding scores family missing-authz, not the generic idor catch-all', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-xpath-idor-family-'));
  try {
    fs.writeFileSync(path.join(dir, 'lookup.php'),
      "<?php\n$tainted = $_GET['username'];\n$query = \"//User[@username='\". $tainted . \"']\";\n$xml = simplexml_load_file(\"users.xml\");\n$res = $xml->xpath($query);\n");
    const { scan } = await runScan(dir, {});
    const f = (scan.findings || []).find(x => x.cwe === 'CWE-862');
    assert.ok(f, 'expected a CWE-862 finding from the full scan pipeline');
    assert.equal(f.family, 'missing-authz');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
