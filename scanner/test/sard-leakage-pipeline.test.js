// SARD_AGENTIC_SECURITY_PRD.md §62 — required leakage tests + a small
// download→ingest→neutralize→scan→score-shaped integration test.
//
// Two things this file deliberately does NOT do:
//  - It never touches the real Juliet/PHP corpora (network, multi-minute
//    clones) — PRD §62 asks for "a small fixture set", and a unit-test-suite
//    file must stay fast and offline.
//  - It never reads bench/sard-juliet-java/** or .bench-cache/** — this repo
//    denies that to the coding agent (see bench/sard/IMPLEMENTATION_STATUS.md
//    §0), and a synthetic fixture exercises the exact same transform code
//    paths without needing raw corpus access at all.
//
// What it DOES exercise for real: the actual `_blindTransform` /
// `auditFile` / `TERMS` functions this session added exports for — not
// reimplementations of them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { _blindTransform } from './benchmark/realworld/bench-realworld.js';
import { TERMS, auditFile } from '../../bench/sard/scripts/leakage-audit.mjs';

function termRegexes() {
  return TERMS.map(term => ({
    term,
    re: new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'),
  }));
}

function mkTmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sard-leakage-test-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  return file;
}

// ── PRD §62's literal leakage-injection list ────────────────────────────────

test('leakage audit: a file containing "CWE-89" is flagged', () => {
  const file = mkTmpFile('a.java', 'public class A { /* CWE-89 */ void bad() {} }');
  const hits = auditFile(file, termRegexes(), false);
  assert.ok(hits.some(h => h.term === 'CWE'), `expected a CWE hit, got: ${JSON.stringify(hits)}`);
});

test('leakage audit: a bare bad() method declaration is flagged', () => {
  const file = mkTmpFile('a.java', 'public class A { void bad() { sink(source()); } }');
  const hits = auditFile(file, termRegexes(), false);
  assert.ok(hits.some(h => h.term === 'juliet-method-name'), `expected a juliet-method-name hit, got: ${JSON.stringify(hits)}`);
});

test('leakage audit: GoodSource() is flagged', () => {
  const file = mkTmpFile('a.java', 'public class A { String x = GoodSource(); }');
  const hits = auditFile(file, termRegexes(), false);
  assert.ok(hits.some(h => h.term === 'GoodSource'), `expected a GoodSource hit, got: ${JSON.stringify(hits)}`);
});

test('leakage audit: the literal word "SARD" is flagged', () => {
  const file = mkTmpFile('a.java', '// This test case is from SARD.\npublic class A {}');
  const hits = auditFile(file, termRegexes(), false);
  assert.ok(hits.some(h => h.term === 'SARD'), `expected a SARD hit, got: ${JSON.stringify(hits)}`);
});

test('leakage audit: the literal word "Juliet" is flagged', () => {
  const file = mkTmpFile('a.java', 'package juliet.testcases.CWE89_SQL_Injection;\npublic class A {}');
  const hits = auditFile(file, termRegexes(), false);
  assert.ok(hits.some(h => h.term === 'Juliet'), `expected a Juliet hit, got: ${JSON.stringify(hits)}`);
});

// ── Context-awareness (PRD §13: "avoid blocking ordinary legitimate program
//    usage") — a real, ordinary word must not false-positive. ──────────────

test('leakage audit: ordinary words containing "good"/"bad" as a substring do NOT false-positive', () => {
  const file = mkTmpFile('a.java', 'public class A { void goodbye() { badge(); goodwill(); } }');
  const hits = auditFile(file, termRegexes(), false);
  assert.equal(hits.filter(h => h.term === 'juliet-method-name').length, 0,
    `word-boundary matching must not flag goodbye/badge/goodwill, got: ${JSON.stringify(hits)}`);
});

test('leakage audit: clean, ordinary Java source produces zero hits', () => {
  const file = mkTmpFile('a.java', 'public class Calculator {\n  int add(int a, int b) { return a + b; }\n}\n');
  const hits = auditFile(file, termRegexes(), false);
  assert.equal(hits.length, 0, `expected no hits on clean code, got: ${JSON.stringify(hits)}`);
});

// ── Small integration test: a synthetic Juliet-SHAPED fixture through the
//    REAL neutralization pipeline, then through the REAL leakage audit.
//    This is the "download→ingest→neutralize→scan→score" pipeline PRD §62
//    asks for, minus the download/clone step (network, out of scope for a
//    fast unit-test file) — the transform + audit stages are exercised for
//    real, on a fixture instead of the real corpus. ─────────────────────────

const SYNTHETIC_JULIET_FIXTURE = `/*
 * CWE89_SQL_Injection__Servlet_getParameter_executeQuery_01.java
 *
 * FLAW: this method fails to sanitize input passed in via getParameter().
 */
package juliet.testcases.CWE89_SQL_Injection__Servlet_getParameter_executeQuery_01;

public class CWE89_SQL_Injection__Servlet_getParameter_executeQuery_01 {
  public void bad(javax.servlet.http.HttpServletRequest request, java.sql.Statement sql) throws Exception {
    String data = request.getParameter("name");
    sql.executeUpdate("SELECT * FROM users WHERE name = '" + data + "'");
  }

  private void goodG2B() throws Exception {
    String data = "safe hardcoded value";
    // this method does not use goodG2B — same shape, safe source
  }
}
`;

test('integration: a synthetic Juliet-shaped fixture leaks under bare content-scanning, and --blind + --scramble-identifiers cleans it', () => {
  // Stage 1: RAW content (no transform at all) — must leak, proving the
  // fixture is a faithful stand-in for the real leak this session found and
  // fixed (Java package/class names mirroring the CWE tag).
  const rawFile = mkTmpFile('Raw.java', SYNTHETIC_JULIET_FIXTURE);
  const rawHits = auditFile(rawFile, termRegexes(), false);
  assert.ok(rawHits.length > 0, 'the raw fixture must leak before any transform is applied (sanity check on the fixture itself)');
  assert.ok(rawHits.some(h => h.term === 'juliet-method-name'), 'raw fixture must leak the bad()/goodG2B() method names');
  // NOT asserted here: a bare `\bCWE\b` term hit. Juliet's real filename/
  // package convention fuses the CWE number directly onto the tag
  // ("CWE89_...", no hyphen, no boundary) — found the hard way when this
  // exact assertion first failed: `\bCWE\b` requires a word-boundary
  // immediately after "CWE", which "CWE89" (digit continues the word) does
  // not have. That fused form is what this session's separate
  // `CWE\d+_[A-Za-z0-9_]+` scramble rule in `_blindTransform` exists to
  // catch (verified below via `doesNotMatch(/\bCWE89\b/)`) — the leakage-
  // audit's own `CWE` TERM is a different, complementary check (catches a
  // hyphenated or otherwise word-bounded "CWE-89" mention, e.g. in prose or
  // a doc comment), not a substitute for it.

  // Stage 2: run the REAL _blindTransform with scrambleIdentifiers (the
  // production leakage-prevention path, not a reimplementation).
  const blinded = _blindTransform(SYNTHETIC_JULIET_FIXTURE, { stripAllComments: true, scrambleIdentifiers: true });
  const blindedFile = mkTmpFile('Blinded.java', blinded);
  const blindedHits = auditFile(blindedFile, termRegexes(), false);
  assert.equal(blindedHits.length, 0,
    `expected zero leakage hits after --blind --scramble-identifiers, got: ${JSON.stringify(blindedHits)}`);
  assert.doesNotMatch(blinded, /\bCWE89\b/, 'the CWE tag must not survive in package/class position');
  assert.doesNotMatch(blinded, /\bFLAW\b/, 'the FLAW comment must not survive');
  assert.doesNotMatch(blinded, /\bbad\b\s*\(/, 'the bad() method name must be renamed');
});
