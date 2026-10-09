// SARD_AGENTIC_SECURITY_PRD.md §56 "LLM Isolation" — adversarial-premortem
// remediation, Round 3 F10. §56 requires: "If Agentic Security invokes an
// LLM during scanning, the model prompt MUST NOT include: SARD / Juliet /
// expected CWE / testcase label / good-bad designation / gold result...
// Benchmark controller should inspect generated prompt/context where
// practical to verify isolation." Before this file, that entire section had
// zero implementation and zero test anywhere in this repo — not merely
// undocumented, silently dropped from the 1000+ line implementation ledger.
//
// This reuses `src/llm-validator/index.js`'s real `_internal.renderPrompt`
// (the Layer-3 LLM validator's actual prompt builder, default-on whenever
// AGENTIC_SECURITY_LLM_ENDPOINT is configured, per root CLAUDE.md) and
// leakage-audit.mjs's real `TERMS`/`auditFile` — never a reimplementation of
// either — so this test can never validate a different isolation contract
// than the one the shipped leakage audit and the shipped prompt builder
// actually enforce.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { _internal } from '../src/llm-validator/index.js';
import { TERMS, auditFile } from '../../bench/sard/scripts/leakage-audit.mjs';
import { mkTestTmp } from './helpers/tmp.js';

function termRegexes() {
  return TERMS.map((term) => ({
    term,
    re: new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'),
  }));
}

// The reusable verification mechanism PRD §56 itself asks for ("Benchmark
// controller should inspect generated prompt/context where practical to
// verify isolation") — writes the rendered prompt to a temp file and reuses
// the SAME leakage-audit machinery a scanner workspace is checked with, so
// "the prompt is leakage-clean" and "the workspace is leakage-clean" are the
// same claim, checked the same way, never two independently-drifting checks.
//
// One deliberate scoping difference from auditing a WORKSPACE file: §56
// forbids leaking the ANSWER KEY's "expected CWE" — it does not forbid the
// scanner from stating its OWN classification ("this is CWE-89"), which
// `renderPrompt` legitimately embeds via `{{cwe}}` so the LLM has something
// to validate. A bare "CWE" mention is illegitimate in SOURCE CODE (nothing
// about program behavior should ever say the word) but legitimate in a
// PROMPT (the scanner's real, self-reported finding). `excludeBareCwe`
// drops the plain `CWE` term and the fused-digit `cwe-number` check for
// exactly that reason — every OTHER term (SARD, Juliet, testcase, bad(),
// GoodSource(), ...) still applies unconditionally, since none of those are
// ever legitimate scanner output.
function auditPromptText(promptText, { excludeBareCwe = false } = {}) {
  const dir = mkTestTmp('sard-llm-isolation-');
  const file = path.join(dir, 'prompt.txt');
  fs.writeFileSync(file, promptText);
  const terms = excludeBareCwe ? termRegexes().filter((t) => t.term !== 'CWE') : termRegexes();
  const hits = auditFile(file, terms, true);
  return excludeBareCwe ? hits.filter((h) => h.term !== 'cwe-number') : hits;
}

test('LLM isolation: a prompt built from an already-neutralized (--blind/--scramble-identifiers) file is leakage-clean', () => {
  // Mirrors what a real SARD benchmark run hands the LLM validator: the
  // SAME fileContents map the taint engine itself scanned — bench-realworld
  // .js's `--blind`/`--scramble-identifiers` neutralization has already run
  // by the time anything reaches runScan(), and renderPrompt has no
  // separate, privileged path to raw corpus content. Opaque filename,
  // opaque class/method names, comment already stripped.
  const finding = {
    file: 'case_92fbb1/F00017.java',
    line: 12,
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
    snippet: 'op1_a1b2c3.executeUpdate("SELECT * FROM users WHERE name = \'" + value + "\'");',
  };
  const neutralizedSource = [
    'package app.code.case_92fbb1;',
    '',
    'public class case_92fbb1 {',
    '  public void op0_9f8e7d(String value, java.sql.Statement op1_a1b2c3) throws Exception {',
    '    op1_a1b2c3.executeUpdate("SELECT * FROM users WHERE name = \'" + value + "\'");',
    '  }',
    '}',
  ].join('\n');
  const fileContents = { [finding.file]: neutralizedSource };
  const prompt = _internal.renderPrompt(finding, fileContents, 'challenge-123', 'nonce-abc', '/scan/root');

  const hits = auditPromptText(prompt, { excludeBareCwe: true });
  assert.equal(hits.length, 0,
    `expected a leakage-clean prompt from already-neutralized input, got: ${JSON.stringify(hits)}`);
  // The scanner's own declared classification is expected to appear exactly
  // once (via {{cwe}}) — confirming the exclusion above isn't hiding a REAL
  // leak, just correctly ignoring the scanner's own legitimate output.
  assert.match(prompt, /CWE-89/, 'the scanner\'s own CWE classification should still be present');
  // Direct, human-legible cross-check for the exact terms PRD §56 names.
  for (const bad of ['SARD', 'Juliet', 'testcase']) {
    assert.doesNotMatch(prompt, new RegExp(`\\b${bad}\\b`, 'i'), `prompt must never contain "${bad}"`);
  }
});

test('LLM isolation: the scanner\'s own true-positive claim (vuln/CWE fields) is legitimate content, not a leak', () => {
  // §56 forbids SARD/Juliet ANSWER-KEY metadata, never the scanner's own
  // classification of what it found — "this is SQL Injection, CWE-89" is
  // the scanner's real output, not benchmark leakage, and must still reach
  // the LLM validator so it has something to validate.
  const finding = { file: 'case_1.java', line: 1, vuln: 'SQL Injection', cwe: 'CWE-89' };
  const prompt = _internal.renderPrompt(finding, {}, 'c', 'n', '/scan/root');
  assert.match(prompt, /SQL Injection/);
  assert.match(prompt, /CWE-89/);
});

test('LLM isolation risk, disclosed not silently assumed away: renderPrompt has no INDEPENDENT neutralization of its own — a leak in fileContents reaches the prompt verbatim', () => {
  // This is the honest, disclosed half of the picture: renderPrompt's own
  // isolation is entirely DERIVED from whatever neutralization already ran
  // upstream (bench-realworld.js's --blind/--scramble-identifiers). There is
  // no redundant, independent scrub inside renderPrompt itself. This test
  // exists so that fact is verified and visible, not assumed — if a future
  // change makes renderPrompt independently redact SARD-shaped strings,
  // this test's own assertion direction should flip along with it.
  const finding = {
    file: 'CWE89_SQL_Injection__Servlet_getParameter_executeQuery_01.java',
    line: 3,
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
  };
  const unneutralizedSource = [
    '// This test case is from the Juliet SARD test suite.',
    'package juliet.testcases.CWE89_SQL_Injection__Servlet_getParameter_executeQuery_01;',
    'public class CWE89_SQL_Injection__Servlet_getParameter_executeQuery_01 {',
    '  /* FLAW: bad source */',
    '  public void bad() { GoodSource(); }',
    '}',
  ].join('\n');
  const fileContents = { [finding.file]: unneutralizedSource };
  const prompt = _internal.renderPrompt(finding, fileContents, 'c', 'n', '/scan/root');

  const hits = auditPromptText(prompt);
  assert.ok(hits.length > 0,
    'expected the un-neutralized fixture to leak through renderPrompt — if this now finds 0 hits, ' +
    'renderPrompt gained its own independent redaction and this test should be inverted, not deleted');
  // The filename itself is embedded verbatim via {{file}} — this is the
  // single highest-value leak PRD §10 names, and it is NOT caught by any
  // isolation renderPrompt performs itself.
  assert.match(prompt, /CWE89_SQL_Injection/);
});
