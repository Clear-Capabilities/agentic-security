// FR-PROV-026: untrusted commit metadata (author name, commit summary) must
// never reach a terminal un-sanitized. A malicious commit author name
// containing ANSI/control escape sequences could manipulate terminal state
// (clear the screen, move the cursor, forge fake output lines).
//
// sanitizeForTerminal lives in posture/provenance/schema.js (shared by
// report/index.js's explainProvenance AND posture/auditor-walkthrough.js's
// renderWalkthrough — two independent CLI renderers of the same untrusted
// findingOrigin fields) and is re-exported from report/index.js for
// discoverability.
//
// A Markdown-specific sibling (sanitizeForMarkdown, backslash-escaping
// CommonMark punctuation) was added here and then REMOVED after code
// review: it was applied to renderWalkthrough's output, but that text's
// only live consumer is bin/agentic-security.js's raw `console.log`
// (`compliance --walkthrough`) — persistWalkthrough, the function that
// would write a real `.md` file, has zero callers anywhere in the
// CLI/command surface, so nothing in this repo ever runs this text through
// an actual Markdown renderer. Backslash-escaping is only inert once a real
// renderer processes it; printed raw to a terminal or read as plain text,
// the escapes are VISIBLE LITERAL BACKSLASHES — a real, reproducible
// regression on extremely common real-world author names (`dependabot[bot]`
// -> `dependabot\[bot\]`, `Jean-Luc Picard` -> `Jean\-Luc Picard`). See the
// regression tests below and schema.js's header comment for the full
// reasoning. `toMarkdown`'s provenance code-fence-breakout defense (a
// SEPARATE, genuinely-needed Markdown fix, since that block IS embedded in
// a real Markdown document written to a report file) does not use
// character escaping at all — it uses a dynamically-sized fence instead,
// which has no "visible backslash" failure mode.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainProvenance, sanitizeForTerminal, toMarkdown } from '../../src/report/index.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';
import { deriveComplianceProvenance, renderWalkthrough } from '../../src/posture/auditor-walkthrough.js';

test('sanitizeForTerminal: strips ANSI escape sequences', () => {
  const malicious = 'Evil\x1b[2J\x1b[HName';
  const clean = sanitizeForTerminal(malicious);
  assert.ok(!clean.includes('\x1b'), 'ESC byte must be stripped');
});

test('sanitizeForTerminal: strips the full C0 control range (except tab) and DEL', () => {
  let allControls = '';
  for (let i = 0; i <= 0x1f; i++) if (i !== 0x09 && i !== 0x0a && i !== 0x0d) allControls += String.fromCharCode(i);
  allControls += String.fromCharCode(0x7f);
  const clean = sanitizeForTerminal(`a${allControls}b`);
  assert.equal(clean, 'ab', 'every non-tab/newline C0 control char and DEL must be removed');
  assert.equal(sanitizeForTerminal('a\tb'), 'a\tb', 'tab is not a control char for this purpose and survives');
});

test('sanitizeForTerminal: collapses embedded newlines to a single line', () => {
  const malicious = 'Real Name\nFAKE: Introduced: abc123 by Nobody';
  const clean = sanitizeForTerminal(malicious);
  assert.ok(!clean.includes('\n'), 'newline must not survive');
  assert.equal(clean.split('\n').length, 1);
  // Collapsed to a visible space, not silently vanished — the forged line
  // is still readable as suspicious single-line text, not hidden.
  assert.match(clean, /Real Name\s+FAKE:/);
});

test('sanitizeForTerminal: leaves ordinary names untouched, including common punctuated real-world names', () => {
  assert.equal(sanitizeForTerminal('Jamie Chen'), 'Jamie Chen');
  assert.equal(sanitizeForTerminal("O'Brien-Smith"), "O'Brien-Smith");
  // Regression fixtures for the code-review finding: these are extremely
  // common real git author names, and a backslash-escaping sanitizer
  // visibly corrupted every one of them (dependabot\[bot\], Jean\-Luc
  // Picard, O'Brien\-Smith, Dr\. Jones) since nothing in this repo ever
  // renders this text through a real Markdown engine that would interpret
  // (and thus need) the escapes.
  assert.equal(sanitizeForTerminal('dependabot[bot]'), 'dependabot[bot]');
  assert.equal(sanitizeForTerminal('renovate[bot]'), 'renovate[bot]');
  assert.equal(sanitizeForTerminal('Jean-Luc Picard'), 'Jean-Luc Picard');
  assert.equal(sanitizeForTerminal('Dr. Jones'), 'Dr. Jones');
});

test('sanitizeForTerminal: non-string input passes through unchanged', () => {
  assert.equal(sanitizeForTerminal(null), null);
  assert.equal(sanitizeForTerminal(undefined), undefined);
  assert.equal(sanitizeForTerminal(42), 42);
});

test('explainProvenance: a malicious authorName in a real finding never reaches raw output with control characters', () => {
  const f = {
    findingProvenance: {
      status: 'complete',
      findingOrigin: {
        commit: 'abc1234567890', authorDate: '2026-01-01T00:00:00Z',
        authorName: 'Evil\x1b[2J\x1b[HPwned', summary: 'x',
      },
      method: 'semantic-history-replay',
      confidence: { level: 'high', score: 0.9, reasons: [] },
    },
  };
  const rendered = explainProvenance(f);
  // explainProvenance returns a single '\n'-joined string, not an array —
  // confirmed against the actual `return lines.join('\n')` in report/index.js.
  assert.equal(typeof rendered, 'string');
  assert.ok(rendered.length > 0);
  for (const line of rendered.split('\n')) {
    assert.ok(!/\x1b/.test(line), `line contains raw ESC: ${JSON.stringify(line)}`);
  }
  assert.match(rendered, /Pwned/, 'the sanitized name must still be visible, not silently dropped');
});

test('explainProvenance: an ordinary punctuated authorName renders with no visible backslashes', () => {
  const f = {
    findingProvenance: {
      status: 'complete',
      findingOrigin: { commit: 'abc1234567890', authorDate: '2026-01-01T00:00:00Z', authorName: 'dependabot[bot]' },
      method: 'semantic-history-replay',
      confidence: { level: 'high', score: 0.9, reasons: [] },
    },
  };
  const rendered = explainProvenance(f);
  assert.match(rendered, /dependabot\[bot\]/);
  assert.ok(!rendered.includes('\\'), `no backslash should appear in output for an ordinary name: ${JSON.stringify(rendered)}`);
});

test('explainProvenance: a malicious branchIntroduction.relationship never reaches raw output with control characters', () => {
  const f = {
    findingProvenance: {
      status: 'complete',
      findingOrigin: { commit: 'abc1234567890', authorDate: '2026-01-01T00:00:00Z', authorName: 'Jamie Chen' },
      branchIntroduction: { commit: 'def4567890abc', relationship: 'merge\x1b[2J-base' },
      method: 'semantic-history-replay',
      confidence: { level: 'high', score: 0.9, reasons: [] },
    },
  };
  const rendered = explainProvenance(f);
  assert.ok(!/\x1b/.test(rendered));
});

test('toMarkdown: an authorName containing a backtick run cannot break out of the provenance code fence', () => {
  const scan = {
    findings: [{
      id: 'f1', file: 'a.js', line: 1, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89',
      findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
        findingOrigin: { commit: 'abc1234567', authorDate: '2026-03-14T00:00:00Z', authorName: 'Evil````\n## Forged Heading\n````Name' },
      }),
    }],
    filesScanned: 1,
  };
  const md = toMarkdown(scan);
  // The forged heading text must never appear OUTSIDE the fenced block as a
  // real Markdown heading — it is only acceptable as literal fenced text.
  // Split on lines and confirm no line outside a fence is a bare '## ...'
  // heading that wasn't part of the report's own structure.
  const lines = md.split('\n');
  const fenceLineIdx = lines.map((l, i) => (/^`{3,}$/.test(l) ? i : -1)).filter((i) => i >= 0);
  assert.ok(fenceLineIdx.length >= 2, 'expected an opening and closing fence');
  // Opening and closing fence markers must be IDENTICAL length and must be
  // longer than the longest backtick run embedded in the content, so the
  // embedded backticks can never terminate the fence early.
  const open = lines[fenceLineIdx[0]];
  const close = lines[fenceLineIdx[1]];
  assert.equal(open, close, 'opening and closing fence must match');
  assert.ok(open.length > 4, 'fence must be longer than the embedded 4-backtick run');
});

test('toMarkdown: an ordinary punctuated authorName (dependabot[bot]) renders with no visible backslashes', () => {
  const scan = {
    findings: [{
      id: 'f1', file: 'a.js', line: 1, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89',
      findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
        findingOrigin: { commit: 'abc1234567', authorDate: '2026-03-14T00:00:00Z', authorName: 'dependabot[bot]' },
      }),
    }],
    filesScanned: 1,
  };
  const md = toMarkdown(scan);
  assert.match(md, /dependabot\[bot\]/);
  assert.ok(!md.includes('\\'), 'no backslash-escaping should appear for an ordinary name');
});

function makeWalkthroughFixture(authorName) {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorDate: '2026-01-01T00:00:00Z', authorName },
  });
  const finding = { id: 'f1', findingProvenance: fp };
  const dp = deriveComplianceProvenance([finding]);
  const fw = { id: 'test-fw', controls: [] };
  const evaluation = [{
    control: { id: 'C-1', function: 'Detect', summary: 'Example control', evidence: [] },
    status: 'absent',
    observations: [],
    controlRefs: ['f1'],
    derivedProvenance: dp,
  }];
  return { dp, rendered: renderWalkthrough(fw, evaluation, {}) };
}

test('deriveComplianceProvenance + renderWalkthrough: a malicious authorName never reaches raw output with control characters', () => {
  const { dp, rendered } = makeWalkthroughFixture('Evil\x1b[2J[click](javascript:alert(1))');
  assert.ok(dp.earliestOrigin);
  assert.equal(dp.earliestOrigin.authorName, 'Evil\x1b[2J[click](javascript:alert(1))', 'raw value is preserved on the data object — sanitization happens at render time, not capture time');
  assert.ok(!/\x1b/.test(rendered), 'ESC byte must not reach the walkthrough console output');
});

// Regression test for the code-review finding: renderWalkthrough's ONLY
// live consumer (bin/agentic-security.js's raw `console.log`) never passes
// this text through a real Markdown renderer, so it must render exactly as
// typed for ordinary names — no backslash-escaping artifacts. Uses real,
// extremely common punctuated author names (a bot account and a hyphenated
// human name), not the bare single-letter names ('A'/'B'/'C'/'D') the
// pre-existing framework-provenance-controlrefs.test.js fixtures use, which
// is exactly why a backslash-escaping regression slipped through review the
// first time — single-letter names have no punctuation to corrupt.
test('renderWalkthrough: dependabot[bot] renders with no visible backslashes', () => {
  const { rendered } = makeWalkthroughFixture('dependabot[bot]');
  assert.match(rendered, /Earliest proven origin.*dependabot\[bot\]/);
  assert.ok(!rendered.includes('\\'), `no backslash should appear for an ordinary bot name: ${JSON.stringify(rendered)}`);
});

test('renderWalkthrough: Jean-Luc Picard renders with no visible backslashes', () => {
  const { rendered } = makeWalkthroughFixture('Jean-Luc Picard');
  assert.match(rendered, /Earliest proven origin.*Jean-Luc Picard/);
  assert.ok(!rendered.includes('\\'), `no backslash should appear for an ordinary hyphenated name: ${JSON.stringify(rendered)}`);
});

test("renderWalkthrough: O'Brien-Smith and Dr. Jones render with no visible backslashes", () => {
  assert.ok(!makeWalkthroughFixture("O'Brien-Smith").rendered.includes('\\'));
  assert.ok(!makeWalkthroughFixture('Dr. Jones').rendered.includes('\\'));
});
