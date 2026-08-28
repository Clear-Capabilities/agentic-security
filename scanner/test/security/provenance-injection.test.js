// FR-PROV-026: untrusted commit metadata (author name, commit summary) must
// never reach a terminal or a Markdown/HTML renderer un-sanitized. A
// malicious commit author name containing ANSI/control escape sequences
// could manipulate terminal state (clear the screen, move the cursor,
// forge fake output lines); one containing Markdown-significant punctuation
// could turn plain text into a live link/image/raw-HTML/code-fence-breakout
// in a rendered report.
//
// sanitizeForTerminal/sanitizeForMarkdown live in posture/provenance/schema.js
// (shared by report/index.js's explainProvenance/toMarkdown AND
// posture/auditor-walkthrough.js's renderWalkthrough — two independent
// CLI/Markdown renderers of the same untrusted findingOrigin fields) and are
// re-exported from report/index.js for discoverability.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainProvenance, sanitizeForTerminal, sanitizeForMarkdown, toMarkdown } from '../../src/report/index.js';
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

test('sanitizeForTerminal: leaves ordinary names untouched', () => {
  assert.equal(sanitizeForTerminal('Jamie Chen'), 'Jamie Chen');
  assert.equal(sanitizeForTerminal("O'Brien-Smith"), "O'Brien-Smith");
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

test('sanitizeForMarkdown: strips control characters and collapses newlines (terminal-safety is a subset)', () => {
  const malicious = 'Evil\x1b[2J\x1b[HName\nSecond line';
  const clean = sanitizeForMarkdown(malicious);
  assert.ok(!/\x1b/.test(clean));
  assert.ok(!clean.includes('\n'));
});

test('sanitizeForMarkdown: neutralizes a Markdown link/image injection', () => {
  const malicious = '[click me](javascript:alert(1))';
  const clean = sanitizeForMarkdown(malicious);
  // The literal author text must survive (visible, not dropped) but no
  // longer parse as a Markdown link: '[' and '(' must be escaped.
  assert.match(clean, /click me/);
  assert.ok(!/(?<!\\)\[click me\]\(javascript:alert\(1\)\)/.test(clean), 'must not remain live link syntax');
  assert.doesNotMatch(clean, /^\[.*\]\(.*\)$/);
});

test('sanitizeForMarkdown: neutralizes a raw-HTML injection', () => {
  const malicious = '<img src=x onerror=alert(1)>';
  const clean = sanitizeForMarkdown(malicious);
  // CommonMark backslash-escaping, not deletion: '<' survives as a literal
  // character (the text stays honest about what was in the data) but is
  // prefixed with '\' so a renderer treats it as inert punctuation rather
  // than the start of an HTML tag.
  assert.ok(!/(?<!\\)</.test(clean), 'every "<" must be backslash-escaped, none may open a raw HTML tag');
  assert.match(clean, /\\</);
});

test('sanitizeForMarkdown: neutralizes a code-fence breakout attempt', () => {
  const malicious = 'Name\n```\nFAKE SECTION\n```';
  const clean = sanitizeForMarkdown(malicious);
  assert.ok(!clean.includes('```'), 'a literal triple-backtick run must not survive unescaped');
});

test('sanitizeForMarkdown: leaves ordinary names readable', () => {
  assert.match(sanitizeForMarkdown('Jamie Chen'), /Jamie Chen/);
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

test('deriveComplianceProvenance + renderWalkthrough: a malicious authorName never reaches raw Markdown output', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorDate: '2026-01-01T00:00:00Z', authorName: 'Evil\x1b[2J[click](javascript:alert(1))' },
  });
  const finding = { id: 'f1', findingProvenance: fp };
  const dp = deriveComplianceProvenance([finding]);
  assert.ok(dp.earliestOrigin);
  assert.equal(dp.earliestOrigin.authorName, 'Evil\x1b[2J[click](javascript:alert(1))', 'raw value is preserved on the data object — sanitization happens at render time, not capture time');

  const fw = { id: 'test-fw', controls: [] };
  const evaluation = [{
    control: { id: 'C-1', function: 'Detect', summary: 'Example control', evidence: [] },
    status: 'absent',
    observations: [],
    controlRefs: ['f1'],
    derivedProvenance: dp,
  }];
  const rendered = renderWalkthrough(fw, evaluation, {});
  assert.ok(!/\x1b/.test(rendered), 'ESC byte must not reach the walkthrough Markdown/console output');
  assert.ok(!/\[click\]\(javascript:alert\(1\)\)/.test(rendered), 'must not remain live Markdown link syntax');
});
