// FR-PROV-018 acceptance: the same finding's provenance status/commit must
// appear, consistently, across every output format — at that format's own
// fidelity (a CSV column is not a JSON tree, but it must not be EMPTY or
// WRONG when the JSON says 'complete'/'abc1234567').
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toJSON, toCLI, toSARIF, toCSV, toMarkdown, toHTML } from '../../src/report/index.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';

const FP = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
  findingOrigin: { commit: 'deadbee1234', authorName: 'Parity Author', authorDate: '2026-05-01T00:00:00Z' },
});
const SCAN = {
  findings: [{ id: 'parity-1', file: 'x.js', line: 7, severity: 'high', vuln: 'Command Injection', cwe: 'CWE-78', findingProvenance: FP }],
  filesScanned: 1,
};

test('format parity: JSON carries the full findingProvenance object', () => {
  const j = toJSON(SCAN);
  assert.equal(j.findings[0].findingProvenance.status, 'complete');
  assert.equal(j.findings[0].findingProvenance.findingOrigin.commit, 'deadbee1234');
});

test('format parity: CLI --provenance carries the commit and status', () => {
  const out = toCLI(SCAN, { color: false, provenance: true });
  assert.match(out, /deadbee/);
});

test('format parity: SARIF result properties carry the commit and status', () => {
  const sarif = toSARIF(SCAN);
  const props = sarif.runs[0].results[0].properties.findingProvenance;
  assert.equal(props.status, 'complete');
  assert.equal(props.findingOrigin.commit, 'deadbee1234');
});

test('format parity: CSV row carries the status and commit columns', () => {
  const csv = toCSV(SCAN);
  const [, row] = csv.split('\n');
  assert.match(row, /complete/);
  assert.match(row, /deadbee1234/);
});

test('format parity: Markdown carries the commit inside the provenance block', () => {
  const md = toMarkdown(SCAN);
  assert.match(md, /deadbee/);
});

test('format parity: HTML embeds the commit via the precomputed _explainProvenance', () => {
  const html = toHTML(SCAN);
  assert.match(html, /deadbee/);
});

test('format parity: every format agrees on ABSENCE too — no findingProvenance means no format fabricates one', () => {
  const clean = { findings: [{ id: 'clean-1', file: 'y.js', line: 1, severity: 'low', vuln: 'Info' }], filesScanned: 1 };
  assert.equal(toJSON(clean).findings[0].findingProvenance, null);
  assert.doesNotMatch(toCLI(clean, { color: false, provenance: true }), /Method:/);
  assert.equal(toSARIF(clean).runs[0].results[0].properties.findingProvenance, undefined);
  const [, csvRow] = toCSV(clean).split('\n');
  assert.match(csvRow, /,,,,$/, 'the four provenance columns must be empty, not fabricated');
  assert.doesNotMatch(toMarkdown(clean), /<summary>Provenance<\/summary>/);
  assert.match(toHTML(clean), /"_explainProvenance":null/);
});
