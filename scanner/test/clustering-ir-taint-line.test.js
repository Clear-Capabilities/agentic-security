// PRD R3 fallout: clusterByRootCause's sinkKey uses f.sink.label as the
// "sink expression" differentiator. For IR-TAINT findings, dataflow/engine.js
// sets sink.label to the catalog rule id (f.sinkId) — the same generic string
// for every callsite of that rule, not a per-line snippet. Before R3, IR-TAINT
// findings were appended AFTER clusterByRootCause ran, so this never mattered.
// R3 moved deep-mode findings into the same pipeline dedup/annotator flow
// everything else uses, which means clusterByRootCause now sees them — and
// two textually-unrelated eval() calls in one file (same rule, same file,
// different lines) collapsed into one cluster, silently dropping a real,
// distinct finding. Since same-line convergence is already resolved by the
// earlier dedupeFindingsWithEvidence pass, IR-TAINT findings reaching this
// annotator always have distinct lines — using the line to disambiguate is
// safe and cannot suppress a genuine same-sink multi-source cluster.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clusterByRootCause } from '../src/posture/clustering.js';

function irTaintFinding(line) {
  return {
    id: `ir-taint:app.js:${line}:js-eval`,
    file: 'app.js',
    line,
    vuln: 'Code Injection (eval)',
    severity: 'critical',
    cwe: 'CWE-94',
    family: 'code-injection',
    parser: 'IR-TAINT',
    sink: { file: 'app.js', line, label: 'js-eval' },
  };
}

test('two distinct IR-TAINT findings at different lines with the same generic sink label do not cluster together', () => {
  const findings = [irTaintFinding(28), irTaintFinding(44)];
  const clustered = clusterByRootCause(findings);
  assert.equal(clustered.length, 2,
    `expected both distinct call sites to survive, got ${clustered.length}: ${JSON.stringify(clustered.map(f => f.line))}`);
});

test('non-IR-TAINT findings with a genuinely identical normalized sink expression still cluster (unchanged behavior)', () => {
  const findings = [
    { file: 'app.js', line: 10, vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'STRUCTURAL', severity: 'high', snippet: `db.query("SELECT * FROM t WHERE id = " + x)` },
    { file: 'app.js', line: 40, vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'STRUCTURAL', severity: 'high', snippet: `db.query("SELECT * FROM t WHERE id = " + x)` },
  ];
  const clustered = clusterByRootCause(findings);
  assert.equal(clustered.length, 1, 'identical repeated pattern at different lines should still cluster for non-IR-TAINT parsers');
  assert.equal(clustered[0].clusterSize, 2);
});
