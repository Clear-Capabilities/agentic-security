import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportFlowsCSV } from '../../src/lineage/export-csv.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

test('exportFlowsCSV: header row matches the documented column list', () => {
  const csv = exportFlowsCSV(flagship);
  const [header] = csv.split('\n');
  assert.equal(header, 'id,source,sink,dataClasses,transitVerdict,atRestVerdict,handlingVerdict,policyVerdict,coverageStatus');
});

test('exportFlowsCSV: one data row per real flow, in graph order', () => {
  const csv = exportFlowsCSV(flagship);
  const rows = csv.split('\n').slice(1);
  assert.equal(rows.length, flagship.flows.length);
});

// Real per-row assertion, traced by hand against the real flagship fixture
// (confirmed by reading flagship-graph.json directly, not invented):
//
//   flow:f7273b6e7b61 (index 0 of flagship.flows) —
//     source: node:source:4aa6d910c10e (Web App)
//     sink:   node:log:608492464d54   (Application Logs)
//     dataElementIds: [data:f68cbbd8e123] -> dataElements[data:f68cbbd8e123]
//       .dataClasses = ['PCI'] -> single value, joins to "PCI" regardless
//       of join character.
//     edgeIds: [edge:54d5b1db3415, edge:d613505336aa]
//       edge:54d5b1db3415.protection: transit=not_assessed,
//         atRest=not_assessed, handling=not_assessed
//       edge:d613505336aa.protection: transit=not_assessed,
//         atRest=not_assessed, handling=protected
//     aggregateVerdicts precedence (protection.js's own _PRECEDENCE, lower
//     index wins): ['unprotected','mixed','unknown','protected',
//     'not_applicable','not_assessed'].
//       transitVerdict  = aggregateVerdicts(['not_assessed','not_assessed'])
//                        = 'not_assessed' (only candidate)
//       atRestVerdict   = aggregateVerdicts(['not_assessed','not_assessed'])
//                        = 'not_assessed' (only candidate)
//       handlingVerdict = aggregateVerdicts(['not_assessed','protected'])
//                        = 'protected' (rank 3 beats rank 5)
//     flow.policyVerdict = 'not_evaluated' (real field on the fixture)
//     flow.coverageStatus = 'modeled' (real field on the fixture)
test('exportFlowsCSV: a real flagship flow row matches hand-traced expected values', () => {
  const flow = flagship.flows.find((f) => f.id === 'flow:f7273b6e7b61');
  assert.ok(flow, 'expected flow:f7273b6e7b61 to exist in the flagship fixture');
  assert.equal(flow.source, 'node:source:4aa6d910c10e');
  assert.equal(flow.sink, 'node:log:608492464d54');
  assert.deepEqual(flow.dataElementIds, ['data:f68cbbd8e123']);
  assert.deepEqual(flow.edgeIds, ['edge:54d5b1db3415', 'edge:d613505336aa']);
  assert.equal(flow.policyVerdict, 'not_evaluated');
  assert.equal(flow.coverageStatus, 'modeled');

  const de = flagship.dataElements.find((d) => d.id === 'data:f68cbbd8e123');
  assert.deepEqual(de.dataClasses, ['PCI']);

  const e1 = flagship.edges.find((e) => e.id === 'edge:54d5b1db3415');
  const e2 = flagship.edges.find((e) => e.id === 'edge:d613505336aa');
  assert.deepEqual(e1.protection, {
    transit: { verdict: 'not_assessed', evidenceGrade: 'none' },
    atRest: { verdict: 'not_assessed', evidenceGrade: 'none' },
    handling: { verdict: 'not_assessed', evidenceGrade: 'none' },
  });
  assert.equal(e2.protection.transit.verdict, 'not_assessed');
  assert.equal(e2.protection.atRest.verdict, 'not_assessed');
  assert.equal(e2.protection.handling.verdict, 'protected');

  const csv = exportFlowsCSV(flagship);
  const rows = csv.split('\n');
  const rowIndex = flagship.flows.findIndex((f) => f.id === 'flow:f7273b6e7b61') + 1; // +1 for header
  assert.equal(rowIndex, 1, 'flow:f7273b6e7b61 is expected at flows[0] in the committed fixture');
  assert.equal(
    rows[rowIndex],
    'flow:f7273b6e7b61,node:source:4aa6d910c10e,node:log:608492464d54,PCI,not_assessed,not_assessed,protected,not_evaluated,modeled',
  );
});

// Real join-character decision: multi-value `dataClasses` cells join with
// `;`, not `,` — the common multi-class case (e.g. a field classified both
// PCI and PII) becomes "PCI;PII" and never needs outer quoting, since `;`
// is not a CSV delimiter. This test proves `esc()`'s comma-quoting still
// fires correctly for ANY comma that ends up in cell content, using a
// synthetic (not-a-real-taxonomy-value) dataClass name that itself
// contains a comma, to construct a case that needs quoting regardless of
// which join character was chosen.
test('exportFlowsCSV: a field containing a comma is quoted', () => {
  const graph = {
    nodes: [],
    edges: [],
    dataElements: [{ id: 'data:x', dataClasses: ['PCI,extra'] }],
    flows: [{
      id: 'flow:x',
      source: 'node:a',
      sink: 'node:b',
      dataElementIds: ['data:x'],
      edgeIds: [],
      policyVerdict: 'not_evaluated',
      coverageStatus: 'modeled',
    }],
  };
  const csv = exportFlowsCSV(graph);
  const rows = csv.split('\n');
  assert.equal(rows.length, 2);
  assert.equal(
    rows[1],
    'flow:x,node:a,node:b,"PCI,extra",not_assessed,not_assessed,not_assessed,not_evaluated,modeled',
  );
});

// Confirms the real join character used for multiple dataClasses values on
// ONE flow (as opposed to a single value, or a single value containing a
// comma, both covered above): two distinct classes join with ';', proving
// the chosen convention directly rather than only by implication.
test('exportFlowsCSV: multiple dataClasses values join with the documented ";" character', () => {
  const graph = {
    nodes: [],
    edges: [],
    dataElements: [{ id: 'data:x', dataClasses: ['PCI', 'PII'] }],
    flows: [{
      id: 'flow:x',
      source: 'node:a',
      sink: 'node:b',
      dataElementIds: ['data:x'],
      edgeIds: [],
      policyVerdict: 'not_evaluated',
      coverageStatus: 'modeled',
    }],
  };
  const csv = exportFlowsCSV(graph);
  const rows = csv.split('\n');
  assert.equal(rows[1], 'flow:x,node:a,node:b,PCI;PII,not_assessed,not_assessed,not_assessed,not_evaluated,modeled');
});
