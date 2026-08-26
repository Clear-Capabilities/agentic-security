// FR-406 (assurance-hardening PRD): generate a code-derived data inventory
// and flow graph. Each record includes data class, source, transformations,
// storage, sink/recipient, and evidence locations.
//
// The property under test throughout: this is an inventory of REAL,
// OBSERVED flows built from what privacy-taint.js already computed — never
// a fabricated or guessed field. "transformations" is always the literal
// not_modeled sentinel (this engine has no sanitizer-tracking for privacy
// flows — that's FR-403, deferred), and "storage" is explicitly
// distinguished from "sink/recipient" by sink category, not merged.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { annotatePrivacyTaint } from '../src/dataflow/privacy-taint.js';
import {
  NOT_MODELED, STORAGE_SINK_KINDS, buildDataInventory,
  emitDataInventoryArtifact, emitDataFlowGraph,
} from '../src/dataflow/privacy-inventory.js';

function twoSinkIR() {
  const m = new Map();
  m.set('a.js', {
    _content: 'const email = req.body.email;\nconsole.log(email);\nfs.writeFile("out.txt", email);\n',
    decls: [{ name: 'email', line: 1 }],
    calls: [
      { callee: 'log', fullPath: 'console.log', args: [{ text: 'email' }], line: 2 },
      { callee: 'writeFile', fullPath: 'fs.writeFile', args: [{ text: 'email' }], line: 3 },
    ],
  });
  return m;
}

test('STORAGE_SINK_KINDS distinguishes at-rest sinks from in-transit ones', () => {
  assert.ok(STORAGE_SINK_KINDS.has('fileWrite'));
  assert.ok(STORAGE_SINK_KINDS.has('s3Upload'));
  assert.ok(!STORAGE_SINK_KINDS.has('log'));
  assert.ok(!STORAGE_SINK_KINDS.has('response'));
  assert.ok(!STORAGE_SINK_KINDS.has('outboundHttp'));
});

test('buildDataInventory: a source reaching both a storage sink and a transmission sink splits correctly across storage/sinkRecipient', () => {
  const r = annotatePrivacyTaint(twoSinkIR());
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  assert.equal(inv.length, 1, 'one source variable => one inventory record');
  const rec = inv[0];
  assert.deepEqual(rec.dataClass, ['PII']);
  assert.equal(rec.source.file, 'a.js');
  assert.equal(rec.source.name, 'email');
  assert.equal(rec.source.line, 1, 'source line comes from the DECLARATION, not the sink call');
  assert.equal(rec.storage.length, 1);
  assert.equal(rec.storage[0].sinkKind, 'fileWrite');
  assert.equal(rec.storage[0].line, 3);
  assert.equal(rec.sinkRecipient.length, 1);
  assert.equal(rec.sinkRecipient[0].sinkKind, 'log');
  assert.equal(rec.sinkRecipient[0].line, 2);
});

test('buildDataInventory: transformations is ALWAYS the not_modeled sentinel — never fabricated', () => {
  const r = annotatePrivacyTaint(twoSinkIR());
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  assert.equal(inv[0].transformations, NOT_MODELED);
  assert.equal(NOT_MODELED, 'not_modeled');
});

test('buildDataInventory: evidenceLocations covers BOTH the source declaration and every sink', () => {
  const r = annotatePrivacyTaint(twoSinkIR());
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  const locs = inv[0].evidenceLocations;
  assert.equal(locs.length, 3, 'source + storage sink + transmission sink');
  assert.ok(locs.some(l => l.role === 'source' && l.line === 1));
  assert.ok(locs.some(l => l.role === 'storage' && l.line === 3));
  assert.ok(locs.some(l => l.role === 'recipient' && l.line === 2));
});

test('buildDataInventory: a policy-permitted flow is included with status policy_permitted, not silently dropped from the inventory', () => {
  const r = annotatePrivacyTaint(twoSinkIR(), {
    sinkPolicy: { allow: [{ sink: 'log', class: 'PII', reason: 'internal audit log' }] },
  });
  assert.equal(r.findings.length, 1, 'only the fileWrite sink still produces a finding');
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  assert.equal(inv.length, 1);
  const rec = inv[0];
  assert.equal(rec.storage[0].status, 'prohibited');
  assert.equal(rec.sinkRecipient[0].status, 'policy_permitted');
  assert.equal(rec.sinkRecipient[0].reason, 'internal audit log');
});

test('buildDataInventory: a declared regulated field that never reaches any recognized sink is NOT included — this is an inventory of observed flows, not declared fields', () => {
  const m = new Map();
  m.set('a.js', {
    _content: 'const email = req.body.email;\n',
    decls: [{ name: 'email', line: 1 }],
    calls: [],
  });
  const r = annotatePrivacyTaint(m);
  assert.equal(r.piiFields.length, 1, 'the field IS classified');
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  assert.equal(inv.length, 0, 'but nothing observed it reaching a sink, so no flow record exists');
});

test('buildDataInventory: two different files with a same-named variable produce two distinct records, never merged', () => {
  const m = new Map();
  m.set('a.js', {
    _content: 'const email = req.body.email;\nconsole.log(email);\n',
    decls: [{ name: 'email', line: 1 }],
    calls: [{ callee: 'log', fullPath: 'console.log', args: [{ text: 'email' }], line: 2 }],
  });
  m.set('b.js', {
    _content: 'const email = req.body.email;\nconsole.log(email);\n',
    decls: [{ name: 'email', line: 5 }],
    calls: [{ callee: 'log', fullPath: 'console.log', args: [{ text: 'email' }], line: 6 }],
  });
  const r = annotatePrivacyTaint(m);
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  assert.equal(inv.length, 2);
  assert.deepEqual(inv.map(rec => rec.source.file).sort(), ['a.js', 'b.js']);
});

test('emitDataInventoryArtifact: valid JSON, carries the schema disclaimer and every record', () => {
  const r = annotatePrivacyTaint(twoSinkIR());
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  const json = emitDataInventoryArtifact(inv);
  const parsed = JSON.parse(json);
  assert.match(parsed.schemaNote, /not_modeled/);
  assert.match(parsed.schemaNote, /best-effort/);
  assert.equal(parsed.records.length, 1);
  assert.ok(parsed.generatedAt);
});

test('emitDataFlowGraph: renders a valid mermaid block with a node per source/sink and a colored edge per flow', () => {
  const r = annotatePrivacyTaint(twoSinkIR());
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  const md = emitDataFlowGraph(inv);
  assert.match(md, /```mermaid/);
  assert.match(md, /graph LR/);
  assert.match(md, /email/);
  assert.match(md, /fileWrite/);
  assert.match(md, /log/);
  // Two edges (source->fileWrite, source->log), both prohibited => both red.
  const edgeCount = (md.match(/-->/g) || []).length;
  assert.equal(edgeCount, 2);
  const redCount = (md.match(/#c0392b/g) || []).length;
  assert.equal(redCount, 2, 'both flows are prohibited (no policy configured)');
  assert.doesNotMatch(md, /#27ae60/, 'no policy-permitted flow exists in this fixture');
});

test('emitDataFlowGraph: a policy-permitted flow renders as a distinctly-colored (green) edge, not the same as a prohibited one', () => {
  const r = annotatePrivacyTaint(twoSinkIR(), {
    sinkPolicy: { allow: [{ sink: 'log', class: 'PII' }] },
  });
  const inv = buildDataInventory(r.piiFields, r.findings, r.policyExemptions);
  const md = emitDataFlowGraph(inv);
  assert.match(md, /#c0392b/, 'the fileWrite flow is still prohibited');
  assert.match(md, /#27ae60/, 'the log flow is policy-permitted');
});

test('emitDataFlowGraph: an empty inventory renders a valid, non-broken diagram rather than an empty mermaid block', () => {
  const md = emitDataFlowGraph([]);
  assert.match(md, /```mermaid/);
  assert.match(md, /No regulated-data flows observed/);
});
