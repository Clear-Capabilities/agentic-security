import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { graphId } from '../../src/lineage/ids.js';
import { emptyGraphEnvelope } from '../../src/lineage/schema.js';
import { exportGraphJSON, computeGraphDigest } from '../../src/lineage/export-json.js';
import { loadRemoteGraphExport } from '../../src/lineage/federation-loader.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

function tmpFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-federation-loader-'));
  return path.join(dir, name);
}

// B1 (final whole-branch review, M5 deliverable #8): every fixture in this
// file now builds via exportGraphJSON's own REAL DEFAULT (redact:true) —
// the shape the CLI's own `dataflow export --format json` actually
// produces. The pre-fix version of this file built exclusively via
// `exportGraphJSON(graph, { redact: false })`, the NON-default option,
// which is exactly why the shipped test suite never caught B1: it only
// ever exercised a shape the real CLI never produces by default.
function validEnvelopeFile() {
  const graph = emptyGraphEnvelope({ graphId: graphId({ repository: 'remote-svc' }) });
  const exported = exportGraphJSON(graph, {});
  const filePath = tmpFile('remote-export.json');
  fs.writeFileSync(filePath, JSON.stringify(exported, null, 2));
  return { filePath, graph, exported };
}

test('loadRemoteGraphExport: missing file — ok:false, reason "missing"', () => {
  const r = loadRemoteGraphExport(path.join(os.tmpdir(), 'this-file-does-not-exist-agsec-federation.json'));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing');
  assert.equal(r.graph, null);
  assert.match(r.message, /No remote graph export found/);
});

test('loadRemoteGraphExport: no filePath at all — ok:false, reason "missing"', () => {
  const r = loadRemoteGraphExport(undefined);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing');
});

test('loadRemoteGraphExport: malformed JSON — ok:false, reason "malformed"', () => {
  const filePath = tmpFile('bad.json');
  fs.writeFileSync(filePath, '{not valid json');
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed');
});

test('loadRemoteGraphExport: valid JSON but not an exportGraphJSON envelope — ok:false, reason "malformed"', () => {
  const filePath = tmpFile('not-an-envelope.json');
  fs.writeFileSync(filePath, JSON.stringify({ hello: 'world' }));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed');
});

test('loadRemoteGraphExport: envelope has bodyDigest+graph but graph fails validateGraph — ok:false, reason "invalid-graph"', () => {
  const filePath = tmpFile('invalid-graph.json');
  const badGraph = { nodes: [{ id: 'not-a-real-node-id-shape' }] }; // missing required fields, wrong id prefix
  fs.writeFileSync(filePath, JSON.stringify({ bodyDigest: computeGraphDigest(badGraph), graph: badGraph }));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid-graph');
  assert.equal(r.graph, null);
});

test('loadRemoteGraphExport: digest mismatch — ok:true, digestMatches:false, reason "digest-mismatch", still returns the graph', () => {
  const { filePath, exported } = validEnvelopeFile();
  const tampered = { ...exported, bodyDigest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' };
  fs.writeFileSync(filePath, JSON.stringify(tampered));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.digestMatches, false);
  assert.equal(r.reason, 'digest-mismatch');
  assert.ok(r.graph);
  assert.match(r.message, /NOT authentication/);
});

test('loadRemoteGraphExport: a genuinely valid, self-consistent export — ok:true, digestMatches:true, reason:null', () => {
  const { filePath, graph } = validEnvelopeFile();
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.digestMatches, true);
  assert.equal(r.reason, null);
  assert.deepEqual(r.graph, graph);
  assert.equal(r.digest, computeGraphDigest(graph));
});

// B1 (final whole-branch review, M5 deliverable #8): the exact bug this
// test reproduces. Pre-fix, `loadRemoteGraphExport` recomputed
// `computeGraphDigest(parsed.graph)` (over the REDACTED body) and compared
// it to `parsed.digest` (the SOURCE graph's digest) — under default
// redaction, this mismatched whenever anything was actually redacted, so a
// genuine, un-tampered, default-redacted export permanently read
// `digestMatches: false`. This fixture carries a Slack-webhook literal as
// a node destination — the exact live-repro shape the final review used —
// which `_redactGraph`/`redactString` genuinely mutates under DEFAULT
// redaction (no `--no-redact`). This test FAILS against the pre-fix code
// (`digestMatches` would be `false`) and PASSES after the fix.
const REDACTABLE_SECRET = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX';

test('loadRemoteGraphExport: a genuinely un-tampered, DEFAULT-redacted export reads digestMatches:true (B1 regression)', () => {
  const graphWithRedactableNode = {
    ...flagship,
    nodes: [
      ...flagship.nodes,
      {
        id: 'node:synthetic-webhook-sink',
        kind: 'sink',
        subtype: 'external-webhook',
        label: 'Synthetic Webhook Sink',
        aliases: [],
        dataElementIds: [],
        evidenceRefs: [],
        coverageStatus: 'modeled',
        destination: {
          resolutionStatus: 'literal',
          raw: REDACTABLE_SECRET,
          literalValue: REDACTABLE_SECRET,
          blockingExpression: null,
        },
      },
    ],
  };
  // Export with the CLI's own real default — no `redact: false`, no
  // `--no-redact` equivalent.
  const exported = exportGraphJSON(graphWithRedactableNode);
  // Confirm the field is genuinely redacted in the exported body (the fix
  // must not turn off redaction — only fix the digest comparison).
  const exportedNode = exported.graph.nodes.find((n) => n.id === 'node:synthetic-webhook-sink');
  assert.doesNotMatch(exportedNode.destination.literalValue, /hooks\.slack\.com\/services\/T00000000/);
  assert.match(exportedNode.destination.literalValue, /\[REDACTED:slack-webhook\]/);

  const filePath = tmpFile('remote-export-redacted.json');
  fs.writeFileSync(filePath, JSON.stringify(exported));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.reason, null);
  assert.equal(r.digestMatches, true, 'a genuinely un-tampered, default-redacted export must self-verify — comparing against bodyDigest, never the source-graph digest');
});

test('federation-loader.js never reuses loadSignedGraph for the remote side — the per-install-HMAC-key trust model is deliberately the WRONG one for a cross-machine remote file', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/federation-loader.js', import.meta.url)), 'utf8');
  assert.ok(!src.includes('graph-loader'), 'must never import scanner/src/server/graph-loader.js\'s loadSignedGraph for the remote side');
});
