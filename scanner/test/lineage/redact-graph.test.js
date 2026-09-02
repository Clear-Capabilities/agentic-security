import { test } from 'node:test';
import assert from 'node:assert/strict';
import { _redactGraph, _redactNode, _redactEvidence } from '../../src/lineage/redact-graph.js';

// fix-round-1, B1: `graph.recipientProfiles[].technicalEndpoint` is lifted
// verbatim from a resolved destination literal (recipient-registry.js's
// buildRecipientProfile) — the exact same "literal URL lifted from scanned
// code" shape `node.destination.literalValue` already redacts — but
// `_redactGraph` never touched `graph.recipientProfiles` at all before this
// fix, so a secret embedded in it reached `dataflow_get_graph` unredacted.

const SECRET_AWS_KEY = 'AKIAABCDEFGHIJKLMNOP';

test('_redactGraph: redacts recipientProfiles[].technicalEndpoint carrying a real secret pattern', () => {
  const graph = {
    nodes: [],
    evidence: [],
    recipientProfiles: [
      {
        id: 'recipient:aws-s3:abc123',
        recipientKey: 'Amazon S3',
        technicalEndpoint: `https://my-bucket.s3.amazonaws.com/?token=${SECRET_AWS_KEY}`,
        provider: 'Amazon S3',
        legalEntity: null,
        retentionCommitment: null,
        transferMechanism: null,
      },
    ],
  };

  const result = _redactGraph(graph);
  const profile = result.recipientProfiles[0];
  assert.doesNotMatch(profile.technicalEndpoint, new RegExp(SECRET_AWS_KEY));
  assert.match(profile.technicalEndpoint, /\[REDACTED:aws-access-key\]/);
  // Non-redactable fields survive untouched.
  assert.equal(profile.provider, 'Amazon S3');
  assert.equal(profile.recipientKey, 'Amazon S3');

  // Never mutates the input graph.
  assert.match(graph.recipientProfiles[0].technicalEndpoint, new RegExp(SECRET_AWS_KEY));
});

test('_redactGraph: also redacts legalEntity/retentionCommitment/transferMechanism defensively', () => {
  const graph = {
    nodes: [],
    evidence: [],
    recipientProfiles: [
      {
        id: 'recipient:acme:def456',
        recipientKey: 'acme',
        technicalEndpoint: null,
        legalEntity: `Acme Corp (key: ${SECRET_AWS_KEY})`,
        retentionCommitment: `retained per contract, ref ${SECRET_AWS_KEY}`,
        transferMechanism: `SCC on file, id ${SECRET_AWS_KEY}`,
      },
    ],
  };

  const result = _redactGraph(graph);
  const profile = result.recipientProfiles[0];
  assert.doesNotMatch(profile.legalEntity, new RegExp(SECRET_AWS_KEY));
  assert.doesNotMatch(profile.retentionCommitment, new RegExp(SECRET_AWS_KEY));
  assert.doesNotMatch(profile.transferMechanism, new RegExp(SECRET_AWS_KEY));
  assert.match(profile.legalEntity, /\[REDACTED:aws-access-key\]/);
  assert.match(profile.retentionCommitment, /\[REDACTED:aws-access-key\]/);
  assert.match(profile.transferMechanism, /\[REDACTED:aws-access-key\]/);
});

test('_redactGraph: recipientProfiles with no redactable string fields pass through unchanged', () => {
  const graph = {
    nodes: [],
    evidence: [],
    recipientProfiles: [
      { id: 'recipient:x:1', recipientKey: 'x', technicalEndpoint: null, legalEntity: null, retentionCommitment: null, transferMechanism: null, provider: 'x' },
    ],
  };
  const result = _redactGraph(graph);
  assert.deepEqual(result.recipientProfiles, graph.recipientProfiles);
});

test('_redactGraph: missing/non-array recipientProfiles is passed through as-is', () => {
  assert.equal(_redactGraph({ nodes: [], evidence: [] }).recipientProfiles, undefined);
  const graphWithNonArray = { nodes: [], evidence: [], recipientProfiles: null };
  assert.equal(_redactGraph(graphWithNonArray).recipientProfiles, null);
});

// Sanity: _redactNode/_redactEvidence are unaffected by this change (still
// exported, still work) — a minimal regression guard, not full re-coverage
// (that already lives in export-json.test.js / mcp-dataflow-tools.test.js).
test('_redactGraph: still redacts nodes/evidence alongside recipientProfiles', () => {
  const graph = {
    nodes: [{ id: 'node:1', destination: { raw: SECRET_AWS_KEY, literalValue: SECRET_AWS_KEY, blockingExpression: null } }],
    evidence: [{ id: 'evidence:1', claim: SECRET_AWS_KEY, snippet: null, location: null }],
    recipientProfiles: [],
  };
  const result = _redactGraph(graph);
  assert.doesNotMatch(result.nodes[0].destination.raw, new RegExp(SECRET_AWS_KEY));
  assert.doesNotMatch(result.evidence[0].claim, new RegExp(SECRET_AWS_KEY));
  assert.deepEqual(result.nodes, [_redactNode(graph.nodes[0])]);
  assert.deepEqual(result.evidence, _redactEvidence(graph.evidence));
});
