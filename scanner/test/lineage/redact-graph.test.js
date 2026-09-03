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

// Final whole-branch review, M5 deliverable #8, B2: `graph.crossRepoLinks[]`
// had no redaction pass at all — a third recurrence of the exact gap class
// this file's own header comment warns against repeating a third time.
const SECRET_ANTHROPIC_KEY = 'sk-ant-abcdefghijklmnopqrstuvwx01234';

function crossRepoLinkFixture(overrides = {}) {
  return {
    id: 'crosslink:abc123',
    version: '1.0.0',
    provenance: 'manual',
    relationship: 'data_flow',
    local: { graphId: 'dfg:local:abc:cfg', graphDigest: 'deadbeef', nodeId: 'node:sink:1' },
    remote: { graphId: 'dfg:remote:def:cfg', graphDigest: 'beefdead', nodeId: 'node:source:2', repository: 'payments-service', sourceFile: '/Users/alice/repos/payments-service/remote-export.json' },
    rationale: null,
    declaredBy: 'alice',
    declaredAt: '2026-09-02T00:00:00.000Z',
    ...overrides,
  };
}

test('_redactGraph: redacts crossRepoLinks[].rationale carrying a real secret pattern', () => {
  const graph = {
    nodes: [],
    evidence: [],
    crossRepoLinks: [crossRepoLinkFixture({ rationale: `see key ${SECRET_ANTHROPIC_KEY} for context` })],
  };
  const result = _redactGraph(graph);
  const link = result.crossRepoLinks[0];
  assert.doesNotMatch(link.rationale, new RegExp(SECRET_ANTHROPIC_KEY));
  assert.match(link.rationale, /\[REDACTED:anthropic-key\]/);
  // Never mutates the input graph.
  assert.match(graph.crossRepoLinks[0].rationale, new RegExp(SECRET_ANTHROPIC_KEY));
});

test('_redactGraph: redacts crossRepoLinks[].remote.sourceFile/.repository', () => {
  const graph = {
    nodes: [],
    evidence: [],
    crossRepoLinks: [crossRepoLinkFixture({
      remote: { graphId: 'dfg:remote:def:cfg', graphDigest: 'beefdead', nodeId: 'node:source:2', repository: `payments-service (token ${SECRET_ANTHROPIC_KEY})`, sourceFile: `/Users/alice/repos/${SECRET_ANTHROPIC_KEY}/remote-export.json` },
    })],
  };
  const result = _redactGraph(graph);
  const link = result.crossRepoLinks[0];
  assert.doesNotMatch(link.remote.sourceFile, new RegExp(SECRET_ANTHROPIC_KEY));
  assert.doesNotMatch(link.remote.repository, new RegExp(SECRET_ANTHROPIC_KEY));
  assert.match(link.remote.sourceFile, /\[REDACTED:anthropic-key\]/);
  assert.match(link.remote.repository, /\[REDACTED:anthropic-key\]/);
  // Non-redactable fields survive untouched.
  assert.equal(link.remote.nodeId, 'node:source:2');
  assert.equal(link.local.nodeId, 'node:sink:1');
});

test('_redactGraph: crossRepoLinks with no redactable string fields pass through unchanged', () => {
  // The `hasRedactable` false-path: rationale is null and remote carries
  // neither a string sourceFile nor a string repository.
  const graphWithNoRedactableFields = {
    nodes: [], evidence: [],
    crossRepoLinks: [crossRepoLinkFixture({
      rationale: null,
      remote: { graphId: 'dfg:remote:def:cfg', graphDigest: 'beefdead', nodeId: 'node:source:2', repository: undefined, sourceFile: undefined },
    })],
  };
  const result = _redactGraph(graphWithNoRedactableFields);
  assert.deepEqual(result.crossRepoLinks, graphWithNoRedactableFields.crossRepoLinks);
});

test('_redactGraph: missing/non-array crossRepoLinks is passed through as-is', () => {
  assert.equal(_redactGraph({ nodes: [], evidence: [] }).crossRepoLinks, undefined);
  const graphWithNonArray = { nodes: [], evidence: [], crossRepoLinks: null };
  assert.equal(_redactGraph(graphWithNonArray).crossRepoLinks, null);
});

test('_redactGraph: redacts crossRepoLinks as part of a whole-graph pass alongside nodes/evidence/recipientProfiles', () => {
  const graph = {
    nodes: [{ id: 'node:1', destination: { raw: SECRET_AWS_KEY, literalValue: SECRET_AWS_KEY, blockingExpression: null } }],
    evidence: [],
    recipientProfiles: [],
    crossRepoLinks: [crossRepoLinkFixture({ rationale: `secret ${SECRET_ANTHROPIC_KEY}` })],
  };
  const result = _redactGraph(graph);
  assert.doesNotMatch(result.nodes[0].destination.raw, new RegExp(SECRET_AWS_KEY));
  assert.doesNotMatch(result.crossRepoLinks[0].rationale, new RegExp(SECRET_ANTHROPIC_KEY));
});
