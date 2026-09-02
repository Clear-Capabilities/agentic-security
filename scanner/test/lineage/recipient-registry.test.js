import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  TECHNICAL_PROVIDER_CATALOG,
  RECIPIENT_CONFIG_FILENAME,
  resolveTechnicalProvider,
  loadRecipientConfig,
  buildRecipientProfile,
} from '../../src/lineage/recipient-registry.js';
import { validateRecipientProfile } from '../../src/lineage/recipient-profile.js';

// =====================================================================
// resolveTechnicalProvider
// =====================================================================

test('resolveTechnicalProvider: a real framework: "anthropic" match', () => {
  const result = resolveTechnicalProvider({ framework: 'anthropic' });
  assert.ok(result, 'expected a match for framework "anthropic"');
  assert.equal(result.provider, 'anthropic');
  assert.equal(typeof result.serviceType, 'string');
});

test('resolveTechnicalProvider: a real framework: "openai" match', () => {
  const result = resolveTechnicalProvider({ framework: 'openai' });
  assert.ok(result, 'expected a match for framework "openai"');
  assert.equal(result.provider, 'openai');
});

test('resolveTechnicalProvider: a real hostname-pattern match against a literalValue', () => {
  const result = resolveTechnicalProvider({ literalValue: 'https://api.anthropic.com/v1/messages' });
  assert.ok(result, 'expected a hostname match for api.anthropic.com');
  assert.equal(result.provider, 'anthropic');
});

// fix-round-1, I4: hostname matching must test the BARE HOSTNAME extracted
// from literalValue, never the raw literal string — testing the raw
// string let an attacker-controlled destination absorb a real company's
// declared legal/DPA facts whenever "anthropic.com" appeared anywhere in
// the URL (a path segment, a query value), not just as the actual host.
test('resolveTechnicalProvider: I4 — a lookalike path segment does NOT match the real hostname pattern', () => {
  const result = resolveTechnicalProvider({ literalValue: 'https://attacker.io/anthropic.com' });
  assert.equal(result, null, 'expected no match — "anthropic.com" here is a PATH segment on attacker.io, not the host');
});

test('resolveTechnicalProvider: I4 — a lookalike query value does NOT match the real hostname pattern', () => {
  const result = resolveTechnicalProvider({ literalValue: 'https://attacker.io/proxy?to=https://api.anthropic.com' });
  assert.equal(result, null, 'expected no match — "api.anthropic.com" here is a QUERY VALUE on attacker.io, not the host');
});

test('resolveTechnicalProvider: I4 — the legitimate hostname still resolves correctly after the fix', () => {
  const result = resolveTechnicalProvider({ literalValue: 'https://api.anthropic.com/v1/messages' });
  assert.ok(result, 'expected the real Anthropic hostname to still match');
  assert.equal(result.provider, 'anthropic');
});

test('resolveTechnicalProvider: no match returns null, never throws', () => {
  assert.equal(resolveTechnicalProvider({ framework: 'express' }), null);
  assert.equal(resolveTechnicalProvider({ literalValue: 'https://example.com/webhook' }), null);
  assert.doesNotThrow(() => resolveTechnicalProvider());
  assert.doesNotThrow(() => resolveTechnicalProvider(null));
  assert.doesNotThrow(() => resolveTechnicalProvider({}));
  assert.doesNotThrow(() => resolveTechnicalProvider({ framework: 42, literalValue: {} }));
  assert.equal(resolveTechnicalProvider(), null);
  assert.equal(resolveTechnicalProvider(null), null);
});

test('resolveTechnicalProvider: framework takes precedence when both are provided and only one matches', () => {
  const result = resolveTechnicalProvider({ framework: 'openai', literalValue: 'https://example.com' });
  assert.ok(result);
  assert.equal(result.provider, 'openai');
});

test('TECHNICAL_PROVIDER_CATALOG is a well-formed array of {provider, serviceType, hostnamePatterns, frameworkNames}', () => {
  assert.ok(Array.isArray(TECHNICAL_PROVIDER_CATALOG));
  assert.ok(TECHNICAL_PROVIDER_CATALOG.length > 0);
  for (const entry of TECHNICAL_PROVIDER_CATALOG) {
    assert.equal(typeof entry.provider, 'string');
    assert.ok(entry.provider.length > 0);
    assert.equal(typeof entry.serviceType, 'string');
    assert.ok(entry.serviceType.length > 0);
    assert.ok(Array.isArray(entry.hostnamePatterns));
    assert.ok(Array.isArray(entry.frameworkNames));
    for (const p of entry.hostnamePatterns) assert.equal(typeof p, 'string');
    for (const f of entry.frameworkNames) assert.equal(typeof f, 'string');
    // Every hostnamePatterns entry must actually compile as a regex.
    for (const p of entry.hostnamePatterns) assert.doesNotThrow(() => new RegExp(p, 'i'));
  }
});

test('TECHNICAL_PROVIDER_CATALOG: aws-sdk is deliberately never used as a frameworkNames match (ambiguous between S3 and SQS)', () => {
  for (const entry of TECHNICAL_PROVIDER_CATALOG) {
    assert.ok(!entry.frameworkNames.includes('aws-sdk'), `entry "${entry.provider}" must not key on the ambiguous "aws-sdk" framework value`);
  }
});

test('resolveTechnicalProvider: real S3 hostname resolves via hostnamePatterns only', () => {
  const result = resolveTechnicalProvider({ literalValue: 'https://my-bucket.s3.amazonaws.com/key' });
  assert.ok(result, 'expected a hostname match for an S3 bucket URL');
  assert.match(result.serviceType, /storage/i);
});

test('resolveTechnicalProvider: real Google Cloud Pub/Sub framework match', () => {
  const result = resolveTechnicalProvider({ framework: 'pubsub' });
  assert.ok(result, 'expected a match for framework "pubsub"');
  assert.match(result.provider.toLowerCase(), /pub\/?sub|google/);
});

// =====================================================================
// loadRecipientConfig — mirrors drift-policy.js's loadDriftPolicies
// test shape exactly.
// =====================================================================

function _tmpFile(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recipient-registry-test-'));
  const file = path.join(dir, RECIPIENT_CONFIG_FILENAME);
  if (content !== undefined) fs.writeFileSync(file, content, 'utf8');
  return file;
}

test('loadRecipientConfig: missing file returns {recipients: {}}, never throws', () => {
  const file = _tmpFile();
  assert.doesNotThrow(() => loadRecipientConfig(file));
  assert.deepEqual(loadRecipientConfig(file), { recipients: {} });
});

test('loadRecipientConfig: no path at all returns {recipients: {}}', () => {
  assert.deepEqual(loadRecipientConfig(null), { recipients: {} });
  assert.deepEqual(loadRecipientConfig(undefined), { recipients: {} });
  assert.deepEqual(loadRecipientConfig(''), { recipients: {} });
});

test('loadRecipientConfig: malformed JSON degrades honestly to {recipients: {}} and warns', () => {
  const file = _tmpFile('{not valid json');
  const origError = console.error;
  let warned = false;
  console.error = () => { warned = true; };
  try {
    const result = loadRecipientConfig(file);
    assert.deepEqual(result, { recipients: {} });
  } finally {
    console.error = origError;
  }
  assert.equal(warned, true, 'expected a warning to be logged for malformed JSON');
});

test('loadRecipientConfig: JSON with no "recipients" object degrades honestly and warns', () => {
  const file = _tmpFile(JSON.stringify({ notRecipients: [] }));
  const origError = console.error;
  let warned = false;
  console.error = () => { warned = true; };
  try {
    const result = loadRecipientConfig(file);
    assert.deepEqual(result, { recipients: {} });
  } finally {
    console.error = origError;
  }
  assert.equal(warned, true);
});

test('loadRecipientConfig: a malformed individual recipient entry (bad enum value) is skipped, others still load', () => {
  const file = _tmpFile(JSON.stringify({
    recipients: {
      'good.example.com': { legalEntity: 'Good Corp', processorRole: 'processor' },
      'bad.example.com': { legalEntity: 'Bad Corp', processorRole: 'not-a-real-role' },
    },
  }));
  const origError = console.error;
  let warned = false;
  console.error = () => { warned = true; };
  let result;
  try {
    result = loadRecipientConfig(file);
  } finally {
    console.error = origError;
  }
  assert.ok(result.recipients['good.example.com'], 'the well-formed entry must still load');
  assert.equal(result.recipients['bad.example.com'], undefined, 'the malformed entry must be skipped entirely');
  assert.equal(warned, true, 'expected a warning naming the skipped-entry count');
});

test('loadRecipientConfig: a malformed dpaStatus is rejected the same way', () => {
  const file = _tmpFile(JSON.stringify({
    recipients: { 'x.example.com': { dpaStatus: 'maybe' } },
  }));
  const origError = console.error;
  console.error = () => {};
  let result;
  try {
    result = loadRecipientConfig(file);
  } finally {
    console.error = origError;
  }
  assert.equal(result.recipients['x.example.com'], undefined);
});

test('loadRecipientConfig: a malformed processingCountries entry (not ISO-3166-alpha-2-shaped) is rejected', () => {
  const file = _tmpFile(JSON.stringify({
    recipients: { 'x.example.com': { processingCountries: ['usa'] } },
  }));
  const origError = console.error;
  console.error = () => {};
  let result;
  try {
    result = loadRecipientConfig(file);
  } finally {
    console.error = origError;
  }
  assert.equal(result.recipients['x.example.com'], undefined);
});

test('loadRecipientConfig: a well-formed file round-trips exactly', () => {
  const entry = {
    legalEntity: 'Anthropic PBC',
    processorRole: 'processor',
    subprocessorChain: ['aws'],
    processingCountries: ['US'],
    dataResidencyCommitment: 'US-only',
    dpaStatus: 'in_place',
    transferMechanism: 'SCCs',
    transferImpactReviewStatus: 'completed',
    retentionCommitment: '30 days',
    confidence: 'high',
    owner: 'privacy-team',
    reviewDate: '2026-09-01',
    conflicts: [],
    expiration: null,
  };
  const file = _tmpFile(JSON.stringify({ recipients: { 'anthropic': entry } }));
  const result = loadRecipientConfig(file);
  assert.deepEqual(result, { recipients: { anthropic: entry } });
});

// fix-round-1, M7: servicePurpose/observedRegion are real RECIPIENT_FACT_FIELDS
// (recipient-profile.js) and are real fields buildRecipientProfile's own
// `facts` object initializes, but were missing from
// _RECIPIENT_CONFIG_FACT_FIELDS/_isValidRecipientConfigEntry — an operator
// declaring either in recipient-profiles.json had it silently ignored
// (never validated, never copied into the built profile).
test('loadRecipientConfig: servicePurpose/observedRegion round-trip through validation, not silently dropped', () => {
  const entry = { servicePurpose: 'customer support ticketing', observedRegion: 'us-east-1' };
  const file = _tmpFile(JSON.stringify({ recipients: { anthropic: entry } }));
  const result = loadRecipientConfig(file);
  assert.deepEqual(result, { recipients: { anthropic: entry } });
});

test('loadRecipientConfig: a malformed servicePurpose/observedRegion (non-string) is rejected like every other declared field', () => {
  const file1 = _tmpFile(JSON.stringify({ recipients: { anthropic: { servicePurpose: 42 } } }));
  const file2 = _tmpFile(JSON.stringify({ recipients: { anthropic: { observedRegion: 42 } } }));
  assert.deepEqual(loadRecipientConfig(file1), { recipients: {} });
  assert.deepEqual(loadRecipientConfig(file2), { recipients: {} });
});

test('loadRecipientConfig: an entry that is not a plain object is skipped', () => {
  const file = _tmpFile(JSON.stringify({
    recipients: { 'good.example.com': { legalEntity: 'Good Corp' }, 'bad-array': ['x'], 'bad-null': null },
  }));
  const origError = console.error;
  console.error = () => {};
  let result;
  try {
    result = loadRecipientConfig(file);
  } finally {
    console.error = origError;
  }
  assert.ok(result.recipients['good.example.com']);
  assert.equal(result.recipients['bad-array'], undefined);
  assert.equal(result.recipients['bad-null'], undefined);
});

// =====================================================================
// buildRecipientProfile
// =====================================================================

const GRAPH = { graphId: 'dfg:test-repo:abc123:default', nodes: [], edges: [], flows: [], dataElements: [] };

function _site(overrides = {}) {
  return {
    file: 'src/handler.js',
    qid: 'src/handler.js#handler',
    nodeId: 'n1',
    line: 12,
    calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'anthropic' }, prop: 'create' },
    args: [],
    entry: { id: 'js-anthropic-messages-create', framework: 'anthropic' },
    decision: { kind: 'sink', category: 'ai-model-provider', coverageStatus: 'modeled', externality: 'external', reason: 'x' },
    ambiguity: null,
    ...overrides,
  };
}

test('buildRecipientProfile: catalog match + operator config match for the SAME recipientKey coexist correctly', () => {
  const site = _site({ destination: { resolutionStatus: 'literal', raw: "'https://api.anthropic.com'", literalValue: 'https://api.anthropic.com', blockingExpression: null } });
  const recipientConfig = {
    recipients: {
      anthropic: {
        legalEntity: 'Anthropic PBC',
        processorRole: 'processor',
        dpaStatus: 'in_place',
        processingCountries: ['US'],
      },
    },
  };
  const profile = buildRecipientProfile(site, GRAPH, { recipientConfig });
  assert.ok(profile, 'expected a real profile');

  assert.equal(profile.provider, 'anthropic');
  assert.equal(profile.fieldEvidence.provider.factType, 'code_inferred');
  assert.equal(profile.fieldEvidence.serviceType.factType, 'code_inferred');
  assert.equal(profile.technicalEndpoint, 'https://api.anthropic.com');
  assert.equal(profile.fieldEvidence.technicalEndpoint.factType, 'code_inferred');

  assert.equal(profile.legalEntity, 'Anthropic PBC');
  assert.equal(profile.fieldEvidence.legalEntity.factType, 'declared');
  assert.equal(profile.processorRole, 'processor');
  assert.equal(profile.fieldEvidence.processorRole.factType, 'declared');
  assert.equal(profile.dpaStatus, 'in_place');
  assert.deepEqual(profile.processingCountries, ['US']);

  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `expected a valid RecipientProfile, got: ${JSON.stringify(errors)}`);
});

test('buildRecipientProfile: catalog-only case leaves declared fields null/absent with no fieldEvidence entries for them', () => {
  const site = _site();
  const profile = buildRecipientProfile(site, GRAPH, {});
  assert.ok(profile);
  assert.equal(profile.provider, 'anthropic');
  assert.equal(profile.legalEntity, null);
  assert.equal(profile.fieldEvidence.legalEntity, undefined);
  assert.equal(profile.dpaStatus, null);
  assert.equal(profile.fieldEvidence.dpaStatus, undefined);
  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `expected a valid RecipientProfile, got: ${JSON.stringify(errors)}`);
});

test('buildRecipientProfile: operator-config-only case (no catalog match) still resolves a recipientKey from a hostname', () => {
  const site = _site({
    entry: { id: 'privacy-js-fetch', framework: 'browser' }, // not in TECHNICAL_PROVIDER_CATALOG
    destination: { resolutionStatus: 'literal', raw: "'https://vendor.example.com/api'", literalValue: 'https://vendor.example.com/api', blockingExpression: null },
  });
  const recipientConfig = {
    recipients: {
      'vendor.example.com': { legalEntity: 'Vendor Example Inc', processorRole: 'processor' },
    },
  };
  const profile = buildRecipientProfile(site, GRAPH, { recipientConfig });
  assert.ok(profile);
  assert.equal(profile.recipientKey, 'vendor.example.com');
  assert.equal(profile.provider, null);
  assert.equal(profile.serviceType, null);
  assert.equal(profile.fieldEvidence.provider, undefined);
  // technicalEndpoint is only ever populated inside the catalog-match
  // branch (per the brief) — with no catalog match it stays null, even
  // though a literalValue was available.
  assert.equal(profile.technicalEndpoint, null, 'technicalEndpoint is only ever populated from a real catalog match, per spec');
  assert.equal(profile.legalEntity, 'Vendor Example Inc');
  assert.equal(profile.fieldEvidence.legalEntity.factType, 'declared');
  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `expected a valid RecipientProfile, got: ${JSON.stringify(errors)}`);
});

test('buildRecipientProfile: a genuinely-nothing case returns null', () => {
  const site = _site({
    entry: { id: 'js-fetch-json', framework: 'browser' },
    destination: { resolutionStatus: 'dynamic', raw: 'url', literalValue: null, blockingExpression: 'url' },
  });
  const profile = buildRecipientProfile(site, GRAPH, {});
  assert.equal(profile, null);
});

test('buildRecipientProfile: no destination at all and no catalog/config match returns null', () => {
  const site = _site({ entry: { id: 'privacy-js-console-log', framework: 'node' } });
  const profile = buildRecipientProfile(site, GRAPH, {});
  assert.equal(profile, null);
});

test('buildRecipientProfile: malformed/missing site never throws, returns null', () => {
  assert.doesNotThrow(() => buildRecipientProfile(null, GRAPH, {}));
  assert.equal(buildRecipientProfile(null, GRAPH, {}), null);
  assert.equal(buildRecipientProfile(undefined, GRAPH, {}), null);
  assert.equal(buildRecipientProfile({}, GRAPH, {}), null);
});

test('buildRecipientProfile: the "framework" field is read from site.entry.framework, never site.framework', () => {
  const site = _site({ framework: 'openai', entry: { id: 'js-anthropic-messages-create', framework: 'anthropic' } });
  const profile = buildRecipientProfile(site, GRAPH, {});
  assert.ok(profile);
  assert.equal(profile.provider, 'anthropic', 'must resolve via site.entry.framework, not a stray top-level site.framework');
});

test('buildRecipientProfile: id/graphId/graphDigest are populated and the record validates end to end', () => {
  const site = _site();
  const profile = buildRecipientProfile(site, GRAPH, {});
  assert.ok(profile);
  assert.match(profile.id, /^recipient:[0-9a-f]{12}$/);
  assert.equal(profile.graphId, GRAPH.graphId);
  assert.equal(typeof profile.graphDigest, 'string');
  assert.ok(profile.graphDigest.length > 0);
});

test('buildRecipientProfile: works with no graph at all (graphId/graphDigest fall back honestly)', () => {
  const site = _site();
  const profile = buildRecipientProfile(site, null, {});
  assert.ok(profile);
  assert.equal(profile.graphId, '(no graph)');
  assert.equal(profile.graphDigest, '(no graph)');
  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `expected a valid RecipientProfile even with no graph, got: ${JSON.stringify(errors)}`);
});

test('buildRecipientProfile: record-level metadata (confidence/owner/reviewDate/conflicts/expiration) comes from operator config with no fieldEvidence needed', () => {
  const site = _site();
  const recipientConfig = {
    recipients: {
      anthropic: { confidence: 'medium', owner: 'privacy-team', reviewDate: '2026-09-01', conflicts: ['legacy-record'], expiration: '2027-01-01' },
    },
  };
  const profile = buildRecipientProfile(site, GRAPH, { recipientConfig });
  assert.ok(profile);
  assert.equal(profile.confidence, 'medium');
  assert.equal(profile.owner, 'privacy-team');
  assert.equal(profile.reviewDate, '2026-09-01');
  assert.deepEqual(profile.conflicts, ['legacy-record']);
  assert.equal(profile.expiration, '2027-01-01');
  assert.equal(profile.fieldEvidence.confidence, undefined, 'record-level metadata must never get a fieldEvidence entry');
  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `got: ${JSON.stringify(errors)}`);
});

test('buildRecipientProfile: opts.recipientConfig omitted entirely still works (catalog-only)', () => {
  const site = _site();
  const profile = buildRecipientProfile(site, GRAPH, undefined);
  assert.ok(profile);
  assert.equal(profile.provider, 'anthropic');
});

// fix-round-1, M7: a real end-to-end proof that operator-declared
// servicePurpose/observedRegion land in the built profile with a
// {factType: 'declared', ...} fieldEvidence entry — before the fix these
// were silently dropped by _RECIPIENT_CONFIG_FACT_FIELDS/
// _isValidRecipientConfigEntry never mentioning either field.
test('buildRecipientProfile: M7 — servicePurpose/observedRegion land in the built profile with declared fieldEvidence', () => {
  const site = _site();
  const recipientConfig = {
    recipients: {
      anthropic: { servicePurpose: 'clinical note summarization', observedRegion: 'us-east-1' },
    },
  };
  const profile = buildRecipientProfile(site, GRAPH, { recipientConfig });
  assert.ok(profile);
  assert.equal(profile.servicePurpose, 'clinical note summarization');
  assert.equal(profile.observedRegion, 'us-east-1');
  assert.deepEqual(profile.fieldEvidence.servicePurpose, { factType: 'declared', source: RECIPIENT_CONFIG_FILENAME });
  assert.deepEqual(profile.fieldEvidence.observedRegion, { factType: 'declared', source: RECIPIENT_CONFIG_FILENAME });
  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `expected a valid RecipientProfile, got: ${JSON.stringify(errors)}`);
});

// =====================================================================
// Boundary / structural checks
// =====================================================================

test('boundary: recipient-registry.js imports node:fs, ids.js, export-json.js, and recipient-profile.js — no dataflow/engine.js, no dataflow/summaries.js', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/recipient-registry.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.ok(!specifiers.includes('../dataflow/engine.js'));
  assert.ok(!specifiers.includes('../dataflow/summaries.js'));
});

test('RECIPIENT_CONFIG_FILENAME is the literal "recipient-profiles.json"', () => {
  assert.equal(RECIPIENT_CONFIG_FILENAME, 'recipient-profiles.json');
});
