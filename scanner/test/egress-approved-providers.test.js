// Approved-provider metadata for regulated profiles (assurance-hardening
// PRD FR-607). "Regulated profiles can require approved contractual and
// retention attributes" — a no-op unless an operator opts in via
// egress-policy.yml's regulatedProfile.requireApprovedProviders, same
// restricts-nothing-until-configured default every other evaluateEgress
// dimension follows.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluateEgress, _internals } from '../src/egress/policy.js';

function mkPolicyDir(yamlBody) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-r607-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'egress-policy.yml'), yamlBody);
  return dir;
}

const ANTHROPIC_ENDPOINT = 'https://api.anthropic.com/v1/messages';

test('evaluateEgress: no regulatedProfile configured — allowed, unaffected, no approvedProviderMetadata on the decision', () => {
  const dir = mkPolicyDir('mode: allow\n');
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, true);
    assert.equal('approvedProviderMetadata' in r, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: requireApprovedProviders set, no approvedProviders entry for this provider -> denied', () => {
  const dir = mkPolicyDir('regulatedProfile:\n  requireApprovedProviders: true\n');
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, false);
    assert.equal(r.decision, 'deny');
    assert.match(r.reason, /has no approved-provider metadata configured/);
    assert.match(r.reason, /anthropic/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: an approvedProviders entry missing one required attribute -> denied, names the specific missing attribute', () => {
  const dir = mkPolicyDir([
    'regulatedProfile:',
    '  requireApprovedProviders: true',
    'approvedProviders:',
    '  anthropic:',
    '    dpaStatus: signed',
    '    retentionPolicy: zero-retention',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, false);
    assert.match(r.reason, /missing required approved-provider attribute\(s\): baaStatus/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: an approvedProviders entry with all default-required attributes present -> allowed, metadata attached to the decision', () => {
  const dir = mkPolicyDir([
    'regulatedProfile:',
    '  requireApprovedProviders: true',
    'approvedProviders:',
    '  anthropic:',
    '    dpaStatus: signed',
    '    baaStatus: signed',
    '    retentionPolicy: zero-retention',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, true);
    assert.deepEqual(r.approvedProviderMetadata, { dpaStatus: 'signed', baaStatus: 'signed', retentionPolicy: 'zero-retention' });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: a custom requiredAttributes list narrows what is checked — an attribute outside the custom list is not required', () => {
  const dir = mkPolicyDir([
    'regulatedProfile:',
    '  requireApprovedProviders: true',
    '  requiredAttributes: [dpaStatus]',
    'approvedProviders:',
    '  anthropic:',
    '    dpaStatus: signed',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, true, 'baaStatus/retentionPolicy are not in the custom requiredAttributes list, so their absence must not block');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: "none" and "not_signed" are treated as absent, not satisfied — an operator cannot accidentally satisfy the gate with a placeholder', () => {
  const dir = mkPolicyDir([
    'regulatedProfile:',
    '  requireApprovedProviders: true',
    'approvedProviders:',
    '  anthropic:',
    '    dpaStatus: none',
    '    baaStatus: not_signed',
    '    retentionPolicy: zero-retention',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, false);
    assert.match(r.reason, /dpaStatus/);
    assert.match(r.reason, /baaStatus/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: requireApprovedProviders is false (or unset) inside regulatedProfile -> the whole check is a no-op', () => {
  const dir = mkPolicyDir([
    'regulatedProfile:',
    '  requireApprovedProviders: false',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, true);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: mode:deny still takes precedence over a satisfied approved-provider entry — approval never overrides an unrelated denial', () => {
  const dir = mkPolicyDir([
    'mode: deny',
    'regulatedProfile:',
    '  requireApprovedProviders: true',
    'approvedProviders:',
    '  anthropic:',
    '    dpaStatus: signed',
    '    baaStatus: signed',
    '    retentionPolicy: zero-retention',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: ANTHROPIC_ENDPOINT });
    assert.equal(r.allowed, false);
    assert.match(r.reason, /egress mode is 'deny'/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('evaluateEgress: a DIFFERENT provider than the one approved is still denied under a regulated profile', () => {
  const dir = mkPolicyDir([
    'regulatedProfile:',
    '  requireApprovedProviders: true',
    'approvedProviders:',
    '  anthropic:',
    '    dpaStatus: signed',
    '    baaStatus: signed',
    '    retentionPolicy: zero-retention',
  ].join('\n'));
  try {
    const r = evaluateEgress({ scanRoot: dir, purpose: 'x', endpoint: 'https://api.openai.com/v1/chat/completions' });
    assert.equal(r.allowed, false);
    assert.match(r.reason, /openai/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('DEFAULT_REQUIRED_PROVIDER_ATTRIBUTES is exposed via _internals for anyone building an approvedProviders config template', () => {
  assert.deepEqual(_internals.DEFAULT_REQUIRED_PROVIDER_ATTRIBUTES, ['dpaStatus', 'baaStatus', 'retentionPolicy']);
});
