// A SYNTHETIC evaluation suite, for exercising the machinery only.
//
// Everything here is authored by the tooling's developers: the code under
// `test/fixtures/evaluation-synthetic/`, the "reviewers", the commits and the
// licence. Every protocol and label it produces carries `synthetic: true`, and
// gates.js refuses to let a synthetic population satisfy any real-code gate. Do
// not read a score computed from this suite as an accuracy figure for the
// engine: three tiny files cannot support one.

import * as path from 'node:path';
import { digestOf } from '../assurance/identity.js';
import { digestTree, targetDigestOf } from './runner.js';
import { freezeProtocol, CORE_LANGUAGES, PREREGISTERED_THRESHOLDS, DEFAULT_MATCHING } from './protocol.js';
import { buildDefectLabel, buildNegativeLabel } from './labels.js';

const SYNTHETIC_LICENSE = 'synthetic-test-fixture';
const SHA = (c) => c.repeat(40);

const TARGETS = [
  { id: 'syn-sqli-js', language: 'javascript', upstream: 'example.invalid/synthetic/sqli-js', preCommit: SHA('1'), postCommit: SHA('2'), split: 'dev' },
  { id: 'syn-cmd-py', language: 'python', upstream: 'example.invalid/synthetic/cmd-py', preCommit: SHA('3'), postCommit: SHA('4'), split: 'dev' },
  { id: 'syn-nearmiss-js', language: 'javascript', upstream: 'example.invalid/synthetic/nearmiss-js', preCommit: SHA('5'), postCommit: null, split: 'sealed' },
];

const reviewers = (tag) => [
  { reviewerId: `synthetic-reviewer-a-${tag}`, verdict: 'confirmed' },
  { reviewerId: `synthetic-reviewer-b-${tag}`, verdict: 'confirmed' },
];
const adjudication = (tag) => ({ status: 'adjudicated', independent: true, reviewers: reviewers(tag) });

/** Directory for one variant of a synthetic target. */
const syntheticTargetDir = (fixturesDir, id, variant) => path.join(fixturesDir, id, variant);

export function buildSyntheticSuite({ fixturesDir, thresholds = { ...PREREGISTERED_THRESHOLDS }, limits } = {}) {
  const targets = TARGETS.map((t) => {
    const pre = digestTree(syntheticTargetDir(fixturesDir, t.id, 'pre'));
    const post = t.postCommit ? digestTree(syntheticTargetDir(fixturesDir, t.id, 'post')) : null;
    const { split, ...rest } = t;
    return { ...rest, pairId: `pair-${t.id}`, advisoryIds: [], license: SYNTHETIC_LICENSE, digest: targetDigestOf({ pre, post }) };
  });
  const splits = { dev: TARGETS.filter((t) => t.split === 'dev').map((t) => t.id).sort(), sealed: TARGETS.filter((t) => t.split === 'sealed').map((t) => t.id).sort() };
  const draft = {
    synthetic: true,
    engine: { version: '0.0.0-synthetic', bundleDigest: digestOf('synthetic-engine') },
    measurement: { commit: SHA('b'), cleanTree: true },
    tools: { node: 'synthetic' },
    models: [],
    datasetLicenses: { [SYNTHETIC_LICENSE]: 'authored for tooling tests; not real-world code' },
    scope: { languages: [...CORE_LANGUAGES], families: ['sql-injection', 'command-injection'] },
    matching: { ...DEFAULT_MATCHING },
    limits: { perTargetTimeoutMs: 120000, spendCeilingUsd: 0, replicates: 3, ...(limits || {}) },
    thresholds,
    targets,
    splits,
    grouping: { method: 'union-find', keys: ['pair', 'upstream', 'advisory', 'commit', 'template'], salt: 'synthetic' },
  };
  const frozen = freezeProtocol(draft);

  const base = (tag) => ({ synthetic: true, adjudication: adjudication(tag), proposedBy: { role: 'worker', id: 'synthetic-proposer' } });
  const defects = [
    buildDefectLabel({
      ...base('d1'), targetId: 'syn-sqli-js', rootCauseId: 'synthetic-root-cause-sqli-js', affected: { commit: SHA('1') },
      language: 'javascript', family: 'sql-injection', cwe: 'CWE-89', location: { file: 'app.js', startLine: 8, endLine: 8 },
      evidence: [{ ref: 'synthetic-review-note-sqli', producer: 'human' }],
    }),
    buildDefectLabel({
      ...base('d2'), targetId: 'syn-cmd-py', rootCauseId: 'synthetic-root-cause-cmd-py', affected: { commit: SHA('3') },
      language: 'python', family: 'command-injection', cwe: 'CWE-78', location: { file: 'tool.py', startLine: 11, endLine: 11 },
      evidence: [{ ref: 'synthetic-review-note-cmd', producer: 'human' }],
    }),
  ];
  const negatives = [
    buildNegativeLabel({
      ...base('n1'), targetId: 'syn-sqli-js', variant: 'post', kind: 'patched', language: 'javascript', family: 'sql-injection',
      scope: { files: ['app.js'] }, pairedDefectId: defects[0].id, rationale: 'synthetic: parameterised query, reviewed as not injectable',
    }),
    buildNegativeLabel({
      ...base('n2'), targetId: 'syn-cmd-py', variant: 'post', kind: 'patched', language: 'python', family: 'command-injection',
      scope: { files: ['tool.py'] }, pairedDefectId: defects[1].id, rationale: 'synthetic: argument list and allow-list check, reviewed as not injectable',
    }),
    buildNegativeLabel({
      ...base('n3'), targetId: 'syn-nearmiss-js', variant: 'pre', kind: 'near-miss', language: 'javascript', family: 'sql-injection',
      scope: { files: ['report.js'] }, rationale: 'synthetic: query assembled from constants only, reviewed as not injectable',
    }),
  ];
  return { protocol: frozen.ok ? frozen.protocol : null, freezeErrors: frozen.errors, draft, defects, negatives, fixturesDir };
}

/** resolveTarget for the runner over the synthetic fixtures. */
export const syntheticResolver = (fixturesDir) => (target, variant) => ({ dir: syntheticTargetDir(fixturesDir, target.id, variant) });
