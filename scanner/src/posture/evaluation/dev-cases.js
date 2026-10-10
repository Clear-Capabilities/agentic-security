// A DEVELOPMENT case suite for engine work (QA-005.AC03, QA-006), scored by the same frozen policy as everything else.
//
// `test/fixtures/engine-mechanisms/` holds small projects, each a vulnerable `pre/` tree and a patched `post/` tree, plus a `cases.json`
// naming the reviewed location of each defect. This module turns them into a protocol, labels and a resolver so that
// `runEvaluation` + `scoreRun` (same matching policy, same end-to-end rules) can answer "which of these defects does the engine
// recover, and which patched trees stay silent" for ANY engine checkout. That makes a before/after comparison a measurement and not
// an anecdote: run it once per engine revision and compare.
//
// What this is NOT: an independent population. The projects and the labels were written by the people who wrote the fix, so every
// label is flagged `synthetic: true` and gates.js will never count them toward a real-code minimum. They exist to show that a
// change recovers the mechanism it was made for, and that its patched twin stays quiet. They say nothing about real-code accuracy.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { digestOf } from '../assurance/identity.js';
import { digestTree, targetDigestOf } from './runner.js';
import { freezeProtocol, CORE_LANGUAGES, PREREGISTERED_THRESHOLDS, DEFAULT_MATCHING } from './protocol.js';
import { buildDefectLabel, buildNegativeLabel } from './labels.js';

const LICENSE = 'development-fixture';
const hex = (n) => n.toString(16).padStart(40, '0');
const adjudication = (tag) => ({ status: 'adjudicated', independent: true, reviewers: [{ reviewerId: `dev-reviewer-a-${tag}`, verdict: 'confirmed' }, { reviewerId: `dev-reviewer-b-${tag}`, verdict: 'confirmed' }] });

function readDevCases(fixturesDir) {
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, 'cases.json'), 'utf8')).cases;
}

/** @returns {{protocol, defects, negatives, freezeErrors}} everything flagged synthetic; every target in the development split. */
export function buildDevSuite({ fixturesDir, cases = readDevCases(fixturesDir) }) {
  const targets = cases.map((c, i) => ({
    id: c.id, language: c.language, upstream: `example.invalid/dev/${c.id}`, pairId: `pair-${c.id}`, preCommit: hex(2 * i + 1), postCommit: hex(2 * i + 2), advisoryIds: [], license: LICENSE,
    digest: targetDigestOf({ pre: digestTree(path.join(fixturesDir, c.id, 'pre')), post: digestTree(path.join(fixturesDir, c.id, 'post')) }),
  }));
  const draft = {
    synthetic: true,
    engine: { version: '0.0.0-dev-cases', bundleDigest: digestOf('dev-cases-engine') },
    measurement: { commit: hex(0xabc), cleanTree: true },
    tools: { node: 'dev' }, models: [], datasetLicenses: { [LICENSE]: 'authored for engine development; not real-world code' },
    scope: { languages: [...CORE_LANGUAGES], families: [...new Set(cases.map((c) => c.family))].sort() },
    matching: { ...DEFAULT_MATCHING },
    limits: { perTargetTimeoutMs: 120000, spendCeilingUsd: 0, replicates: 3 },
    thresholds: { ...PREREGISTERED_THRESHOLDS },
    targets, splits: { dev: targets.map((t) => t.id).sort(), sealed: [] },
    grouping: { method: 'union-find', keys: ['pair', 'upstream', 'advisory', 'commit', 'template'], salt: 'dev-cases' },
  };
  const frozen = freezeProtocol(draft);
  const defects = []; const negatives = [];
  cases.forEach((c, i) => {
    const base = (tag) => ({ synthetic: true, adjudication: adjudication(`${tag}${i}`), proposedBy: { role: 'worker', id: 'dev-proposer' } });
    const d = buildDefectLabel({
      ...base('d'), targetId: c.id, rootCauseId: `development-root-cause-${c.id}`, affected: { commit: hex(2 * i + 1) },
      language: c.language, family: c.family, cwe: c.cwe, location: { file: c.file, startLine: c.startLine, endLine: c.endLine },
      evidence: [{ ref: `development-review-note-${c.id}`, producer: 'human' }],
    });
    defects.push(d);
    negatives.push(buildNegativeLabel({
      ...base('n'), targetId: c.id, variant: 'post', kind: 'patched', language: c.language, family: c.family,
      scope: { files: [c.file] }, pairedDefectId: d.id, rationale: `development: the patched ${c.id} was reviewed as not exploitable`,
    }));
  });
  return { protocol: frozen.ok ? frozen.protocol : null, freezeErrors: frozen.errors, defects, negatives, cases };
}

/** resolveTarget for the runner over the dev fixtures. */
export const devResolver = (fixturesDir) => (target, variant) => ({ dir: path.join(fixturesDir, target.id, variant) });
