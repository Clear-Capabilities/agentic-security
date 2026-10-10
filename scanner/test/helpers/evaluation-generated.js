// GENERATED populations for exercising evaluation ARITHMETIC (reports, intervals, gates). Not a test file.
//
// Nothing here describes real code. The "targets" are names, the labels were never adjudicated by anyone, and the "runs" are
// records built in memory from a rule the test chooses (which targets are detected, which negatives raise a false alarm). They exist
// so a test can feed known counts through the real scoring, reporting and gate code and check what comes out. Nothing is written to
// disk. A population built with `flagSynthetic: false` is NOT evidence about the engine; it is a way to reach the arithmetic.

import { freezeProtocol, CORE_LANGUAGES, PREREGISTERED_THRESHOLDS, DEFAULT_MATCHING } from '../../src/posture/evaluation/protocol.js';
import { buildDefectLabel, buildNegativeLabel } from '../../src/posture/evaluation/labels.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { scoreRun } from '../../src/posture/evaluation/score.js';

export const FAMILY = 'sql-injection';

/** `per` sealed targets per core language (a positive label and a patched negative each), all generated. `groupSize` targets share a pair id, so they form one resampling group. */
export function generatedPopulation({ per = 100, flagSynthetic = false, thresholds = { ...PREREGISTERED_THRESHOLDS }, prefix = 'gen', groupSize = 1 } = {}) {
  const targets = []; const defects = []; const negatives = [];
  const adj = (tag) => ({ status: 'adjudicated', independent: true, reviewers: [{ reviewerId: `gen-a-${tag}`, verdict: 'confirmed' }, { reviewerId: `gen-b-${tag}`, verdict: 'confirmed' }] });
  const common = (tag) => ({ synthetic: flagSynthetic, adjudication: adj(tag), proposedBy: { role: 'worker', id: 'gen-proposer' } });
  let n = 0;
  for (const lang of CORE_LANGUAGES) {
    for (let i = 0; i < per; i++, n++) {
      const id = `${prefix}-${lang}-${i}`;
      const hex = (n + 1 + (prefix === 'gen' ? 0 : 100000)).toString(16).padStart(40, '0');
      targets.push({ id, language: lang, license: 'gen-license', upstream: `example.invalid/${id}`, pairId: `pair-${prefix}-${lang}-${Math.floor(i / groupSize)}`, preCommit: hex, postCommit: (n + 1 + (prefix === 'gen' ? 900000 : 1000000)).toString(16).padStart(40, '0'), advisoryIds: [], digest: digestOf(id) });
      const d = buildDefectLabel({ ...common(`d${n}`), targetId: id, rootCauseId: `root-${id}`, affected: { commit: hex }, language: lang, family: FAMILY, cwe: 'CWE-89', location: { file: 'a.x', startLine: 1, endLine: 1 }, evidence: [{ ref: `ref-${id}`, producer: 'human' }] });
      defects.push(d);
      negatives.push(buildNegativeLabel({ ...common(`n${n}`), targetId: id, variant: 'post', kind: 'patched', language: lang, family: FAMILY, scope: { files: ['a.x'] }, pairedDefectId: d.id, rationale: `gen-rationale-${id}` }));
    }
  }
  targets.push({ id: 'gen-dev-sink', language: 'rust', license: 'gen-license', upstream: 'example.invalid/gen-dev-sink', pairId: 'pair-gen-dev-sink', preCommit: 'e'.repeat(40), postCommit: 'd'.repeat(40), advisoryIds: [], digest: digestOf('gen-dev-sink') });
  const ids = targets.map((t) => t.id).filter((id) => id !== 'gen-dev-sink').sort();
  const draft = {
    synthetic: false,
    engine: { version: '0.0.0-gen', bundleDigest: digestOf('gen-engine') },
    measurement: { commit: 'a'.repeat(40), cleanTree: true },
    tools: { node: 'gen' }, models: [], datasetLicenses: { 'gen-license': 'generated' },
    scope: { languages: [...CORE_LANGUAGES], families: [FAMILY] }, matching: { ...DEFAULT_MATCHING },
    limits: { perTargetTimeoutMs: 1000, spendCeilingUsd: 0, replicates: 3 }, thresholds,
    targets, splits: { dev: ['gen-dev-sink'], sealed: ids },
  };
  const f = freezeProtocol(draft);
  if (!f.ok) throw new Error(`generated protocol failed to freeze: ${JSON.stringify(f.errors.slice(0, 3))}`);
  return { protocol: f.protocol, defects, negatives, draft };
}

const hit = () => ({ id: 'gen-finding', file: 'a.x', line: 1, family: FAMILY, cwe: 'CWE-89', severity: 'high', parser: 'IR-TAINT', vuln: 'SQL Injection' });

/**
 * A run record over a generated population. `detect(target)` says whether the pre variant yields the finding; `falseAlarm(target)`
 * says whether the post variant does; `status(target, variant)` may return a non-completed status; `extraAlerts(target, variant)` adds
 * further alerts on adjacent lines of the same flaw. Everything defaults to a perfect engine.
 */
export function generatedRun(protocol, { detect = () => true, falseAlarm = () => false, status = () => 'completed', extraAlerts = () => 0, split = 'sealed', quarantine = () => false } = {}) {
  const wanted = new Set(protocol.splits[split]);
  const outcomes = [];
  for (const t of protocol.targets.filter((x) => wanted.has(x.id))) {
    for (const variant of ['pre', 'post']) {
      const st = quarantine(t, variant) ? 'quarantined' : status(t, variant);
      if (st !== 'completed') { outcomes.push({ targetId: t.id, variant, status: st, findings: [], durationMs: 0, costUsd: null, costSource: 'unmeasured', failureReason: st === 'quarantined' ? 'leakage control: answer-key-file@expected.json' : `${st}`, inputHash: null, outputHash: null, cached: false }); continue; }
      const findings = [];
      if (variant === 'pre' && detect(t)) findings.push(hit());
      if (variant === 'post' && falseAlarm(t)) findings.push(hit());
      for (let i = 0; i < extraAlerts(t, variant); i++) findings.push({ ...hit(), id: `gen-dup-${i}`, line: 2 + i });
      outcomes.push({ targetId: t.id, variant, status: 'completed', findings, durationMs: 1, costUsd: null, costSource: 'unmeasured', failureReason: null, inputHash: 'x', outputHash: 'y', cached: false });
    }
  }
  const totals = Object.fromEntries(['completed', 'timeout', 'error', 'unavailable', 'quarantined'].map((s) => [s, outcomes.filter((o) => o.status === s).length]));
  return { runId: 'erun:generated', protocolHash: protocol.protocolHash, split, outcomes, totals, config: { layer: 'deep-taint' } };
}

export function generatedScore(pop, runOpts = {}) {
  const run = generatedRun(pop.protocol, runOpts);
  return { run, score: scoreRun({ run, protocol: pop.protocol, defects: pop.defects, negatives: pop.negatives }) };
}

/** Deterministic pseudo-random choice in [0,1) from a target id, so a "detect 90%" rule is reproducible. */
export function unitOf(id, salt = '') {
  let h = 2166136261;
  for (const c of `${salt}|${id}`) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); }
  return ((h >>> 0) % 100000) / 100000;
}
