// Evidence contract (PRD FR 10): additive scan-record and finding-record fields. Nothing here replaces an existing
// field; every field is derived from data the scan already holds or from read-only git queries on the scan root.

import * as crypto from 'node:crypto';
import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';

export const SCAN_RECORD_SCHEMA = 'scan-record/1';
export const FINDING_RECORD_SCHEMA = 'finding-record/1';
const DIRTY_CAP = 200;

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function git(root, args) {
  const r = cp.spawnSync('git', hardenGitArgs(args), { cwd: root, env: hardenGitEnv({}), encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? r.stdout.toString('utf8') : null;
}

/** Source commit and digests of the files that differ from it, so a result is tied to the exact code scanned. */
export function sourceState(root) {
  const inside = git(root, ['rev-parse', '--is-inside-work-tree']);
  if (!inside || inside.trim() !== 'true') return { vcs: 'none', commit: null, dirty: null, dirtyFiles: [], dirtyFilesTruncated: false };
  const commit = (git(root, ['rev-parse', 'HEAD']) || '').trim() || null;
  const status = git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=normal']);
  const entries = (status || '').split('\0').filter(Boolean).map((e) => ({ code: e.slice(0, 2), file: e.slice(3) }));
  const dirtyFiles = entries.slice(0, DIRTY_CAP).map((e) => {
    let digest = null;
    try { const abs = path.join(root, e.file); if (fs.lstatSync(abs).isFile()) digest = sha(fs.readFileSync(abs)); } catch { /* deleted */ }
    return { file: e.file, status: e.code.trim() || '?', sha256: digest };
  });
  return { vcs: 'git', commit, dirty: entries.length > 0, dirtyFiles, dirtyFilesTruncated: entries.length > DIRTY_CAP, dirtyCount: entries.length };
}

/** Flags that shaped the run, with values that could carry secrets or local paths reduced to their names. */
export function invocationSummary(argv) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    let [k, v] = a.split(/=(.*)/s, 2);
    // `--flag value`: keep a short non-path value so the record shows the format and mode that were chosen.
    if (v === undefined && argv[i + 1] !== undefined && !argv[i + 1].startsWith('-') && /^[A-Za-z0-9_.,:-]{1,40}$/.test(argv[i + 1]) && !argv[i + 1].includes('/')) v = argv[i + 1];
    out.push(/key|token|secret|password/i.test(k) ? `${k}=<redacted>` : (v !== undefined ? `${k}=${v}` : k));
  }
  return out;
}

export function buildScanRecord({ root, scan, meta, argv = [], engineVersion, mode }) {
  const h = scan.scanHealth || {};
  const model = scan.aiAssistance || null;
  return {
    schema: SCAN_RECORD_SCHEMA,
    tool: { name: 'agentic-security', version: engineVersion || null },
    source: sourceState(root),
    invocation: { flags: invocationSummary(argv), mode: mode || (meta && meta.mode) || 'full' },
    ignorePolicy: scan.scope ? { mode: scan.scope.policy.mode, ruleDigest: scan.scope.policy.ruleDigest, trackedFileSemantics: scan.scope.policy.trackedFileSemantics } : { mode: 'legacy-walk', ruleDigest: null, trackedFileSemantics: false },
    rules: { rulesetVersion: scan._rulesetVersion || null, rulesetSource: scan._rulesetVersionSource || null },
    model: model ? { provider: model.provider, model: model.model, egress: model.egress, stages: model.stages } : { configured: false },
    capability: { status: h.status || null, conditions: Array.isArray(h.conditions) ? h.conditions.length : 0 },
    fileCounts: { scanned: scan.filesScanned ?? null, skipped: scan.scope ? scan.scope.skippedCount : null, included: scan.scope ? scan.scope.includedCount : null },
    // Wall-clock time differs on every run, so deterministic mode leaves it out and the record stays byte-identical.
    elapsedMs: process.env.AGENTIC_SECURITY_DETERMINISTIC === '1' ? null : (meta && meta.durationMs != null ? meta.durationMs : null),
  };
}

/** The span a finding occupies: source line through sink line when both are known, else its own line. */
function spanOf(f) {
  const lines = [f.line, f.source && f.source.line, f.sink && f.sink.line].filter((n) => Number.isInteger(n));
  if (!lines.length) return null;
  return { startLine: Math.min(...lines), endLine: Math.max(...lines) };
}

/** Finding record. `fileContents` maps scan-relative path to text. Existing fields are untouched. */
export function annotateFindingRecords(findings, fileContents, { engineVersion = null } = {}) {
  for (const f of findings || []) {
    if (!f || f.record) continue;
    const text = fileContents && (fileContents instanceof Map ? fileContents.get(f.file) : fileContents[f.file]);
    f.record = {
      schema: FINDING_RECORD_SCHEMA,
      stableId: f.stableId || null,
      path: f.file || null,
      sourceHash: typeof text === 'string' ? sha(text) : null,
      span: spanOf(f),
      ruleFamily: f.family || null,
      ruleVersion: engineVersion,
      originalSeverity: f.originalSeverity || f.severity || null,
      confidence: typeof f.confidence === 'number' ? f.confidence : null,
      disposition: f.disposition || null,
      evidence: {
        sourceToSink: f.source || f.sink ? { source: f.source || null, sink: f.sink || null } : null,
        guards: f.falsification ? [f.falsification] : [],
        missingEvidence: (f.dispositionDetail && f.dispositionDetail.missingEvidence) || [],
      },
      reviewerVerdicts: Array.isArray(f.reviewerVerdicts) ? f.reviewerVerdicts : [],
      modelOpinion: f.validator_verdict ? { verdict: f.validator_verdict, confidence: f.llm_confidence ?? null } : null,
      remediation: f.fix || f.remediation || null,
    };
  }
  return findings;
}

/**
 * Raw and displayed findings must reconcile: every raw item is either displayed or accounted for by a named reason.
 * Returns { ok, raw, displayed, accounted, gap }.
 */
export function reconcileFindings({ raw, displayed, hidden = {} }) {
  const accounted = Object.values(hidden).reduce((a, b) => a + b, 0);
  const gap = raw - displayed - accounted;
  return { ok: gap === 0, raw, displayed, accounted, gap };
}
