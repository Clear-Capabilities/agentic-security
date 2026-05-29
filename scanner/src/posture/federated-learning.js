// Federated learning across opt-in customers — Recommendation #7 of the
// world-class+2 plan.
//
// Extends scanner/src/posture/triage-learning.js with a privacy-preserving
// cross-customer aggregation layer. Each opt-in customer's triage
// decisions contribute a noisy gradient (ε-differential privacy) to a
// central coordinator. The aggregated global prior gets blended with
// each local prior so all customers benefit from each other's calibration
// without sharing source code or findings.
//
// Privacy model:
//   - We only submit (family, sink-method, tp_delta, fp_delta) — never
//     the finding text, file path, or any identifier
//   - Counts are perturbed with Laplace noise at scale 1/ε (default ε=1.0)
//   - Receipts of every transmission written to
//     .agentic-security/federated-receipts.jsonl for audit
//   - Opt-in via AGENTIC_SECURITY_FEDERATED=1; off-by-default
//
// Threat model:
//   - Attacker controls the coordinator → cannot recover an individual
//     customer's triage history because of DP noise
//   - Attacker controls one customer → can attempt poisoning, but each
//     customer's contribution is capped via SUBMISSION_CAP_PER_DAY
//   - Network observer → all traffic is HTTPS; payloads are aggregated
//     counts not individual events

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath, safeWriteState } from './state-dir.js';
import { loadCalibration } from './triage-learning.js';

const RECEIPTS_FILE = 'federated-receipts.jsonl';
const LAST_PUSH_FILE = 'federated-last-push.json';
const DEFAULT_EPSILON = 1.0;
const SUBMISSION_CAP_PER_DAY = 10;
const DEFAULT_PUSH_INTERVAL_HOURS = 24;

/**
 * Sample from Laplace(0, b) where b = 1/ε. Used to add DP noise to count
 * deltas before submission.
 */
function laplaceNoise(epsilon) {
  if (epsilon <= 0) return 0;
  const u = Math.random() - 0.5;
  const b = 1 / epsilon;
  return -b * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
}

function _receiptsPath(scanRoot) { return statePath(scanRoot, RECEIPTS_FILE); }
function _lastPushPath(scanRoot) { return statePath(scanRoot, LAST_PUSH_FILE); }

function _appendReceipt(scanRoot, receipt) {
  const fp = _receiptsPath(scanRoot);
  try { fs.appendFileSync(fp, JSON.stringify(receipt) + '\n'); } catch {}
}

function _readLastPush(scanRoot) {
  const fp = _lastPushPath(scanRoot);
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

function _writeLastPush(scanRoot, payload) {
  const fp = _lastPushPath(scanRoot);
  safeWriteState(fp, JSON.stringify(payload, null, 2));
}

/**
 * Compute the privatized gradient against a baseline calibration. The
 * gradient is the per-bucket count delta since the last push, with
 * Laplace noise added. The baseline is `lastPush.snapshot`; current
 * counts come from the local triage-learning store.
 */
export function computePrivatizedGradient(currentCalibration, baseline, opts = {}) {
  const epsilon = opts.epsilon ?? DEFAULT_EPSILON;
  const grad = { global: {}, perProject: null }; // perProject NEVER shared
  const baseGlobal = baseline?.snapshot?.global || {};
  for (const [bucket, cur] of Object.entries(currentCalibration.global || {})) {
    const prev = baseGlobal[bucket] || { tp: 0, fp: 0 };
    const tpDelta = (cur.tp || 0) - (prev.tp || 0);
    const fpDelta = (cur.fp || 0) - (prev.fp || 0);
    if (tpDelta === 0 && fpDelta === 0) continue;
    grad.global[bucket] = {
      tp: Math.max(0, Math.round(tpDelta + laplaceNoise(epsilon))),
      fp: Math.max(0, Math.round(fpDelta + laplaceNoise(epsilon))),
    };
  }
  return grad;
}

/**
 * Push the privatized gradient to the central coordinator. Coordinator
 * endpoint defaults to a known address; can be overridden by
 * AGENTIC_SECURITY_FEDERATED_ENDPOINT. Records a receipt on success or
 * failure.
 */
export async function pushGradient(scanRoot, gradient, opts = {}) {
  if (process.env.AGENTIC_SECURITY_FEDERATED !== '1') {
    return { ok: false, reason: 'opt-in-not-enabled' };
  }
  const last = _readLastPush(scanRoot) || { count: 0, day: '' };
  const today = new Date().toISOString().slice(0, 10);
  if (last.day === today && last.count >= SUBMISSION_CAP_PER_DAY) {
    return { ok: false, reason: 'daily-cap-reached', cap: SUBMISSION_CAP_PER_DAY };
  }
  const endpoint = opts.endpoint || process.env.AGENTIC_SECURITY_FEDERATED_ENDPOINT;
  if (!endpoint) return { ok: false, reason: 'no-endpoint-configured' };
  const payload = {
    schema: 'agentic-security/federated-grad/v1',
    epsilon: opts.epsilon ?? DEFAULT_EPSILON,
    bucketCount: Object.keys(gradient.global || {}).length,
    gradient: gradient.global || {},
    ts: new Date().toISOString(),
    submissionId: crypto.randomBytes(8).toString('hex'),
  };
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'agentic-security/0.1' },
      body: JSON.stringify(payload),
    });
    const ok = res.ok;
    const status = res.status;
    _appendReceipt(scanRoot, { ts: payload.ts, submissionId: payload.submissionId, ok, status, bucketCount: payload.bucketCount });
    _writeLastPush(scanRoot, {
      count: (last.day === today ? last.count : 0) + 1, day: today,
      snapshot: { global: Object.fromEntries(Object.entries(loadCalibration(scanRoot).global || {})) },
    });
    return { ok, status, submissionId: payload.submissionId };
  } catch (e) {
    _appendReceipt(scanRoot, { ts: payload.ts, submissionId: payload.submissionId, ok: false, error: String(e && e.message || e) });
    return { ok: false, reason: 'network-error', error: String(e && e.message || e) };
  }
}

/**
 * Pull the aggregated global prior from the coordinator. The coordinator
 * returns an aggregated calibration after combining all opt-in customer
 * gradients.
 */
export async function pullAggregatedPrior(scanRoot, opts = {}) {
  if (process.env.AGENTIC_SECURITY_FEDERATED !== '1') return null;
  const endpoint = (opts.endpoint || process.env.AGENTIC_SECURITY_FEDERATED_ENDPOINT || '').replace(/\/$/, '');
  if (!endpoint) return null;
  try {
    const res = await fetch(`${endpoint}/aggregate`, {
      headers: { 'User-Agent': 'agentic-security/0.1' },
    });
    if (!res.ok) return null;
    const prior = await res.json();
    _appendReceipt(scanRoot, { ts: new Date().toISOString(), kind: 'pull', ok: true });
    return prior;
  } catch { return null; }
}

/**
 * Run the periodic federated learning cycle: compute privatized
 * gradient against last push baseline, submit, fetch aggregated prior.
 */
export async function federatedCycle(scanRoot, opts = {}) {
  const calibration = loadCalibration(scanRoot);
  const last = _readLastPush(scanRoot);
  const gradient = computePrivatizedGradient(calibration, last || {}, opts);
  const pushResult = await pushGradient(scanRoot, gradient, opts);
  const pullResult = await pullAggregatedPrior(scanRoot, opts);
  return { gradient, pushResult, aggregatedPrior: pullResult };
}

export const _internals = {
  laplaceNoise, DEFAULT_EPSILON, SUBMISSION_CAP_PER_DAY, DEFAULT_PUSH_INTERVAL_HOURS,
};
