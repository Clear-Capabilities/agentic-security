// Canonical scan output (E6-06).
//
// A scan result mixes two kinds of fact. Some are about the CODE: which findings exist, where, with what evidence. Those must be identical on every
// run over the same input, whatever order the files were read in, however many scans ran at once, and whenever it happened. The rest are about the
// RUN: when it started, how long each stage took, which stage finished first. Those differ every time and are not a defect.
//
// This module splits them:
//   canonical   findings (and the other finding-bearing lists) with volatile fields removed, numbers rounded to a fixed precision, object keys sorted,
//               lists in a total order (file, line, vuln, stableId, id, then the serialized record as the last tiebreak). Hashed into `digest`.
//   run         timestamps, durations, telemetry, scan id; kept, separate, and never part of the digest
//   provenance  what produced the canonical part: scanner version, rule-pack hash, and each source of NONDETERMINISM that was active (a network feed,
//               a model), named so a reader knows which results could legitimately differ
//
// The digest therefore answers one question: did two runs find the same things? A difference in `run` never changes it.
import { createHash } from 'node:crypto';
import { computeRulePackHash } from '../posture/deterministic.js';

const LISTS = Object.freeze(['findings', 'secrets', 'logicVulns', 'supplyChain']);
// fields inside a finding that describe the run, not the code
const VOLATILE_FINDING_KEYS = new Set(['detectedAt', 'scannedAt', 'ts', 'timestamp', 'elapsedMs', 'durationMs', 'scanId']);
const PRECISION = 6;

const round = (n) => (Number.isInteger(n) ? n : Math.round(n * 10 ** PRECISION) / 10 ** PRECISION);
function clean(v) {
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v).sort()) { if (VOLATILE_FINDING_KEYS.has(k) || v[k] === undefined) continue; o[k] = clean(v[k]); }
    return o;
  }
  return typeof v === 'number' && Number.isFinite(v) ? round(v) : v;
}
const s = (x) => (x === undefined || x === null ? '' : String(x));
function order(a, b) {
  return s(a.file).localeCompare(s(b.file), 'en') || (Number(a.line) || 0) - (Number(b.line) || 0) || s(a.vuln || a.title).localeCompare(s(b.vuln || b.title), 'en')
    || s(a.stableId).localeCompare(s(b.stableId), 'en') || s(a.id).localeCompare(s(b.id), 'en') || JSON.stringify(a).localeCompare(JSON.stringify(b), 'en');
}

/** Sources of nondeterminism that are active for this process, named. */
export function nondeterminismSources(env = process.env) {
  const out = [];
  if (env.AGENTIC_SECURITY_LLM_ENDPOINT && env.AGENTIC_SECURITY_LLM_VALIDATE !== '0') out.push({ source: 'llm-validator', reason: 'a model endpoint is configured and the validator is on: its verdicts can differ between runs', model: env.AGENTIC_SECURITY_LLM_MODEL || null });
  if (env.AGENTIC_SECURITY_DETERMINISTIC !== '1' && env.AGENTIC_SECURITY_OFFLINE !== '1') out.push({ source: 'network-feeds', reason: 'vulnerability and registry feeds are fetched and cached; their content changes over time' });
  return out;
}

/**
 * @param {object} scan a scan result
 * @param {{env?:object, scannerVersion?:string}} opts
 * @returns {{canonical:object, digest:string, run:object, provenance:object}}
 */
export function canonicalizeScan(scan, opts = {}) {
  const canonical = {};
  for (const k of LISTS) if (Array.isArray(scan && scan[k])) canonical[k] = scan[k].map(clean).sort(order);
  const digest = createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
  const meta = (scan && (scan._scanMeta || scan.meta)) || {};
  const run = {
    scanId: meta.scanId ?? null, startedAt: meta.startedAt ?? null, durationMs: meta.durationMs ?? null,
    telemetry: scan && scan.telemetry ? scan.telemetry : null,
    fileTimings: Array.isArray(meta.fileTimings) ? meta.fileTimings : null,
  };
  const provenance = { scannerVersion: opts.scannerVersion ?? null, rulePackHash: computeRulePackHash(), nondeterminism: nondeterminismSources(opts.env), canonicalPrecision: PRECISION };
  return { canonical, digest, run, provenance };
}
