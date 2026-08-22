// PRD F7.4 — calibration must be verified on HELD-OUT data before a release.
//
// The confidence number on every finding is a claim about how often the engine
// is right. Nothing checked that claim at release time, so a confidence surface
// could drift arbitrarily far from reality and ship.
//
// WHY NOT calibration-drift.js
// ----------------------------
// `computeDrift()` reads per-project triage feedback from a scanned project's
// state directory. At release time, in this repo, that data does not exist — it
// returns `no-feedback-data`. Wiring it into the gate would produce a check
// that passes vacuously on every release forever, which is worse than no check:
// it would read as "calibration verified" in the output.
//
// WHY NOT calibration-seed.json
// -----------------------------
// The seed is FITTING data, 4 entries. Measuring calibration error against the
// same labels the table was fitted on is the mistake CLAUDE.md explicitly names
// ("Calibration is held-out-only ... never compute Brier/ECE against the same
// labels"). It would report a flattering number that means nothing.
//
// WHAT THIS DOES
// --------------
// It looks for a held-out labelled set. If one exists, it computes ECE and
// Brier over it and fails when ECE exceeds the threshold. If one does NOT
// exist, calibration is UNVERIFIED — and unverified is not a pass, the same
// rule dependency-currency applies to an unreachable registry.
//
// Because no held-out set exists in this repo today, an unconditional failure
// would block every release until someone produces one. That is a real
// decision, not one to make silently, so it is waivable exactly the way
// `.dependency-holds.json` waives an unavoidable dependency pin: an explicit,
// reasoned, DATED entry that expires. A waiver past its reviewBy fails, so
// "temporarily unverified" cannot quietly become permanent.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const pathToUrl = (p) => pathToFileURL(p).href;

// ECE above this means the reported confidence is materially wrong. 0.10 is
// deliberately loose — this is a "something is badly off" alarm, not a
// precision instrument, and a tight threshold on a small held-out set would
// fire on noise.
const ECE_THRESHOLD = 0.10;

// Below this, an ECE figure is noise. Reported, but not gated on.
const MIN_HOLDOUT_SAMPLES = 30;

const HOLDOUT_CANDIDATES = [
  'bench/calibration-holdout/labels.jsonl',
  'scanner/test/fixtures/calibration/holdout.jsonl',
];

const WAIVER_FILE = '.calibration-waiver.json';

function readJson(p, fallback = null) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; }
}

function findHoldout(repo) {
  for (const rel of HOLDOUT_CANDIDATES) {
    const p = path.join(repo, rel);
    if (fs.existsSync(p) && fs.statSync(p).size > 0) return p;
  }
  return null;
}

/**
 * @returns {{ok:boolean, detail:string, warnings?:string[]}}
 */
export function runCalibrationHoldoutCheck(repo, { now = new Date() } = {}) {
  const holdout = findHoldout(repo);

  if (holdout) {
    // Reuse the CANONICAL ECE implementation rather than reimplementing it here
    // — a second copy would drift, and a calibration gate measuring calibration
    // differently from the calibration module is worse than none. The gate is
    // synchronous and holdout-eval.js is ESM, so it is loaded in a short-lived
    // child that prints JSON.
    const script = `
      import { parseLabeledJsonl, expectedCalibrationError } from ${JSON.stringify(pathToUrl(path.join(repo, 'scanner/src/posture/holdout-eval.js')))};
      import fs from 'node:fs';
      const samples = parseLabeledJsonl(fs.readFileSync(${JSON.stringify(holdout)}, 'utf8'));
      process.stdout.write(JSON.stringify({ n: samples.length, ece: samples.length ? expectedCalibrationError(samples) : null }));
    `;
    let measured;
    try {
      const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
        encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
      });
      measured = JSON.parse(out);
    } catch (e) {
      const why = (e.stderr || e.message || '').toString().split('\n')[0];
      return { ok: false, detail: `held-out set at ${path.relative(repo, holdout)} could not be evaluated: ${why}. Unevaluable is not a pass.` };
    }

    const { n, ece } = measured || {};
    if (!n || ece == null) {
      return { ok: false, detail: `held-out set at ${path.relative(repo, holdout)} produced no usable samples. Empty is not a pass.` };
    }
    if (n < MIN_HOLDOUT_SAMPLES) {
      return {
        ok: true,
        detail: `ECE ${ece.toFixed(3)} over ${n} held-out samples — below the ${MIN_HOLDOUT_SAMPLES}-sample floor, reported but NOT gated on (too few to separate drift from noise).`,
        warnings: [`calibration measured over only ${n} held-out samples; treat the figure as indicative.`],
      };
    }
    if (ece > ECE_THRESHOLD) {
      return {
        ok: false,
        detail: `ECE ${ece.toFixed(3)} over ${n} held-out samples exceeds ${ECE_THRESHOLD} — the reported confidence surface is materially miscalibrated.`,
      };
    }
    return { ok: true, detail: `ECE ${ece.toFixed(3)} over ${n} held-out samples (threshold ${ECE_THRESHOLD}).` };
  }

  // No held-out set. Unverified — not a pass.
  const waiver = readJson(path.join(repo, WAIVER_FILE));
  if (!waiver) {
    return {
      ok: false,
      detail: 'no held-out calibration set found, so the confidence surface is UNVERIFIED — which is not the same as calibrated. '
        + `Add one at ${HOLDOUT_CANDIDATES[0]}, or record a dated waiver in ${WAIVER_FILE}.`,
    };
  }
  const { reason, reviewBy } = waiver;
  if (typeof reason !== 'string' || reason.trim().length < 40) {
    return { ok: false, detail: `${WAIVER_FILE} needs a real reason — a waiver nobody can evaluate is indistinguishable from an oversight.` };
  }
  if (!reviewBy || Number.isNaN(Date.parse(reviewBy))) {
    return { ok: false, detail: `${WAIVER_FILE} needs a reviewBy date. A waiver with no expiry becomes permanent.` };
  }
  if (Date.parse(reviewBy) < now.getTime()) {
    return { ok: false, detail: `${WAIVER_FILE} expired on ${reviewBy}. Produce a held-out set or renew the waiver deliberately.` };
  }
  return {
    ok: true,
    detail: `calibration UNVERIFIED — waived until ${reviewBy}. ${reason.trim()}`,
    warnings: [`calibration is unverified and waived until ${reviewBy}; this is not evidence the confidence surface is correct.`],
  };
}
