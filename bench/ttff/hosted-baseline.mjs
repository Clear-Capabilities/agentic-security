#!/usr/bin/env node
// Derive the `hosted` block of bench/ttff/BASELINE.json from time-to-first-finding samples measured ON THE HOSTED RUNNER.
//
// A laptop number says nothing about a shared runner: the same scan that takes 8 s locally takes 11 to 14 s hosted, and the spread
// between two hosted runs of one byte-identical tree has been 20 percent (13.7 s and 16.5 s for the 0.220.0 tree, 2026-11-22). The
// gate therefore compares a hosted run with a hosted baseline, and that baseline must be re-derived deliberately when what it
// describes changes: the runner image (ubuntu-latest moved to 26.04 in November 2026, after the previous block was recorded on
// 2026-10-26) or the engine (0.221.0 removed 2.5 s of a 10.5 s local scan).
//
// The rule, unchanged from the hand-derived block it replaces: `ms` is the MEDIAN of the samples; the regression factor is the
// largest sample over the median, rounded up to the next 0.05 and then raised by 0.15, never below 1.35 (two hosted runs of one byte-identical tree were 13.7 s and 16.5 s on consecutive days, a spread of 1.20, which a block derived on one day would not see), so one more sample of the
// observed spread passes and a slowdown of the whole distribution fails. Every sample and where it came from is written into the
// block, so the next reader can judge it. Fewer than five samples are refused: a median of three is a coin toss.
//
//   node bench/ttff/hosted-baseline.mjs --samples 13956,11473,13891 --derived-from "ci runs 45032576984, 45033132610 (attempts 1 to 4) ..." [--write]
//
// Without --write it prints the block it would write. With --write it replaces ONLY the `hosted` block of BASELINE.json; the local
// baseline (`ms`, `findings`, `filesScanned`, `recordedAt`, `regressionFactor`) is untouched, because `runner.mjs --update-baseline`
// owns those and keeps `hosted` the same way.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const BASELINE = path.join(HERE, 'BASELINE.json');
export const MIN_SAMPLES = 5;
export const MIN_FACTOR = 1.35;
export const FACTOR_MARGIN = 0.15;

export function median(values) {
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
}

/** The `hosted` block for a set of hosted samples (milliseconds). Throws on too few or non-positive samples. */
export function deriveHosted(samples, { derivedFrom, recordedAt = new Date().toISOString().slice(0, 10) } = {}) {
  const ms = samples.map(Number);
  if (ms.length < MIN_SAMPLES) throw new Error(`need at least ${MIN_SAMPLES} hosted samples, got ${ms.length}`);
  if (ms.some((v) => !Number.isFinite(v) || v <= 0)) throw new Error('every sample must be a positive number of milliseconds');
  if (!derivedFrom || !String(derivedFrom).trim()) throw new Error('--derived-from must say which hosted runs the samples came from');
  const med = median(ms);
  const spread = Math.max(...ms) / med;
  const factor = Math.max(MIN_FACTOR, Math.ceil(spread * 20) / 20 + FACTOR_MARGIN);
  return {
    ms: med,
    regressionFactor: Math.round(factor * 100) / 100,
    samples: [...ms].sort((a, b) => a - b),
    derivedFrom: `${String(derivedFrom).trim()} ms is the median of the ${ms.length} samples; the factor is the largest sample over the median (${Math.max(...ms)}/${med} = ${spread.toFixed(2)}) rounded up to 0.05 plus ${FACTOR_MARGIN}, floor ${MIN_FACTOR}; limit ${Math.round(med * factor)} ms.`,
    recordedAt,
  };
}

/** Replace only the `hosted` block of a baseline file's parsed object; everything else is returned as it was. */
export function withHosted(baseline, hosted) {
  const { hosted: _old, ...rest } = baseline;
  return { ...rest, hosted };
}

function arg(name) { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; }

if (import.meta.url === `file://${process.argv[1]}`) {
  const samples = String(arg('--samples') || '').split(',').map((s) => s.trim()).filter(Boolean);
  const derivedFrom = arg('--derived-from');
  let hosted;
  try { hosted = deriveHosted(samples, { derivedFrom }); } catch (e) { console.error(`✗ ${e.message}`); process.exit(2); }
  const baseline = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  const next = withHosted(baseline, hosted);
  if (process.argv.includes('--write')) {
    fs.writeFileSync(BASELINE, JSON.stringify(next, null, 1) + '\n');
    console.log(`✓ hosted baseline written: median ${hosted.ms} ms, factor ${hosted.regressionFactor}, limit ${Math.round(hosted.ms * hosted.regressionFactor)} ms, ${hosted.samples.length} samples`);
  } else {
    console.log(JSON.stringify(hosted, null, 1));
    console.log(`(dry run: median ${hosted.ms} ms, factor ${hosted.regressionFactor}, limit ${Math.round(hosted.ms * hosted.regressionFactor)} ms; add --write to replace the hosted block)`);
  }
}
