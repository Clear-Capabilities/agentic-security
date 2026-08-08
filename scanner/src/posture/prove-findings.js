// Promote findings to `execution-proven` during a scan (R2 — the automatic half).
//
// Before this, `proveFinding` existed and was tested but had no call site in a
// scan, so `last-scan.json` could never contain an execution-proven finding and
// corpus auto-enrolment had to be driven by hand. This annotator closes that:
// it synthesizes a sandbox-runnable PoC for eligible findings, runs it inside
// R1's sandbox, and lets the sandbox decide the tier.
//
// OPT-IN, AND IT STAYS OPT-IN. This executes code derived from the scanned
// project. That is a different risk class from static analysis, and it is slow
// — one sandboxed process per candidate. Making it default-on would change
// what `scan` means. Enable with `AGENTIC_SECURITY_PROVE=1`.
//
// FAIL-CLOSED IN BOTH DIRECTIONS:
//   - No sandbox → nothing is executed and no tier is promoted. An
//     unavailable sandbox disables the feature, it never bypasses it.
//   - A PoC that could not run leaves the finding at its static tier. Only a
//     PoC that RAN and produced the marker yields `execution-proven`;
//     `attachProofTier` enforces that independently of anything here.
//
// BOUNDED. `maxCandidates` caps how many findings are proved in one scan, and
// the cap is REPORTED rather than applied silently — a scan that quietly proved
// the first N findings and said nothing would look like a scan that found only
// N provable ones.

import { synthesizeInProcessPoc } from './poc-inprocess.js';
import { proveFinding } from './execution-proof.js';
import { sandboxAvailable } from '../sandbox/index.js';

const DEFAULT_MAX = 25;

export function proveEnabled(env = process.env) {
  return env.AGENTIC_SECURITY_PROVE === '1';
}

/**
 * @param {object[]} findings   annotated findings (mutated in place)
 * @param {object}   opts
 * @param {Map|object} opts.fileContents  file -> source, as the engine already carries
 * @returns {object} a summary suitable for surfacing on the scan
 */
export async function annotateExecutionProofs(findings, {
  fileContents = null, maxCandidates = DEFAULT_MAX, timeoutMs = 10000, env = process.env,
} = {}) {
  const summary = {
    enabled: false, attempted: 0, proven: 0, failed: 0, inconclusive: 0,
    skipped: 0, capped: 0, reason: null,
  };
  if (!Array.isArray(findings) || !findings.length) return summary;
  if (!proveEnabled(env)) {
    summary.reason = 'not enabled (set AGENTIC_SECURITY_PROVE=1)';
    return summary;
  }
  if (!sandboxAvailable()) {
    // Deliberately not an error: an unavailable confinement primitive means
    // execution features switch OFF, per R1's constraint.
    summary.reason = 'no confinement backend available; execution proof disabled';
    return summary;
  }
  summary.enabled = true;

  const read = (file) => {
    if (!fileContents) return null;
    if (typeof fileContents.get === 'function') return fileContents.get(file) ?? null;
    return fileContents[file] ?? null;
  };

  const candidates = [];
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const content = read(f.file);
    const syn = synthesizeInProcessPoc(f, content);
    if (!syn.ok) { summary.skipped++; continue; }
    candidates.push({ finding: f, poc: syn.poc, content });
  }

  if (candidates.length > maxCandidates) {
    summary.capped = candidates.length - maxCandidates;
    candidates.length = maxCandidates;
  }

  for (const c of candidates) {
    summary.attempted++;
    // The PoC imports the vulnerable file, so it must exist in the sandbox
    // root alongside it.
    const files = {};
    for (const rel of c.poc.requires || []) files[rel] = c.content;
    let proved;
    try {
      proved = await proveFinding({ ...c.finding, poc: c.poc }, { files, timeoutMs });
    } catch (e) {
      summary.inconclusive++;
      continue;
    }
    c.finding.poc = c.poc;
    c.finding.proofTier = proved.proofTier;
    c.finding.proofEvidence = proved.proofEvidence;
    if (proved.proofTier === 'execution-proven') summary.proven++;
    else if (proved.proofTier === 'proof-failed') summary.failed++;
    else summary.inconclusive++;
  }
  return summary;
}

/** One-line human summary; null when the feature did not run. */
export function renderProofSummary(s) {
  if (!s || !s.enabled) return null;
  const bits = [`${s.proven} execution-proven of ${s.attempted} attempted`];
  if (s.failed) bits.push(`${s.failed} ran without demonstrating the bug (triage signal, NOT a false-positive verdict)`);
  if (s.inconclusive) bits.push(`${s.inconclusive} inconclusive`);
  if (s.capped) bits.push(`${s.capped} eligible finding(s) NOT attempted (per-scan cap)`);
  return bits.join('; ') + '.';
}

export const _internals = { DEFAULT_MAX };
