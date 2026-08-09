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
// BOUNDED TWICE, BECAUSE ONE BOUND WAS NOT ENOUGH. `maxCandidates` caps how
// many findings are proved in one scan, and the cap is REPORTED rather than
// applied silently — a scan that quietly proved the first N findings and said
// nothing would look like a scan that found only N provable ones.
//
// A count cap alone bounds nothing in time, though, and a per-run timeout is
// only as good as the backend's ability to enforce it — which CI proved is not
// something to take on faith (the namespace backend's timeout did not stop a
// payload at all until `killSignal: 'SIGKILL'` landed). So there is also an
// AGGREGATE wall-clock budget checked between candidates. It cannot interrupt a
// call already in flight (`spawnSync` blocks the thread), but it bounds the
// total and stops the loop rather than letting a slow host multiply one bad
// case by `maxCandidates`.
//
// WHAT THIS ACTUALLY EXECUTES, STATED PLAINLY. The generated PoC does
// `import handler from './<target file>'`, and an ES module import runs the
// target file's ENTIRE TOP-LEVEL BODY before any handler is called. So enabling
// this on a repository you do not trust executes that repository's top-level
// code. Confinement contains what it can — no filesystem writes outside the
// sandbox root, no network egress, both verified by executing tests on each
// backend — but CPU and wall-clock are bounded only by the budgets here. Do not
// enable this on untrusted code without accepting that.

import { synthesizeInProcessPoc } from './poc-inprocess.js';
import { proveFinding, DEFAULT_PROOF_TIMEOUT_MS } from './execution-proof.js';
import { sandboxAvailable } from '../sandbox/index.js';

const DEFAULT_MAX = 25;
// Aggregate wall-clock across all candidates in one scan.
const DEFAULT_TOTAL_BUDGET_MS = 120000;

/**
 * The file set materialised into the sandbox root for one PoC.
 *
 * `requires` names the vulnerable source (the PoC imports it). `extraFiles`
 * carries support files a template needs that are NOT that source — the SQL
 * class ships a recording driver stub as `node_modules/<driver>/index.js`.
 *
 * `requires` WINS on a collision. Otherwise a template could name the
 * vulnerable file in `extraFiles` and replace the very code the PoC is
 * supposed to exploit with content of its own choosing, and the run would
 * prove a fact about the template.
 */
export function mergePocFiles(poc, content) {
  const files = {};
  for (const rel of poc?.requires || []) files[rel] = content;
  for (const [rel, c] of Object.entries(poc?.extraFiles || {})) {
    if (rel in files) continue;
    if (typeof c === 'string') files[rel] = c;
  }
  return files;
}

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
  // Shares one ceiling with execution-proof.js so the two cannot drift; see the
  // rationale on DEFAULT_PROOF_TIMEOUT_MS there. Bounded overall by
  // maxCandidates, so a generous per-PoC budget cannot run away.
  fileContents = null, maxCandidates = DEFAULT_MAX, timeoutMs = DEFAULT_PROOF_TIMEOUT_MS,
  totalBudgetMs = DEFAULT_TOTAL_BUDGET_MS, env = process.env, now = Date.now,
} = {}) {
  const summary = {
    enabled: false, attempted: 0, proven: 0, failed: 0, inconclusive: 0,
    skipped: 0, capped: 0, budgetExhausted: 0, reason: null,
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

  const startedAt = now();
  for (const c of candidates) {
    // Checked BEFORE each call, since a call in flight cannot be interrupted.
    // Reported, never silent: findings left unproven because the budget ran out
    // are a different statement from findings that could not be proved.
    if (now() - startedAt >= totalBudgetMs) {
      summary.budgetExhausted = candidates.length - summary.attempted;
      break;
    }
    summary.attempted++;
    // The PoC imports the vulnerable file, so it must exist in the sandbox
    // root alongside it.
    const files = mergePocFiles(c.poc, c.content);
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
  if (s.budgetExhausted) {
    bits.push(`${s.budgetExhausted} eligible finding(s) NOT attempted (aggregate time budget exhausted) — `
      + 'unproven here means unattempted, not unprovable');
  }
  return bits.join('; ') + '.';
}

export const _internals = { DEFAULT_MAX, DEFAULT_TOTAL_BUDGET_MS };
