// Model-of-the-month re-scan delta.
//
// Re-runs the LLM validator (already opt-in via AGENTIC_SECURITY_LLM_VALIDATE)
// with a different model and produces a delta report: which findings the
// newer model marked TP that the prior model marked FP (or vice versa),
// what newer reasoning catches that older reasoning missed.
//
// Use case: every time Anthropic ships a new Claude model (or you want to
// A/B against gpt-5 / a custom finetune), re-validate the last scan and see
// which findings change verdict.
//
// Output: .agentic-security/model-rescan/<from>-vs-<to>.json with:
//   { from, to, changed: [{ finding_id, before, after, why }], ts }

import * as fs from 'node:fs';
import * as path from 'node:path';

const STATE = '.agentic-security';

function _readJson(scanRoot, name) {
  try { return JSON.parse(fs.readFileSync(path.join(scanRoot, STATE, name), 'utf8')); } catch { return null; }
}

/**
 * Compare two validator runs by finding_id. Each run is a JSON like:
 *   { model: 'claude-sonnet-4', results: { findingId: { verdict, reason }, ... } }
 */
export function diffValidatorRuns(runA, runB) {
  const a = runA && runA.results ? runA.results : {};
  const b = runB && runB.results ? runB.results : {};
  const ids = new Set([...Object.keys(a), ...Object.keys(b)]);
  const changed = [];
  for (const id of ids) {
    const av = (a[id] && a[id].verdict) || null;
    const bv = (b[id] && b[id].verdict) || null;
    if (av !== bv) {
      changed.push({
        finding_id: id,
        before: av,
        after: bv,
        before_reason: a[id]?.reason || null,
        after_reason: b[id]?.reason || null,
      });
    }
  }
  return changed;
}

/**
 * Persist a model-rescan report. Returns the file path.
 */
export function persistRescanReport(scanRoot, from, to, changed) {
  const dir = path.join(scanRoot, STATE, 'model-rescan');
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const safe = (s) => String(s || 'unknown').replace(/[^\w.-]/g, '-');
  const fp = path.join(dir, `${safe(from)}-vs-${safe(to)}.json`);
  const report = { from, to, ts: new Date().toISOString(), changed };
  try { fs.writeFileSync(fp, JSON.stringify(report, null, 2)); } catch {}
  return fp;
}

/**
 * Build a quick natural-language summary of the delta.
 */
export function summarizeDelta(changed) {
  if (!Array.isArray(changed) || !changed.length) return 'No changes — validators agree on every finding.';
  const flipsToTP = changed.filter(c => c.before === 'fp' && c.after === 'tp');
  const flipsToFP = changed.filter(c => c.before === 'tp' && c.after === 'fp');
  const lines = [];
  lines.push(`${changed.length} verdict change(s) between models:`);
  if (flipsToTP.length) lines.push(`  ${flipsToTP.length} finding(s) now confirmed TP (newer model caught what older missed)`);
  if (flipsToFP.length) lines.push(`  ${flipsToFP.length} finding(s) now FP (newer model recognized as safe)`);
  return lines.join('\n');
}

export const _internals = {};
