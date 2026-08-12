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

import { statePath, stateWritesEnabled } from './state-dir.js';

function _readJson(scanRoot, name) {
  try { return JSON.parse(fs.readFileSync(statePath(scanRoot, name), 'utf8')); } catch { return null; }
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
  const dir = statePath(scanRoot, 'model-rescan');
  if (!stateWritesEnabled()) return null;
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

// Stage 6 correctness audit: diffValidatorRuns/persistRescanReport/
// summarizeDelta above were fully built, but nothing in the codebase ever
// produced a `{model, results: {findingId: {verdict, reason}}}` run file
// for them to consume — commands/labs.md's `--model-rescan` mode was
// disclosed as genuinely unwired rather than fabricated. This is the
// missing producer: runs the SAME findings through the LLM validator twice
// — once under whatever model the environment currently resolves to
// ("from"), once under `toModel` ("to", via the existing per-role env
// override `AGENTIC_SECURITY_LLM_MODEL_VALIDATE` — no new plumbing needed,
// llm-validator/providers.js already supports it) — and turns the two runs
// into a real delta report. Reuses validateMany's own candidate filter
// (critical/high severity, low confidence, or AST parser) rather than
// re-validating every finding, matching normal validation scope. When no
// LLM endpoint is configured, validateMany degrades every finding to
// 'unvalidated' with no network call — this function inherits that
// no-network-by-default behavior rather than working around it.
export async function runModelRescan(scanRoot, { toModel } = {}) {
  if (!toModel) return { ok: false, reason: 'no --model given to rescan with' };
  const scan = _readJson(scanRoot, 'last-scan.json');
  if (!scan) return { ok: false, reason: 'no .agentic-security/last-scan.json — run a scan first' };
  const findings = Array.isArray(scan.findings) ? scan.findings : [];
  if (!findings.length) return { ok: false, reason: 'last scan has no findings to re-validate' };

  const fileContents = {};
  for (const f of findings) {
    if (!f.file || fileContents[f.file] !== undefined) continue;
    try { fileContents[f.file] = fs.readFileSync(path.join(scanRoot, f.file), 'utf8'); }
    catch { /* file may have moved/been deleted since the scan; validateMany skips it */ }
  }

  const { validateMany } = await import('../llm-validator/index.js');
  const { resolveProvider } = await import('../llm-validator/providers.js');

  const runFor = async (envKey, modelOverride) => {
    const prev = envKey ? process.env[envKey] : undefined;
    if (envKey) process.env[envKey] = modelOverride;
    let resolvedModel = 'unvalidated';
    try {
      const r = resolveProvider({ role: 'validate' });
      if (r.ok) resolvedModel = r.config.model;
      const clones = findings.map(f => ({ ...f }));
      await validateMany(clones, { fileContents, scanRoot });
      const results = {};
      for (const f of clones) {
        const id = f.stableId || f.id;
        if (!id) continue;
        results[id] = { verdict: f.validator_verdict || 'unvalidated', reason: f.validator_reasoning || null };
      }
      return { model: resolvedModel, results };
    } finally {
      if (envKey) {
        if (prev === undefined) delete process.env[envKey];
        else process.env[envKey] = prev;
      }
    }
  };

  const runA = await runFor(null, null);
  const runB = await runFor('AGENTIC_SECURITY_LLM_MODEL_VALIDATE', toModel);

  const changed = diffValidatorRuns(runA, runB);
  const reportPath = persistRescanReport(scanRoot, runA.model, runB.model, changed);
  return { ok: true, from: runA.model, to: runB.model, changed, reportPath, summary: summarizeDelta(changed) };
}

export const _internals = {};
