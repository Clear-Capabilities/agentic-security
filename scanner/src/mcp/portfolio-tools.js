// portfolio-tools.js: the MCP surface for portfolio progress and review queues (X-707).
//
// One READ-ONLY tool, `portfolio_progress`: the coverage-aware progress view of a durable portfolio store that lives inside the session
// root. It reads the store (verified; a corrupt store is an error, never a reset), the scheduler ledger beside it, and optionally a
// budgets file and a findings file, and writes nothing. The same function the CLI calls (`posture/portfolio/progress.js`
// `buildProgressView`) does the work, so the two surfaces cannot disagree.
//
// Guarantees, each with a test:
//   - paths are confined to the session root by the server's own `_confine` (passed in; this file never resolves a path itself);
//   - the view separates verified, blocked/failed/stale, coverage, budget and pending review, keeps stale workers visible, and never
//     states that the portfolio passed (a finished controller is reported as finished);
//   - the serialized result is checked with the server's secret-shape redactor and BLOCKED rather than edited if anything would change;
//   - gated behind the `portfolio-assurance` feature (off by default): with it off the tool answers `status: 'disabled'` and reads nothing.
// The factory shape (rather than importing `_confine` from tools.js) avoids a cycle between this file and the registry.
import * as fs from 'node:fs';
import { resolveAssuranceConfig, featureStatus } from '../posture/assurance/config.js';
import { readStore } from '../posture/portfolio/work-units.js';
import { readLedger } from '../posture/portfolio/scheduler.js';
import { buildProgressView } from '../posture/portfolio/progress.js';
import { FEATURE_ID } from '../posture/portfolio/wording.js';
import { redactSecretShapes } from './redact.js';

const MAX_RESPONSE_BYTES = 1_500_000;
const MAX_INPUT_BYTES = 8 * 1024 * 1024;

function readJson(file) {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_INPUT_BYTES) throw new Error('not a regular JSON file within the size limit');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function makePortfolioTools({ confine, META }) {
  const portfolio_progress = {
    name: 'portfolio_progress',
    description: 'Show the progress of a resumable multi-repository portfolio audit as a coverage-aware view: verified units, blocked/failed/stale units, per-repository coverage, remaining budget, pending human review, worker liveness (stale workers stay visible) and, when a findings file is given, aggregate findings deduplicated by stable identity with per-repository/environment evidence and separate affected releases. A finished controller is reported as finished, never as passed. Read-only; paths must be inside the session root. Disabled unless the portfolio-assurance feature is on.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        store_file: { type: 'string', minLength: 1, maxLength: 512 },
        budgets_file: { type: 'string', minLength: 1, maxLength: 512 },
        findings_file: { type: 'string', minLength: 1, maxLength: 512 },
        blocking_severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] },
        now: { type: 'integer', minimum: 0 },
      },
      required: ['store_file'],
    },
    async handler(args, ctx) {
      const config = resolveAssuranceConfig({ scanRoot: ctx.sessionRoot, env: process.env });
      const gate = featureStatus(config, FEATURE_ID);
      if (gate.status !== 'ok') return { _meta: META, ok: false, status: gate.status, reason: `portfolio progress is not available: ${gate.reason ?? gate.code}` };
      let storePath; let budgetsPath; let findingsPath;
      try {
        storePath = confine(ctx.sessionRoot, args.store_file, 'store_file');
        if (args.budgets_file) budgetsPath = confine(ctx.sessionRoot, args.budgets_file, 'budgets_file');
        if (args.findings_file) findingsPath = confine(ctx.sessionRoot, args.findings_file, 'findings_file');
      } catch (e) {
        return { _meta: META, ok: false, status: 'rejected', reason: `path refused: ${String(e.message).replace(ctx.sessionRoot, '<root>')}` };
      }
      let store; let ledger; let budgets = null; let findings = null;
      try {
        store = readStore(storePath);
        if (!store) return { _meta: META, ok: false, status: 'rejected', reason: 'no portfolio store at that path' };
        ledger = readLedger(storePath);
        if (budgetsPath) budgets = readJson(budgetsPath);
        if (findingsPath) findings = readJson(findingsPath);
      } catch (e) {
        return { _meta: META, ok: false, status: 'blocked', reason: `the store or an input failed verification: ${String(e.code ?? e.message).slice(0, 200)}` };
      }
      const r = buildProgressView({ store, ledger, budgets, now: Number.isInteger(args.now) ? args.now : Date.now(), findings, blockingSeverity: args.blocking_severity });
      if (!r.ok) return { _meta: META, ok: false, status: 'rejected', reason: r.errors.map((e) => e.message).join('; ').slice(0, 400) };
      const text = JSON.stringify(r.view);
      if (redactSecretShapes(text).redactions > 0) return { _meta: META, ok: false, status: 'blocked', reason: 'the view contains secret-shaped content and was not returned' };
      if (text.length > MAX_RESPONSE_BYTES) return { _meta: META, ok: false, status: 'blocked', reason: 'the view is too large for one response' };
      return { _meta: META, ok: true, status: 'ok', view: r.view };
    },
  };
  return { portfolio_progress };
}
