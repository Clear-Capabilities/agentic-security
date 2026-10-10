// invariant-tools.js: the MCP surface for bounded business-logic scenarios (X-407.AC03).
//
// One READ-ONLY tool, `invariant_scenario_export`: build the reproducible scenario package for a reviewer-supplied contract and a
// disposable fixture directory that both live inside the session root. It runs nothing and writes nothing. The same function
// the CLI calls (`posture/invariants/export.js` `exportFromFiles`) does the work, so the two surfaces cannot disagree.
//
// Guarantees, each with a test:
//   - paths are confined to the session root by the server's own `_confine` (passed in; this file never resolves a path itself);
//   - the export carries no tenant secret: scenarios holding secret-looking content are withheld, the fixture source is never
//     included, and the serialized result is checked once more with the server's own secret-shape redactor, which BLOCKS the
//     result rather than editing it (an edited scenario is a different scenario);
//   - it never claims exhaustive correctness: every export carries the bounded-sample statement;
//   - gated behind the `invariant-scenarios` feature (off by default, operator-only): with it off the tool reports it is
//     disabled and builds nothing.
// The factory shape (rather than importing `_confine` from tools.js) avoids a cycle between this file and the registry.
import { exportFromFiles } from '../posture/invariants/export.js';
import { resolveAssuranceConfig } from '../posture/assurance/config.js';
import { redactSecretShapes } from './redact.js';

const MAX_RESPONSE_BYTES = 1_500_000;

export function makeInvariantTools({ confine, META }) {
  const invariant_scenario_export = {
    name: 'invariant_scenario_export',
    description: 'Export the bounded stateful scenarios for one executable business-logic invariant as a reproducible package: scenario documents with content digests, the pinned fixture digest, replay manifests (when a commit is given), the bounds applied and the scenario families that could not be built. Read-only: runs nothing. The fixture source and any secret-looking content are never included, and the package states that it is a bounded sample, not a proof of correctness. Requires the invariant-scenarios feature (off by default).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        invariant_file: { type: 'string', minLength: 1, maxLength: 512 },
        fixture_dir: { type: 'string', minLength: 1, maxLength: 512 },
        ledger_file: { type: 'string', minLength: 1, maxLength: 512 },
        commit: { type: 'string', pattern: '^[0-9a-f]{40}([0-9a-f]{24})?$' },
        seed: { type: 'integer', minimum: 0, maximum: 4294967295 },
        bounds: {
          type: 'object', additionalProperties: false,
          properties: {
            actors: { type: 'integer', minimum: 1, maximum: 4 }, depth: { type: 'integer', minimum: 1, maximum: 12 }, requests: { type: 'integer', minimum: 1, maximum: 16 },
            scenarios: { type: 'integer', minimum: 1, maximum: 6 }, timeBudgetMs: { type: 'integer', minimum: 1, maximum: 8000 },
          },
        },
      },
      required: ['invariant_file', 'fixture_dir'],
    },
    async handler(args, ctx) {
      let invariantPath; let fixturePath; let ledgerPath;
      try {
        invariantPath = confine(ctx.sessionRoot, args.invariant_file, 'invariant_file');
        fixturePath = confine(ctx.sessionRoot, args.fixture_dir, 'fixture_dir');
        if (args.ledger_file) ledgerPath = confine(ctx.sessionRoot, args.ledger_file, 'ledger_file');
      } catch (e) {
        return { _meta: META, ok: false, status: 'rejected', reason: `path refused: ${String(e.message).replace(ctx.sessionRoot, '<root>')}` };
      }
      const config = resolveAssuranceConfig({ scanRoot: ctx.sessionRoot, env: process.env });
      const r = exportFromFiles({ invariantPath, fixturePath, ledgerPath, commit: args.commit, seed: args.seed, bounds: args.bounds, config });
      if (r.status !== 'ok') return { _meta: META, ok: false, status: r.status, reason: String(r.reason || '').replace(ctx.sessionRoot, '<root>').slice(0, 400), withheld: r.withheld ?? [] };
      const text = JSON.stringify(r.export);
      if (redactSecretShapes(text).redactions > 0) return { _meta: META, ok: false, status: 'blocked', reason: 'the export contains secret-shaped content and was not returned; an edited scenario would be a different scenario' };
      if (text.length > MAX_RESPONSE_BYTES) return { _meta: META, ok: false, status: 'blocked', reason: 'the export is too large for one response; lower the bounds' };
      return { _meta: META, ok: true, status: 'ok', export: r.export, withheld: r.withheld };
    },
  };
  return { invariant_scenario_export };
}
