// proof-tools.js: the MCP surface for execution-backed exploit proof (PRD 1).
//
// Two tools, both of which RUN CODE in the proof fabric's confined environment, so both are classified `mutating` and both require
// `confirm: true`:
//   prove_finding   execute a reproducer (supplied, stored, or generated from the finding) and report the evidence state
//   prove_fix       overlay a patch on a COPY of the sources, replay the original exploit against it, run the static verification,
//                   and search for sibling exposures; the patch is never written to the project
//
// Guarantees, each with a test:
//   - nothing runs without `confirm: true`, without a verified (HMAC-checked) last scan, or for a shadow finding;
//   - a reproducer an agent supplies is validated as untrusted input (closed schema, argv only, bounded files, safe paths) before
//     it reaches the runner, and it runs under the same sandbox, limits, network policy and 3-of-3 plus independent replay as any other;
//   - patch paths are confined to the session root and the reserved write paths are refused, though nothing is written;
//   - the result carries evidence STATE and counts, never the target's output, and is scrubbed before it is returned;
//   - a model decides nothing: the oracle does.
// The factory shape (rather than importing helpers from tools.js) avoids a cycle between this file and the registry.
import { proveFinding } from '../posture/proof-fabric/orchestrator.js';
import { verifyFixWithProof, formatFixProof } from '../posture/proof-fabric/fix-proof.js';
import { resolveReproducer } from '../posture/proof-fabric/cli.js';
import { saveProof, scrubDeep } from '../posture/proof-fabric/store.js';
import { validateReproducer } from '../posture/proof-fabric/reproducer.js';
import { findSiblings } from '../posture/proof-fabric/siblings.js';
import { verifyFix } from '../posture/fix-verify.js';

const MAX_RESPONSE_BYTES = 200_000;

export function makeProofTools({ confine, META, readLastScanVerified, findById, isReservedWritePath, redactString }) {
  const refuse = (reason, extra = {}) => ({ _meta: META, ok: false, reason, ...extra });

  async function load(args, ctx) {
    if (args.confirm !== true) return { error: refuse('this tool executes code in the proof environment and requires confirm: true.') };
    const { scan, status } = readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) return { error: refuse(`last-scan.json failed integrity check: ${status}. Run a fresh scan.`) };
    const finding = findById(scan, args.finding_id);
    if (!finding) return { error: refuse(`Finding not found: ${args.finding_id}`) };
    if (finding._shadow === true) return { error: refuse('shadow findings cannot be proven') };
    let reproducer = null; let generated = null;
    if (args.reproducer) {
      const errs = validateReproducer(args.reproducer);
      if (errs.length) return { error: refuse(`the reproducer is not acceptable: ${errs.slice(0, 5).join('; ')}`) };
      reproducer = args.reproducer;
    } else {
      const r = resolveReproducer(ctx.sessionRoot, finding, null);
      if (!r.reproducer) return { error: refuse(`no reproducer was supplied or stored, and none could be generated: ${r.reason}`) };
      reproducer = r.reproducer; generated = r.generated;
    }
    return { scan, finding, reproducer, generated };
  }

  const finish = (obj) => {
    const safe = scrubDeep(obj);
    const text = redactString(JSON.stringify(safe));
    if (text.length > MAX_RESPONSE_BYTES) return refuse('the result is too large for one response');
    return { _meta: META, ...JSON.parse(text) };
  };

  const prove_finding = {
    name: 'prove_finding',
    description: 'Execute a reproducer for a finding in the confined proof environment and report its evidence state (CANDIDATE ... EXPLOIT_CONFIRMED). The reproducer is supplied, stored, or generated from the finding; EXPLOIT_CONFIRMED needs 3 of 3 reproductions and an independent replay, decided by a deterministic oracle, never by a model. Runs code: requires confirm: true. Returns state and counts, never the target\'s output.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        finding_id: { type: 'string', minLength: 1, maxLength: 256 },
        confirm: { type: 'boolean' },
        reproducer: { type: 'object' },
        attempts: { type: 'integer', minimum: 1, maximum: 10 },
        required: { type: 'integer', minimum: 1, maximum: 10 },
        require_container: { type: 'boolean' },
      },
      required: ['finding_id', 'confirm'],
    },
    async handler(args, ctx) {
      const l = await load(args, ctx);
      if (l.error) return l.error;
      const policy = {};
      if (args.attempts) policy.attempts = args.attempts;
      if (args.required) policy.required = Math.min(args.required, args.attempts ?? 10);
      if (args.require_container) policy.requireContainer = true;
      let result;
      try { result = await proveFinding({ finding: l.finding, reproducer: l.reproducer, policy, sourceRoot: ctx.sessionRoot }); } catch (e) { return refuse(`the proof could not run: ${String(e.message).slice(0, 200)}`); }
      const saved = saveProof(ctx.sessionRoot, { ...result, reproducer: l.reproducer, ...(l.generated ? { generatedFrom: l.generated } : {}) });
      return finish({
        ok: true, findingId: result.findingId, state: result.state, outcome: result.outcome, oracle: result.oracle, completeness: result.completeness,
        attempts: result.attempts, independentReplay: result.independentReplay?.status ?? 'not-run', environment: result.environment ? { mode: result.environment.mode, assurance: result.environment.assurance } : null,
        degradation: result.degradation, durationMs: result.timing?.proofMs ?? null, generated: l.generated, stored: saved.ok,
        note: 'Not reproduced is not proof of safety.',
      });
    },
  };

  const prove_fix = {
    name: 'prove_fix',
    description: 'Check a proposed patch against the original exploit: confirm the exploit before the patch, overlay the patch on a COPY of the sources, replay the exploit, run the static verification, and search for sibling exposures. Reports FIX_VERIFIED only when the exploit is blocked in every replay and nothing was skipped. Nothing is written to the project. Runs code (and the project tests): requires confirm: true.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        finding_id: { type: 'string', minLength: 1, maxLength: 256 },
        confirm: { type: 'boolean' },
        patch: { type: 'object', additionalProperties: { type: 'string', maxLength: 500_000 }, minProperties: 1, maxProperties: 8 },
        reproducer: { type: 'object' },
      },
      required: ['finding_id', 'confirm', 'patch'],
    },
    async handler(args, ctx) {
      const l = await load(args, ctx);
      if (l.error) return l.error;
      const files = {};
      for (const [rel, content] of Object.entries(args.patch)) {
        let abs;
        try { abs = confine(ctx.sessionRoot, rel, 'patch key'); } catch (e) { return refuse(`path-escape refused: ${String(e.message).replace(ctx.sessionRoot, '<root>')}`); }
        if (isReservedWritePath(ctx.sessionRoot, abs)) return refuse(`reserved path refused: ${rel}`);
        files[rel] = String(content);
      }
      let staticVerification = null;
      try { staticVerification = l.finding.stableId ? await verifyFix({ scanRoot: ctx.sessionRoot, originalFindingStableId: l.finding.stableId, files, recordMetrics: false }) : null; } catch { staticVerification = null; }
      const sib = findSiblings({ root: ctx.sessionRoot, finding: l.finding, scanFindings: l.scan.findings || [] });
      let fp;
      try {
        fp = await verifyFixWithProof({ finding: l.finding, reproducer: l.reproducer, files, scanRoot: ctx.sessionRoot, staticVerification, siblings: sib.siblings.map((x) => ({ file: x.file, line: x.line, source: x.source })), siblingSearchTruncated: sib.truncated });
      } catch (e) { return refuse(`the fix proof could not run: ${String(e.message).slice(0, 200)}`); }
      return finish({
        ok: true, findingId: fp.findingId, state: fp.state, verified: fp.verified, completeness: fp.completeness, degradedLegs: fp.degradedLegs ?? [], legs: fp.legs,
        reason: fp.reason ?? null, incompleteStep: fp.incompleteStep ?? null, siblings: sib.siblings.slice(0, 20), siblingSearchTruncated: sib.truncated, report: formatFixProof(fp), generated: l.generated,
        note: 'The patch was not written. Apply it with apply_fix once it is verified.',
      });
    },
  };

  return { prove_finding, prove_fix };
}
