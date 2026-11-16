// repair-tools.js: the MCP surface for contract-driven repair (verified-remediation PRD AC-04.5, FR-18).
//
// One READ-ONLY tool, `repair_plan`: build the repair contract for a finding from the signed scan (or a declared family and file) and an
// application profile, both inside the session root, and return its identity and obligations. It executes nothing and writes nothing.
// The same function the CLI's `repair plan` calls (`repair/intake.js` `planFromInputs`) does the work, so the two surfaces derive the
// same contract and the same obligations from the same inputs.
//
// Running a repair (which executes candidate code in the trust boundary) is not offered through MCP in this milestone: it stays an
// operator command (`agentic-security repair run --allow-execution`), so no MCP client can enable execution or bypass the obligations.
// Request header values in the returned obligations are replaced by digests (a profile's test credentials are not echoed).
import { planFromInputs } from '../repair/intake.js';
import { obligationSummary } from '../repair/contracts.js';
import { digestOf } from '../posture/assurance/identity.js';

export function makeRepairTools({ confine, META }) {
  const repair_plan = {
    name: 'repair_plan',
    description: 'Build the repair contract for one finding: the required obligations (attack requests that must reach no forbidden effect, legitimate requests that must keep working, the central verifier), the edit scope and the known unknowns, from an application profile. Read-only: executes and writes nothing. Running the repair is an operator CLI command (repair run --allow-execution).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        profile_file: { type: 'string', minLength: 1, maxLength: 512 },
        finding_id: { type: 'string', minLength: 1, maxLength: 200 },
        family: { type: 'string', enum: ['sql-injection', 'object-authorization', 'ssrf', 'path-traversal', 'password-storage'] },
        file: { type: 'string', minLength: 1, maxLength: 512 },
      },
      required: ['profile_file'],
    },
    async handler(args, ctx) {
      let profilePath;
      try { profilePath = confine(ctx.sessionRoot, args.profile_file, 'profile_file'); } catch (e) {
        return { _meta: META, ok: false, status: 'rejected', reason: `path refused: ${String(e.message).replace(ctx.sessionRoot, '<root>')}` };
      }
      if (!args.finding_id && !(args.family && args.file)) return { _meta: META, ok: false, status: 'rejected', reason: 'name finding_id, or family and file' };
      const r = planFromInputs({ root: ctx.sessionRoot, profilePath, findingId: args.finding_id, family: args.family, file: args.file });
      if (!r.plan) return { _meta: META, ok: false, status: r.status, reason: [...r.problems, ...r.blocked].join('; ').replace(ctx.sessionRoot, '<root>').slice(0, 800) };
      const c = r.plan.contract;
      return {
        _meta: META, ok: true, status: r.status,
        contractId: c.contractId, contractDigest: c.contractDigest, family: c.family, findingRefs: c.findingRefs,
        obligations: obligationSummary(c), editScope: c.editScope, policyFacts: c.policyFacts.map((f) => ({ id: f.id, origin: f.origin, approval: f.approval })),
        knownUnknowns: c.knownUnknowns, blocked: r.blocked,
        actors: (c.profile.actorMatrix || []).length ? c.profile.actorMatrix : undefined,
        headerDigest: digestOf(r.plan.actors),
        note: 'a plan executes nothing; a repair is verified only by `agentic-security repair run`, for this contract only',
      };
    },
  };
  return { repair_plan };
}
