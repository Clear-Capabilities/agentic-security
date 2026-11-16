// Running a recipe's examples (verified-remediation PRD FR-11, M3-02): each positive or independent example is a real repair run, on a
// copy of the example project, with the recipe as the ONLY proposer. The finding is the scanner's own finding of the recipe's family on
// that project when the scanner reports one (its stable id lets the central verifier tell a finding the project already had from one
// the patch introduced), otherwise a declared one. Nothing here judges anything: the coordinator and its obligations do.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { planRepair, runRepair } from './coordinator.js';
import { recipeProposer } from './recipes.js';
import { familyForFinding } from './intake.js';

async function findingFor(root, entry, family) {
  try {
    const { runFullScan } = await import('../engine.js');
    const scan = await runFullScan({ fileContents: { [entry]: fs.readFileSync(path.join(root, entry), 'utf8') }, scanRoot: root, provenance: false }, () => {});
    const f = (scan.findings || []).find((x) => familyForFinding(x) === family);
    if (f) return { findingId: f.id, id: f.id, stableId: f.stableId, file: entry, cwe: f.cwe };
  } catch { /* fall through to a declared finding */ }
  return { findingId: `recipe-example:${family}:${entry}`, file: entry };
}

/** The `run` dependency `evaluateRecipe` takes, bound to an assurance configuration that enables execution. */
export function exampleRunner({ config, policy = { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 1 } } }) {
  return async ({ recipe, example, dir, planOnly }) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `recipe-${recipe.recipeId}-${example.id}-`));
    try {
      fs.cpSync(dir, root, { recursive: true });
      const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
      const finding = await findingFor(root, profile.application.entry, example.family);
      const p = planRepair({ root, finding, family: example.family, profile, profileOrigin: 'repository-file' });
      if (!p.plan) return { disposition: 'plan-failed', reasons: [...p.problems, ...p.blocked], contract: null };
      if (planOnly) return { contract: p.plan.contract };
      const r = await runRepair({ root, plan: p.plan, config, proposers: [recipeProposer(recipe)], policy });
      return {
        disposition: r.record.disposition, reasons: r.record.reasons,
        obligationDigests: Object.fromEntries(p.plan.contract.obligations.map((o) => [o.id, o.inputsDigest ?? null])),
      };
    } finally {
      try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* temporary */ }
    }
  };
}
