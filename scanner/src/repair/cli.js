// `agentic-security repair plan|run|show|resume|cancel|verify|export|recipes` (verified-remediation PRD FR-18, FR-11).
//
// Every subcommand delegates to the coordinator; none writes project files except `run --apply`, which goes through applyVerifiedFix.
// Exit codes (stable): 0 the requested operation completed (read the disposition), 1 a failed obligation or rejected repair, 2 usage or
// schema error, 3 a required prerequisite unavailable, unsupported or blocked, 4 cancelled or budget-exhausted before verification
// completed. A plan or export exiting 0 does not mean anything was verified.
import fs from 'node:fs';
import path from 'node:path';
import { digestOf } from '../posture/assurance/identity.js';
import { resolveAssuranceConfig } from '../posture/assurance/config.js';
import { stateDir } from '../posture/state-dir.js';
import { validateContract, validateRepairRecord } from './schemas.js';
import { planFromInputs } from './intake.js';
import { obligationSummary, supportFor } from './contracts.js';
import { runRepair, readRun, requestCancel, runsDir, isRunId, EXIT, validatePolicy } from './coordinator.js';
import { queueProposer } from './candidates.js';
import { usableRecipes, recipeProposer, loadRecipeLedger, allRecipes, stateOf, recipeDigest, transition, draftRecipe, evaluateRecipe } from './recipes.js';

export const USAGE = `agentic-security repair <command>
  plan    --profile <profile.json> (--finding <id> [--import <import-id>] | --family <family> --file <rel>) [--root <path>] [--out <plan.json>] [--json]
  run     --plan <plan.json> [--policy <policy.json>] [--candidates <file.json>] [--allow-execution] [--apply [--approved-by <who> --approval-reason <why>]] [--root <path>] [--json]
  show    <run-id> [--root <path>] [--json]
  resume  <run-id> [--allow-execution] [--root <path>] [--json]
  cancel  <run-id> [--root <path>]
  verify  <bundle-dir> [--root <path>] [--image <archive.tar>] [--json]
  export  <run-id> --out <directory> [--root <path>]
  artifact <run-id> --image <archive.tar> --app-dir <dir> [--allow-execution] [--root <path>] [--json]
  import  --format sarif|normalized --file <report.json> | --show <import-id> | --accept-risk <imported-id> --import <import-id> --reason <why> [--root <path>] [--json]
  recipes list|evaluate|promote|retire|rollback|draft [<recipe-id>[@<version>]] [--reason <why>] [--file <recipe.json>] [--allow-execution] [--root <path>] [--json]
families: sql-injection, object-authorization, ssrf, path-traversal, password-storage, dependency, credential, workflow
exit: 0 completed (read the disposition), 1 rejected, 2 usage, 3 blocked or prerequisite missing, 4 cancelled or budget stop`;

const out = (args, text, json) => { process.stdout.write(args.flags.json ? `${JSON.stringify(json, null, 2)}\n` : `${text}\n`); };
const err = (m) => { process.stderr.write(`agentic-security repair: ${m}\n`); };
const readJsonFile = (p) => JSON.parse(fs.readFileSync(path.resolve(String(p)), 'utf8'));

export function textOfRecord(rec) {
  const lines = [`run ${rec.runId}  contract ${rec.contractId}`, `disposition: ${rec.disposition}   completion: ${rec.completion}   application: ${rec.application}   artifact: ${rec.artifact}   environment: ${rec.environment}`, `scope: ${rec.scope}`];
  for (const c of rec.candidates || []) {
    lines.push(`  candidate ${c.candidateId || '(refused)'} round ${c.round} [${c.generator}] ${c.strategy || ''}: ${c.status}${c.scope?.totals ? `, ${c.scope.totals.files} file(s), ${c.scope.totals.editedLines} edited line(s)` : ''}`);
    for (const r of c.results || []) lines.push(`    ${r.status.padEnd(12)} ${r.obligation}: ${String(r.reason).slice(0, 160)}`);
    for (const r of c.reasons || []) lines.push(`    refused: ${r}`);
  }
  for (const x of rec.counterexamples || []) lines.push(`  counterexample (${x.obligation}): ${x.sealed ? x.message : `${x.property} ${x.request ? `${x.request.method} ${x.request.path}${x.request.body ? ` ${JSON.stringify(x.request.body)}` : ''}` : ''}${x.actor ? ` as ${x.actor}` : ''}`}`);
  if (rec.quarantined?.length) lines.push(`  quarantined checks: ${rec.quarantined.length} (see --json for each reason)`);
  if (rec.regressionGuards?.length) lines.push(`  regression guards: ${rec.regressionGuards.length} attacks the original already blocks, still required to stay blocked`);
  for (const r of rec.reasons || []) lines.push(`  note: ${r}`);
  if (rec.nextPrerequisite) lines.push(`next: ${rec.nextPrerequisite}`);
  if (rec.disposition === 'verified-for-contract') lines.push(`verified for contract ${rec.contractId} only: the declared obligations passed on this exact patch; nothing was built or deployed`);
  return lines.join('\n');
}

const exitForRecord = (rec) => ({ 'verified-for-contract': EXIT.ok, 'refuted-finding': EXIT.ok, rejected: EXIT.failed, cancelled: EXIT.cancelled }[rec.disposition] ?? (rec.completion === 'partial' && rec.reasons.some((r) => r.includes('wall budget')) ? EXIT.cancelled : EXIT.blocked));

function configFor(args, root) {
  return resolveAssuranceConfig({ scanRoot: root, env: process.env, overrides: args.flags['allow-execution'] ? { features: { 'verification-oracles': true } } : {} });
}

function supportLine(contract) {
  const s = supportFor(contract.family, contract.profile.runtime);
  return s ? `support: ${s.family} on ${s.runtime}: macOS ${s.macos}, Linux ${s.linux}${s.recipe ? `, recipe ${s.recipe}` : ', no recipe'}` : `support: ${contract.family} on ${contract.profile.runtime} has no support record`;
}

/** The recipes a run uses automatically: shipped ones not retired or rolled back, and promoted ones whose evidence is current. */
function recipeProposersFor(root, plan) {
  const u = usableRecipes(root, plan.contract.family);
  for (const n of u.notes) process.stderr.write(`agentic-security repair: ${n}\n`);
  return u.recipes.map((r) => recipeProposer(r));
}

function proposersFor(plan, candidatesFile, root) {
  const ps = [...recipeProposersFor(root, plan)];
  if (candidatesFile) {
    const c = readJsonFile(candidatesFile);
    if (!Array.isArray(c?.candidates)) throw new Error('--candidates must hold {"candidates":[{"files":{...}}]}');
    ps.push(queueProposer(c.candidates));
  }
  return ps;
}

async function cmdPlan(args, root) {
  if (!args.flags.profile) { err('plan needs --profile'); return EXIT.usage; }
  if (!args.flags.finding && !(args.flags.family && args.flags.file)) { err('plan needs --finding <id>, or --family and --file for a finding the scanner did not report'); return EXIT.usage; }
  const r = planFromInputs({ root, profilePath: path.resolve(String(args.flags.profile)), importId: args.flags.import ? String(args.flags.import) : undefined, findingId: args.flags.finding ? String(args.flags.finding) : undefined, family: args.flags.family ? String(args.flags.family) : undefined, file: args.flags.file ? String(args.flags.file) : undefined });
  if (!r.plan) { err(r.problems.length ? `the profile or contract is invalid:\n  ${r.problems.join('\n  ')}` : `blocked: ${r.blocked.join('; ')}`); return r.status === 'usage' ? EXIT.usage : EXIT.blocked; }
  const dest = args.flags.out ? path.resolve(String(args.flags.out)) : path.join(stateDir(root), 'repair', 'plans', `${r.plan.contract.contractId.replace(':', '-')}.json`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, JSON.stringify(r.plan, null, 2) + '\n');
  const summary = obligationSummary(r.plan.contract);
  out(args, [`plan ${dest}`, `contract ${r.plan.contract.contractId} (${r.plan.contract.family}), profile facts ${r.plan.contract.policyFacts[0].approval}`, ...summary.map((o) => `  ${o.required ? 'required' : 'optional'} ${o.kind.padEnd(24)} ${o.id}: ${o.scope}${o.requests !== null ? ` (${o.requests} requests, ${o.stateChecks} state checks)` : ''}`), ...(r.blocked.length ? [`blocked: ${r.blocked.join('; ')}`] : []), ...r.plan.contract.knownUnknowns.map((k) => `  unknown: ${k}`), supportLine(r.plan.contract), 'nothing was executed or applied'].join('\n'),
    { plan: dest, contractId: r.plan.contract.contractId, contractDigest: r.plan.contract.contractDigest, family: r.plan.contract.family, obligations: summary, blocked: r.blocked, knownUnknowns: r.plan.contract.knownUnknowns, support: supportFor(r.plan.contract.family, r.plan.contract.profile.runtime) });
  return r.blocked.length ? EXIT.blocked : EXIT.ok;
}

async function execute(args, root, plan, policy, proposers, extra = {}) {
  const ac = new AbortController();
  const onSig = () => ac.abort();
  process.once('SIGINT', onSig); process.once('SIGTERM', onSig);
  try {
    const apply = args.flags.apply ? { approval: args.flags['approved-by'] ? { approvedBy: String(args.flags['approved-by']), reason: String(args.flags['approval-reason'] || '') } : undefined } : null;
    const r = await runRepair({ root, plan, policy, config: configFor(args, root), proposers, signal: ac.signal, apply, ...extra,
      onEvent: args.flags.json ? undefined : (e) => { if (e.kind === 'candidate') process.stderr.write(`  judging candidate ${e.candidateId} (round ${e.round})\n`); } });
    out(args, `${textOfRecord(r.record)}\nrecord ${path.join(r.dir, 'record.json')}`, r.record);
    return r.exitCode;
  } finally { process.removeListener('SIGINT', onSig); process.removeListener('SIGTERM', onSig); }
}

async function cmdRun(args, root) {
  if (!args.flags.plan) { err('run needs --plan'); return EXIT.usage; }
  let plan; let policy = null; let proposers;
  try { plan = readJsonFile(args.flags.plan); } catch (e) { err(`the plan could not be read: ${e.message}`); return EXIT.usage; }
  if (!plan?.contract || !validateContract(plan.contract).ok) { err('the plan does not hold a valid repair contract'); return EXIT.usage; }
  if (args.flags.policy) {
    try { policy = readJsonFile(args.flags.policy); } catch (e) { err(`the policy could not be read: ${e.message}`); return EXIT.usage; }
    const v = validatePolicy(policy); if (!v.policy) { err(v.errors.join('; ')); return EXIT.usage; }
  }
  try { proposers = proposersFor(plan, args.flags.candidates, root); } catch (e) { err(e.message); return EXIT.usage; }
  return execute(args, root, plan, policy, proposers);
}

async function cmdShow(args, root) {
  const id = args._[2];
  const r = readRun(root, id);
  if (r.error) { err(r.error); return isRunId(id) ? EXIT.blocked : EXIT.usage; }
  out(args, `${textOfRecord(r.record)}${r.valid ? '' : `\nthe stored record does not validate: ${r.problems.join('; ')}`}`, { record: r.record, valid: r.valid, problems: r.problems, note: 'a stored record is history: it carries receipt digests, not live receipts, and cannot promote anything' });
  return EXIT.ok;
}

async function cmdResume(args, root) {
  const id = args._[2];
  const r = readRun(root, id);
  if (r.error) { err(r.error); return isRunId(id) ? EXIT.blocked : EXIT.usage; }
  if (r.record.completion === 'complete') { out(args, `run ${id} is complete (${r.record.disposition}); nothing to resume`, { record: r.record }); return exitForRecord(r.record); }
  for (const f of ['policy', 'budgets', 'candidates', 'model', 'apply']) if (args.flags[f]) { err(`resume cannot change --${f}: it re-runs the stored plan and policy only`); return EXIT.usage; }
  let policy = null;
  try { policy = JSON.parse(fs.readFileSync(path.join(r.dir, 'policy.json'), 'utf8')); } catch { /* the default policy */ }
  if (digestOf(policy || null) !== r.record.policyDigest && policy) { err('the stored policy does not match the record; refusing to resume'); return EXIT.blocked; }
  // the same proposers: the recipe (if the family has one) and every stored candidate, in the order they were judged
  const stored = [];
  try {
    for (const c of r.record.candidates || []) {
      if (!c.candidateId) continue;
      const cand = JSON.parse(fs.readFileSync(path.join(r.dir, 'candidates', `${c.candidateId.replace(':', '-')}.json`), 'utf8'));
      if (digestOf(cand.files) !== cand.patchDigest) { err(`stored candidate ${c.candidateId} does not match its digest`); return EXIT.blocked; }
      if (cand.generator !== 'deterministic-recipe') stored.push({ files: cand.files, strategy: cand.strategy });
    }
  } catch (e) { err(`stored candidates could not be read: ${e.message}`); return EXIT.blocked; }
  try { fs.rmSync(path.join(r.dir, 'cancel'), { force: true }); } catch { /* ignore */ }
  const proposers = [...recipeProposersFor(root, r.plan), ...(stored.length ? [queueProposer(stored, 'resumed-user-supplied')] : [])];
  return execute(args, root, r.plan, policy, proposers, { runId: id, resumedFrom: id });
}

async function cmdCancel(args, root) {
  const r = requestCancel(root, args._[2]);
  if (!r.ok) { err(r.reason); return isRunId(args._[2]) ? EXIT.blocked : EXIT.usage; }
  out(args, `cancellation requested for ${args._[2]}`, { ok: true });
  return EXIT.ok;
}

// Request header values are the profile's test credentials. They are replaced by digests in the headers AND wherever the same
// credential appears elsewhere in the contract (a seeded session table holds the token the header carries).
const redactHeaders = (contract) => {
  const creds = new Set();
  JSON.stringify(contract, (k, v) => { if (k === 'headers' && v && typeof v === 'object') for (const x of Object.values(v)) for (const part of String(x).split(/\s+/)) if (part.length >= 6) creds.add(part); return v; });
  const scrub = (s) => { let t = s; for (const c of creds) if (t.includes(c)) t = t.split(c).join(`[redacted ${digestOf(c).slice(7, 19)}]`); return t; };
  return JSON.parse(JSON.stringify(contract), (k, v) => (k === 'headers' && v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([h, x]) => [h, `[redacted ${digestOf(String(x)).slice(7, 19)}]`])) : typeof v === 'string' ? scrub(v) : v));
};

async function cmdExport(args, root) {
  const id = args._[2];
  if (!args.flags.out) { err('export needs --out <directory>'); return EXIT.usage; }
  const r = readRun(root, id);
  if (r.error) { err(r.error); return isRunId(id) ? EXIT.blocked : EXIT.usage; }
  const dest = path.resolve(String(args.flags.out));
  fs.mkdirSync(path.join(dest, 'patch'), { recursive: true });
  const files = r.record.exactPatch?.files || {};
  const patchFiles = {};
  for (const [rel, text] of Object.entries(files)) {
    if (text === null) { patchFiles[rel] = null; continue; }
    const abs = path.join(dest, 'patch', rel);
    if (!abs.startsWith(path.join(dest, 'patch') + path.sep)) { err(`refusing to export a path outside the bundle: ${rel}`); return EXIT.blocked; }
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
    patchFiles[rel] = digestOf(text);
  }
  const contract = redactHeaders(r.plan.contract);
  fs.writeFileSync(path.join(dest, 'contract.json'), JSON.stringify(contract, null, 2) + '\n');
  fs.writeFileSync(path.join(dest, 'record.json'), JSON.stringify({ ...r.record, exactPatch: r.record.exactPatch ? { ...r.record.exactPatch, files: Object.fromEntries(Object.keys(files).map((k) => [k, files[k] === null ? null : `patch/${k}`])) } : null }, null, 2) + '\n');
  const manifest = {
    schema: 'agentic-security/repair-export', schemaVersion: '1.0.0', runId: id, contractId: r.plan.contract.contractId, contractDigest: r.plan.contract.contractDigest,
    sourceDigest: r.plan.contract.sourceDigest, disposition: r.record.disposition, completion: r.record.completion, application: r.record.application, artifact: r.record.artifact, environment: r.record.environment,
    artifactDigest: r.record.source?.artifactDigest ?? null,
    patchDigest: r.record.patchDigest ?? null, patchFiles, approvalsRequired: r.plan.contract.policyFacts.filter((f) => f.approval !== 'approved').map((f) => `${f.id}: ${f.approval}`),
    rollback: 'the patch replaces whole files; the before digests in record.json name the content to restore, and an applied patch is reverted with `agentic-security undo`',
    redactions: 'request header values in the contract are replaced by digests; patch bytes are exported unchanged',
    claim: r.record.disposition !== 'verified-for-contract' ? 'not verified' : r.record.artifact === 'artifact-verified' ? `verified for contract ${r.plan.contract.contractId} only, in the source and in image ${r.record.source.artifactDigest}; staging and deployment not observed` : `verified for contract ${r.plan.contract.contractId} only; source-only, nothing built or deployed`,
  };
  fs.writeFileSync(path.join(dest, 'bundle.json'), JSON.stringify(manifest, null, 2) + '\n');
  out(args, `exported ${id} to ${dest} (${Object.keys(patchFiles).length} patched file(s)); an export does not mean the patch is verified: ${manifest.claim}`, manifest);
  return EXIT.ok;
}

/** Check an exported bundle: the patch bytes match their digests and the bundle's source matches the given root. Executes nothing. */
async function cmdVerify(args, root) {
  const dir = args._[2];
  if (!dir) { err('verify needs a bundle directory'); return EXIT.usage; }
  let m;
  try { m = JSON.parse(fs.readFileSync(path.join(path.resolve(dir), 'bundle.json'), 'utf8')); } catch (e) { err(`not a repair bundle: ${e.message}`); return EXIT.usage; }
  const problems = [];
  const files = {};
  for (const [rel, d] of Object.entries(m.patchFiles || {})) {
    if (d === null) { files[rel] = null; continue; }
    let text = null;
    try { text = fs.readFileSync(path.join(path.resolve(dir), 'patch', rel), 'utf8'); } catch { problems.push(`${rel}: missing from the bundle`); continue; }
    if (digestOf(text) !== d) problems.push(`${rel}: the patch bytes do not match their digest`);
    files[rel] = text;
  }
  if (m.patchDigest && !problems.length && digestOf(files) !== m.patchDigest) problems.push('the patch digest does not match the patch files');
  let contract = null;
  try { contract = JSON.parse(fs.readFileSync(path.join(path.resolve(dir), 'contract.json'), 'utf8')); } catch { problems.push('contract.json is missing'); }
  if (contract && contract.contractDigest !== m.contractDigest) problems.push('the contract in the bundle is not the one the manifest names');
  let artifactMatches = null;
  if (args.flags.image) {
    // AC-16.5: the bundle names the exact image it was checked against; a different image is a different artifact
    try {
      const { readImage } = await import('./artifact.js');
      const img = readImage(fs.readFileSync(path.resolve(String(args.flags.image))));
      artifactMatches = !!m.artifactDigest && img.digest === m.artifactDigest;
      if (!m.artifactDigest) problems.push('the bundle names no checked artifact');
      else if (!artifactMatches) problems.push(`the image is ${img.digest}, not the checked artifact ${m.artifactDigest}`);
    } catch (e) { problems.push(`the image could not be read: ${String(e.message).slice(0, 120)}`); }
  }
  let sourceMatches = null;
  if (contract && args.flags.root) {
    const { snapshotSource } = await import('./contracts.js');
    const snap = snapshotSource(root, { application: contract.profile.application });
    const applied = Object.keys(files).length > 0 && Object.entries(files).every(([rel, t]) => (snap.files[rel] ?? null) === t);
    sourceMatches = snap.sourceDigest === m.sourceDigest ? 'baseline' : applied ? 'patch-applied' : 'different';
    if (sourceMatches === 'different') problems.push('the source under --root is neither the source this repair was verified against nor that source with the patch applied');
  }
  const ok = problems.length === 0;
  out(args, ok ? `bundle intact: ${m.claim}${sourceMatches === 'baseline' ? '; the source under --root is the verified baseline (patch not applied)' : sourceMatches === 'patch-applied' ? '; the patched files under --root are exactly the patch' : ''}. Integrity is custody, not a re-verification: re-run the plan to re-establish evidence` : `bundle problems:\n  ${problems.join('\n  ')}`,
    { ok, problems, sourceMatches, artifactMatches, claim: m.claim, note: 'integrity establishes custody, not semantic correctness; nothing was executed' });
  return ok ? EXIT.ok : EXIT.failed;
}

// `repair recipes`: the lifecycle of repair recipes. Every change is a signed ledger record with a reason; evaluation executes the
// recipe's examples (operator-enabled execution only) and promotion needs an evaluation of the recipe exactly as it is now.
async function cmdRecipes(args, root) {
  const action = args._[2] || 'list';
  const ledger = loadRecipeLedger(root);
  const find = (ref) => {
    const [id, version] = String(ref || '').split('@');
    const all = allRecipes(ledger).filter((r) => r.recipeId === id && (!version || r.version === version));
    return all.length ? all[all.length - 1] : null;
  };
  if (action === 'list') {
    const rows = allRecipes(ledger).map((r) => ({ recipe: `${r.recipeId}@${r.version}`, family: r.supports.family, state: stateOf(ledger, r).state, digest: recipeDigest(r), origin: r.provenance?.origin || null }));
    out(args, [...(ledger.tampered ? [`the recipe ledger FAILED verification: ${ledger.tamperReason}; no recipe is used automatically`] : []), ...rows.map((x) => `${x.recipe.padEnd(34)} ${x.family.padEnd(18)} ${x.state.padEnd(12)} ${x.origin}`)].join('\n'), { recipes: rows, tampered: !!ledger.tampered, tamperReason: ledger.tamperReason || null });
    return ledger.tampered ? EXIT.blocked : EXIT.ok;
  }
  if (action === 'draft') {
    if (!args.flags.file) { err('recipes draft needs --file <recipe.json>'); return EXIT.usage; }
    const r = draftRecipe(root, readJsonFile(args.flags.file), { reason: args.flags.reason || 'drafted', actor: args.flags['approved-by'] });
    if (!r.ok) { err(r.reason); return EXIT.usage; }
    out(args, 'drafted; a draft is never used automatically until it is evaluated and promoted', { ok: true });
    return EXIT.ok;
  }
  const recipe = find(args._[3]);
  if (!recipe) { err(`no recipe ${args._[3] || '(none named)'}; see repair recipes list`); return EXIT.usage; }
  if (action === 'evaluate') {
    if (!args.flags['allow-execution']) { err('evaluating a recipe executes its example applications: pass --allow-execution'); return EXIT.blocked; }
    const { exampleRunner } = await import('./recipe-eval.js');
    // the examples ship with the source checkout (scanner/test/fixtures), next to src/ or to the bundle's dist/
    const here = path.dirname(new URL(import.meta.url).pathname);
    const repoRoot = [path.resolve(here, '..', '..'), path.resolve(here, '..')].find((d) => fs.existsSync(path.join(d, 'test', 'fixtures', 'repair'))) || path.resolve(here, '..', '..');
    const e = await evaluateRecipe(recipe, { repoRoot, run: exampleRunner({ config: configFor(args, root) }) });
    if (e.problems) { err(e.problems.join('; ')); return EXIT.usage; }
    if (e.results.some((x) => x.outcome === 'example-unavailable')) { out(args, 'the recipe\'s examples are not available in this installation (they ship with the source checkout); nothing was recorded', e); return EXIT.blocked; }
    let recorded = null;
    if (e.ok) recorded = transition(root, recipe, 'evaluated', { reason: args.flags.reason || 'every example met its expectation', evaluation: e, actor: args.flags['approved-by'] });
    out(args, [...e.results.map((x) => `${x.ok ? 'ok  ' : 'FAIL'} ${x.kind.padEnd(19)} ${x.id}: expected ${x.expect}, got ${x.outcome}`), e.ok ? (recorded?.ok ? 'recorded: evaluated' : `not recorded: ${recorded?.reason}`) : 'not recorded: an example did not meet its expectation'].join('\n'), { evaluation: e, recorded });
    return e.ok && recorded?.ok ? EXIT.ok : EXIT.failed;
  }
  const to = { promote: 'promoted', retire: 'retired', rollback: 'rolled-back' }[action];
  if (!to) { err(`unknown recipes action ${action}`); return EXIT.usage; }
  if (!args.flags.reason) { err(`recipes ${action} needs --reason <why>`); return EXIT.usage; }
  const r = transition(root, recipe, to, { reason: args.flags.reason, actor: args.flags['approved-by'] });
  if (!r.ok) { err(r.reason); return EXIT.blocked; }
  out(args, `${recipe.recipeId}@${recipe.version}: ${r.from} -> ${r.to}`, r);
  return EXIT.ok;
}

// `repair import`: external findings (SARIF 2.1.0 or the normalized format) into a signed import record. Executes nothing and writes no
// project file; an imported finding is planned with `repair plan --import <import-id> --finding <imported-id>`.
async function cmdImport(args, root) {
  const { importReport, saveImport, loadImport, decide } = await import('./import.js');
  if (args.flags.show) {
    const l = loadImport(root, String(args.flags.show));
    if (!l.record) { err(l.reason); return EXIT.blocked; }
    out(args, importText(l.record), l.record);
    return EXIT.ok;
  }
  if (args.flags['accept-risk']) {
    if (!args.flags.import) { err('--accept-risk needs --import <import-id>'); return EXIT.usage; }
    const d = decide(root, String(args.flags.import), String(args.flags['accept-risk']), { disposition: 'accepted-risk', reason: args.flags.reason, actor: args.flags['approved-by'] });
    if (!d.ok) { err(d.reason); return EXIT.usage; }
    out(args, `${args.flags['accept-risk']}: accepted risk recorded; it will not be planned for repair`, d);
    return EXIT.ok;
  }
  if (!args.flags.file || !['sarif', 'normalized'].includes(args.flags.format)) { err('import needs --format sarif|normalized and --file <report.json>'); return EXIT.usage; }
  let text;
  try { text = fs.readFileSync(path.resolve(String(args.flags.file)), 'utf8'); } catch (e) { err(`the report could not be read: ${e.message}`); return EXIT.usage; }
  const r = importReport({ root, format: args.flags.format, text, reportName: path.basename(String(args.flags.file)) });
  if (!r.ok) { err(r.problems.join('; ')); return EXIT.usage; }
  const file = saveImport(root, r.record);
  out(args, `${importText(r.record)}\nrecord ${path.relative(root, file)} (signed); nothing was executed or changed`, { ...r.record, problems: r.problems });
  return EXIT.ok;
}

function importText(rec) {
  const c = rec.counts;
  const lines = [`import ${rec.importId} (${rec.format}): ${c.results} result(s), ${c.findings} finding(s) after merging ${c.merged}, ${c.rejected} rejected, ${c.plannable} can be planned`];
  for (const f of rec.findings) lines.push(`  ${f.importedId} ${f.file}:${f.line ?? '?'} ${f.cwe || 'no CWE'} ${f.family || 'unsupported'} mapping ${f.mapping}${f.mappingReason ? ` (${f.mappingReason})` : ''} custody ${f.custody} ${f.disposition}${f.sources.length > 1 ? ` [${f.sources.length} sources]` : ''}`);
  for (const r of rec.rejected) lines.push(`  rejected ${r.tool?.name || '?'} ${r.ruleId || '?'}: ${r.reason}`);
  return lines.join('\n');
}

// `repair artifact`: does a built image contain the verified repair, and does it still meet the contract (FR-16)? Content and package
// checks need nothing else; re-running the contract's checks on the image's own files executes it, so it needs --allow-execution.
async function cmdArtifact(args, root) {
  const id = args._[2];
  const r = readRun(root, id);
  if (r.error) { err(r.error); return isRunId(id) ? EXIT.blocked : EXIT.usage; }
  if (!args.flags.image || !args.flags['app-dir']) { err('artifact needs --image <archive.tar> and --app-dir <dir> (where the application lives inside the image)'); return EXIT.usage; }
  if (r.record.disposition !== 'verified-for-contract' || !r.record.exactPatch) { err(`run ${id} has no verified patch to look for (disposition ${r.record.disposition})`); return EXIT.blocked; }
  const { readImage, compareArtifact, rerunOnArtifact, artifactVerdict } = await import('./artifact.js');
  let image;
  try { image = readImage(fs.readFileSync(path.resolve(String(args.flags.image)))); } catch (e) { err(`the image could not be read: ${String(e.message).slice(0, 200)}`); return EXIT.usage; }
  const comparison = compareArtifact({ record: r.record, plan: r.plan, image, appDir: args.flags['app-dir'] });
  let checks = [];
  if (args.flags['allow-execution'] && !comparison.problems.length) checks = await rerunOnArtifact({ record: r.record, plan: r.plan, image, appDir: args.flags['app-dir'], config: configFor(args, root) });
  const v = artifactVerdict({ image, appDir: args.flags['app-dir'], comparison, checks });
  const updated = { ...r.record, artifact: v.artifact, source: v.source };
  if (!args.flags['allow-execution'] && !comparison.problems.length) updated.source.problems.push('the contract checks were not re-run on the artifact (pass --allow-execution)');
  const valid = validateRepairRecord(updated);
  if (!valid.ok) { err(`the updated record failed its schema: ${valid.errors.map((e) => e.message).join('; ')}`); return EXIT.blocked; }
  fs.writeFileSync(path.join(r.dir, 'record.json'), `${JSON.stringify(updated, null, 2)}\n`);
  out(args, [`artifact ${image.digest}: ${v.artifact}`, ...v.source.files.map((f) => `  ${f.state.padEnd(10)} ${f.file}`), ...v.source.packages.map((p) => `  ${p.state.padEnd(10)} ${p.path}@${p.version}`), ...v.source.checks.map((c) => `  ${c.status.padEnd(10)} ${c.obligation} on the artifact`), ...v.source.problems.map((p) => `  problem: ${p}`), 'staging and deployment are not observed'].join('\n'), { artifact: v.artifact, source: v.source });
  return v.artifact === 'artifact-verified' ? EXIT.ok : v.artifact === 'artifact-mismatch' ? EXIT.failed : EXIT.blocked;
}

export async function cmdRepair(args, root) {
  const sub = args._[1];
  const handlers = { plan: cmdPlan, run: cmdRun, show: cmdShow, resume: cmdResume, cancel: cmdCancel, export: cmdExport, verify: cmdVerify, recipes: cmdRecipes, import: cmdImport, artifact: cmdArtifact };
  if (!handlers[sub] || args.flags.help) { (handlers[sub] ? process.stdout : process.stderr).write(`${USAGE}\n`); return args.flags.help ? EXIT.ok : EXIT.usage; }
  try { return await handlers[sub](args, root); } catch (e) { err(String(e?.message || e)); return EXIT.blocked; }
}

export { runsDir };
