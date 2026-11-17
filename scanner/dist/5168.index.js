export const id = 5168;
export const ids = [5168];
export const modules = {

/***/ 85168:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   USAGE: () => (/* binding */ USAGE),
/* harmony export */   cmdRepair: () => (/* binding */ cmdRepair),
/* harmony export */   runsDir: () => (/* reexport safe */ _coordinator_js__WEBPACK_IMPORTED_MODULE_8__.AM),
/* harmony export */   textOfRecord: () => (/* binding */ textOfRecord)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(41877);
/* harmony import */ var _posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(90385);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(31174);
/* harmony import */ var _schemas_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(68962);
/* harmony import */ var _intake_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(30356);
/* harmony import */ var _contracts_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(20771);
/* harmony import */ var _coordinator_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(50382);
/* harmony import */ var _candidates_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(4370);
/* harmony import */ var _recipes_js__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(60681);
// `agentic-security repair plan|run|show|resume|cancel|verify|export|recipes` (verified-remediation PRD FR-18, FR-11).
//
// Every subcommand delegates to the coordinator; none writes project files except `run --apply`, which goes through applyVerifiedFix.
// Exit codes (stable): 0 the requested operation completed (read the disposition), 1 a failed obligation or rejected repair, 2 usage or
// schema error, 3 a required prerequisite unavailable, unsupported or blocked, 4 cancelled or budget-exhausted before verification
// completed. A plan or export exiting 0 does not mean anything was verified.












const USAGE = `agentic-security repair <command>
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
families: sql-injection, object-authorization, ssrf, path-traversal, password-storage, dependency, credential, workflow, infrastructure
exit: 0 completed (read the disposition), 1 rejected, 2 usage, 3 blocked or prerequisite missing, 4 cancelled or budget stop`;

const out = (args, text, json) => { process.stdout.write(args.flags.json ? `${JSON.stringify(json, null, 2)}\n` : `${text}\n`); };
const err = (m) => { process.stderr.write(`agentic-security repair: ${m}\n`); };
const readJsonFile = (p) => JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(p)), 'utf8'));

function textOfRecord(rec) {
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

const exitForRecord = (rec) => ({ 'verified-for-contract': _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok, 'refuted-finding': _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok, rejected: _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.failed, cancelled: _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.cancelled }[rec.disposition] ?? (rec.completion === 'partial' && rec.reasons.some((r) => r.includes('wall budget')) ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.cancelled : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked));

function configFor(args, root) {
  return (0,_posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_3__.resolveAssuranceConfig)({ scanRoot: root, env: process.env, overrides: args.flags['allow-execution'] ? { features: { 'verification-oracles': true } } : {} });
}

function supportLine(contract) {
  const s = (0,_contracts_js__WEBPACK_IMPORTED_MODULE_7__/* .supportFor */ .l3)(contract.family, contract.profile.runtime);
  return s ? `support: ${s.family} on ${s.runtime}: macOS ${s.macos}, Linux ${s.linux}${s.recipe ? `, recipe ${s.recipe}` : ', no recipe'}` : `support: ${contract.family} on ${contract.profile.runtime} has no support record`;
}

/** The recipes a run uses automatically: shipped ones not retired or rolled back, and promoted ones whose evidence is current. */
function recipeProposersFor(root, plan) {
  const u = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .usableRecipes */ .YD)(root, plan.contract.family);
  for (const n of u.notes) process.stderr.write(`agentic-security repair: ${n}\n`);
  return u.recipes.map((r) => (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .recipeProposer */ .Hi)(r));
}

function proposersFor(plan, candidatesFile, root) {
  const ps = [...recipeProposersFor(root, plan)];
  if (candidatesFile) {
    const c = readJsonFile(candidatesFile);
    if (!Array.isArray(c?.candidates)) throw new Error('--candidates must hold {"candidates":[{"files":{...}}]}');
    ps.push((0,_candidates_js__WEBPACK_IMPORTED_MODULE_9__/* .queueProposer */ .uI)(c.candidates));
  }
  return ps;
}

async function cmdPlan(args, root) {
  if (!args.flags.profile) { err('plan needs --profile'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (!args.flags.finding && !(args.flags.family && args.flags.file)) { err('plan needs --finding <id>, or --family and --file for a finding the scanner did not report'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const r = (0,_intake_js__WEBPACK_IMPORTED_MODULE_6__/* .planFromInputs */ .Zn)({ root, profilePath: node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.profile)), importId: args.flags.import ? String(args.flags.import) : undefined, findingId: args.flags.finding ? String(args.flags.finding) : undefined, family: args.flags.family ? String(args.flags.family) : undefined, file: args.flags.file ? String(args.flags.file) : undefined });
  if (!r.plan) { err(r.problems.length ? `the profile or contract is invalid:\n  ${r.problems.join('\n  ')}` : `blocked: ${r.blocked.join('; ')}`); return r.status === 'usage' ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  const dest = args.flags.out ? node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.out)) : node_path__WEBPACK_IMPORTED_MODULE_1__.join((0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__/* .stateDir */ .Pn)(root), 'repair', 'plans', `${r.plan.contract.contractId.replace(':', '-')}.json`);
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(dest), { recursive: true });
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(dest, JSON.stringify(r.plan, null, 2) + '\n');
  const summary = (0,_contracts_js__WEBPACK_IMPORTED_MODULE_7__/* .obligationSummary */ .NL)(r.plan.contract);
  out(args, [`plan ${dest}`, `contract ${r.plan.contract.contractId} (${r.plan.contract.family}), profile facts ${r.plan.contract.policyFacts[0].approval}`, ...summary.map((o) => `  ${o.required ? 'required' : 'optional'} ${o.kind.padEnd(24)} ${o.id}: ${o.scope}${o.requests !== null ? ` (${o.requests} requests, ${o.stateChecks} state checks)` : ''}`), ...(r.blocked.length ? [`blocked: ${r.blocked.join('; ')}`] : []), ...r.plan.contract.knownUnknowns.map((k) => `  unknown: ${k}`), supportLine(r.plan.contract), 'nothing was executed or applied'].join('\n'),
    { plan: dest, contractId: r.plan.contract.contractId, contractDigest: r.plan.contract.contractDigest, family: r.plan.contract.family, obligations: summary, blocked: r.blocked, knownUnknowns: r.plan.contract.knownUnknowns, support: (0,_contracts_js__WEBPACK_IMPORTED_MODULE_7__/* .supportFor */ .l3)(r.plan.contract.family, r.plan.contract.profile.runtime) });
  return r.blocked.length ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
}

async function execute(args, root, plan, policy, proposers, extra = {}) {
  const ac = new AbortController();
  const onSig = () => ac.abort();
  process.once('SIGINT', onSig); process.once('SIGTERM', onSig);
  try {
    const apply = args.flags.apply ? { approval: args.flags['approved-by'] ? { approvedBy: String(args.flags['approved-by']), reason: String(args.flags['approval-reason'] || '') } : undefined } : null;
    const r = await (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .runRepair */ .Lq)({ root, plan, policy, config: configFor(args, root), proposers, signal: ac.signal, apply, ...extra,
      onEvent: args.flags.json ? undefined : (e) => { if (e.kind === 'candidate') process.stderr.write(`  judging candidate ${e.candidateId} (round ${e.round})\n`); } });
    out(args, `${textOfRecord(r.record)}\nrecord ${node_path__WEBPACK_IMPORTED_MODULE_1__.join(r.dir, 'record.json')}`, r.record);
    return r.exitCode;
  } finally { process.removeListener('SIGINT', onSig); process.removeListener('SIGTERM', onSig); }
}

async function cmdRun(args, root) {
  if (!args.flags.plan) { err('run needs --plan'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  let plan; let policy = null; let proposers;
  try { plan = readJsonFile(args.flags.plan); } catch (e) { err(`the plan could not be read: ${e.message}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (!plan?.contract || !(0,_schemas_js__WEBPACK_IMPORTED_MODULE_5__/* .validateContract */ .T7)(plan.contract).ok) { err('the plan does not hold a valid repair contract'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (args.flags.policy) {
    try { policy = readJsonFile(args.flags.policy); } catch (e) { err(`the policy could not be read: ${e.message}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
    const v = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .validatePolicy */ .tE)(policy); if (!v.policy) { err(v.errors.join('; ')); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  }
  try { proposers = proposersFor(plan, args.flags.candidates, root); } catch (e) { err(e.message); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  return execute(args, root, plan, policy, proposers);
}

async function cmdShow(args, root) {
  const id = args._[2];
  const r = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .readRun */ .cI)(root, id);
  if (r.error) { err(r.error); return (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .isRunId */ .Pk)(id) ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  out(args, `${textOfRecord(r.record)}${r.valid ? '' : `\nthe stored record does not validate: ${r.problems.join('; ')}`}`, { record: r.record, valid: r.valid, problems: r.problems, note: 'a stored record is history: it carries receipt digests, not live receipts, and cannot promote anything' });
  return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
}

async function cmdResume(args, root) {
  const id = args._[2];
  const r = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .readRun */ .cI)(root, id);
  if (r.error) { err(r.error); return (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .isRunId */ .Pk)(id) ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (r.record.completion === 'complete') { out(args, `run ${id} is complete (${r.record.disposition}); nothing to resume`, { record: r.record }); return exitForRecord(r.record); }
  for (const f of ['policy', 'budgets', 'candidates', 'model', 'apply']) if (args.flags[f]) { err(`resume cannot change --${f}: it re-runs the stored plan and policy only`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  let policy = null;
  try { policy = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(r.dir, 'policy.json'), 'utf8')); } catch { /* the default policy */ }
  if ((0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(policy || null) !== r.record.policyDigest && policy) { err('the stored policy does not match the record; refusing to resume'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  // the same proposers: the recipe (if the family has one) and every stored candidate, in the order they were judged
  const stored = [];
  try {
    for (const c of r.record.candidates || []) {
      if (!c.candidateId) continue;
      const cand = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(r.dir, 'candidates', `${c.candidateId.replace(':', '-')}.json`), 'utf8'));
      if ((0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(cand.files) !== cand.patchDigest) { err(`stored candidate ${c.candidateId} does not match its digest`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
      if (cand.generator !== 'deterministic-recipe') stored.push({ files: cand.files, strategy: cand.strategy });
    }
  } catch (e) { err(`stored candidates could not be read: ${e.message}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(r.dir, 'cancel'), { force: true }); } catch { /* ignore */ }
  const proposers = [...recipeProposersFor(root, r.plan), ...(stored.length ? [(0,_candidates_js__WEBPACK_IMPORTED_MODULE_9__/* .queueProposer */ .uI)(stored, 'resumed-user-supplied')] : [])];
  return execute(args, root, r.plan, policy, proposers, { runId: id, resumedFrom: id });
}

async function cmdCancel(args, root) {
  const r = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .requestCancel */ .AX)(root, args._[2]);
  if (!r.ok) { err(r.reason); return (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .isRunId */ .Pk)(args._[2]) ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  out(args, `cancellation requested for ${args._[2]}`, { ok: true });
  return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
}

// Request header values are the profile's test credentials. They are replaced by digests in the headers AND wherever the same
// credential appears elsewhere in the contract (a seeded session table holds the token the header carries).
const redactHeaders = (contract) => {
  const creds = new Set();
  JSON.stringify(contract, (k, v) => { if (k === 'headers' && v && typeof v === 'object') for (const x of Object.values(v)) for (const part of String(x).split(/\s+/)) if (part.length >= 6) creds.add(part); return v; });
  const scrub = (s) => { let t = s; for (const c of creds) if (t.includes(c)) t = t.split(c).join(`[redacted ${(0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(c).slice(7, 19)}]`); return t; };
  return JSON.parse(JSON.stringify(contract), (k, v) => (k === 'headers' && v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([h, x]) => [h, `[redacted ${(0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(String(x)).slice(7, 19)}]`])) : typeof v === 'string' ? scrub(v) : v));
};

async function cmdExport(args, root) {
  const id = args._[2];
  if (!args.flags.out) { err('export needs --out <directory>'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const r = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .readRun */ .cI)(root, id);
  if (r.error) { err(r.error); return (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .isRunId */ .Pk)(id) ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const dest = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.out));
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dest, 'patch'), { recursive: true });
  const files = r.record.exactPatch?.files || {};
  const patchFiles = {};
  for (const [rel, text] of Object.entries(files)) {
    if (text === null) { patchFiles[rel] = null; continue; }
    const abs = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dest, 'patch', rel);
    if (!abs.startsWith(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dest, 'patch') + node_path__WEBPACK_IMPORTED_MODULE_1__.sep)) { err(`refusing to export a path outside the bundle: ${rel}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(abs), { recursive: true });
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(abs, text);
    patchFiles[rel] = (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(text);
  }
  const contract = redactHeaders(r.plan.contract);
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dest, 'contract.json'), JSON.stringify(contract, null, 2) + '\n');
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dest, 'record.json'), JSON.stringify({ ...r.record, exactPatch: r.record.exactPatch ? { ...r.record.exactPatch, files: Object.fromEntries(Object.keys(files).map((k) => [k, files[k] === null ? null : `patch/${k}`])) } : null }, null, 2) + '\n');
  const manifest = {
    schema: 'agentic-security/repair-export', schemaVersion: '1.0.0', runId: id, contractId: r.plan.contract.contractId, contractDigest: r.plan.contract.contractDigest,
    sourceDigest: r.plan.contract.sourceDigest, disposition: r.record.disposition, completion: r.record.completion, application: r.record.application, artifact: r.record.artifact, environment: r.record.environment,
    artifactDigest: r.record.source?.artifactDigest ?? null,
    patchDigest: r.record.patchDigest ?? null, patchFiles, approvalsRequired: r.plan.contract.policyFacts.filter((f) => f.approval !== 'approved').map((f) => `${f.id}: ${f.approval}`),
    rollback: 'the patch replaces whole files; the before digests in record.json name the content to restore, and an applied patch is reverted with `agentic-security undo`',
    redactions: 'request header values in the contract are replaced by digests; patch bytes are exported unchanged',
    claim: r.record.disposition !== 'verified-for-contract' ? 'not verified' : r.record.artifact === 'artifact-verified' ? `verified for contract ${r.plan.contract.contractId} only, in the source and in image ${r.record.source.artifactDigest}; staging and deployment not observed` : `verified for contract ${r.plan.contract.contractId} only; source-only, nothing built or deployed`,
  };
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dest, 'bundle.json'), JSON.stringify(manifest, null, 2) + '\n');
  out(args, `exported ${id} to ${dest} (${Object.keys(patchFiles).length} patched file(s)); an export does not mean the patch is verified: ${manifest.claim}`, manifest);
  return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
}

/** Check an exported bundle: the patch bytes match their digests and the bundle's source matches the given root. Executes nothing. */
async function cmdVerify(args, root) {
  const dir = args._[2];
  if (!dir) { err('verify needs a bundle directory'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  let m;
  try { m = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(dir), 'bundle.json'), 'utf8')); } catch (e) { err(`not a repair bundle: ${e.message}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const problems = [];
  const files = {};
  for (const [rel, d] of Object.entries(m.patchFiles || {})) {
    if (d === null) { files[rel] = null; continue; }
    let text = null;
    try { text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(dir), 'patch', rel), 'utf8'); } catch { problems.push(`${rel}: missing from the bundle`); continue; }
    if ((0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(text) !== d) problems.push(`${rel}: the patch bytes do not match their digest`);
    files[rel] = text;
  }
  if (m.patchDigest && !problems.length && (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_2__/* .digestOf */ .ol)(files) !== m.patchDigest) problems.push('the patch digest does not match the patch files');
  let contract = null;
  try { contract = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(dir), 'contract.json'), 'utf8')); } catch { problems.push('contract.json is missing'); }
  if (contract && contract.contractDigest !== m.contractDigest) problems.push('the contract in the bundle is not the one the manifest names');
  let artifactMatches = null;
  if (args.flags.image) {
    // AC-16.5: the bundle names the exact image it was checked against; a different image is a different artifact
    try {
      const { readImage } = await __webpack_require__.e(/* import() */ 4410).then(__webpack_require__.bind(__webpack_require__, 24410));
      const img = readImage(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.image))));
      artifactMatches = !!m.artifactDigest && img.digest === m.artifactDigest;
      if (!m.artifactDigest) problems.push('the bundle names no checked artifact');
      else if (!artifactMatches) problems.push(`the image is ${img.digest}, not the checked artifact ${m.artifactDigest}`);
    } catch (e) { problems.push(`the image could not be read: ${String(e.message).slice(0, 120)}`); }
  }
  let sourceMatches = null;
  if (contract && args.flags.root) {
    const { snapshotSource } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 20771));
    const snap = snapshotSource(root, { application: contract.profile.application });
    const applied = Object.keys(files).length > 0 && Object.entries(files).every(([rel, t]) => (snap.files[rel] ?? null) === t);
    sourceMatches = snap.sourceDigest === m.sourceDigest ? 'baseline' : applied ? 'patch-applied' : 'different';
    if (sourceMatches === 'different') problems.push('the source under --root is neither the source this repair was verified against nor that source with the patch applied');
  }
  const ok = problems.length === 0;
  out(args, ok ? `bundle intact: ${m.claim}${sourceMatches === 'baseline' ? '; the source under --root is the verified baseline (patch not applied)' : sourceMatches === 'patch-applied' ? '; the patched files under --root are exactly the patch' : ''}. Integrity is custody, not a re-verification: re-run the plan to re-establish evidence` : `bundle problems:\n  ${problems.join('\n  ')}`,
    { ok, problems, sourceMatches, artifactMatches, claim: m.claim, note: 'integrity establishes custody, not semantic correctness; nothing was executed' });
  return ok ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.failed;
}

// `repair recipes`: the lifecycle of repair recipes. Every change is a signed ledger record with a reason; evaluation executes the
// recipe's examples (operator-enabled execution only) and promotion needs an evaluation of the recipe exactly as it is now.
async function cmdRecipes(args, root) {
  const action = args._[2] || 'list';
  const ledger = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .loadRecipeLedger */ .eB)(root);
  const find = (ref) => {
    const [id, version] = String(ref || '').split('@');
    const all = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .allRecipes */ .$g)(ledger).filter((r) => r.recipeId === id && (!version || r.version === version));
    return all.length ? all[all.length - 1] : null;
  };
  if (action === 'list') {
    const rows = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .allRecipes */ .$g)(ledger).map((r) => ({ recipe: `${r.recipeId}@${r.version}`, family: r.supports.family, state: (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .stateOf */ .L4)(ledger, r).state, digest: (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .recipeDigest */ .dF)(r), origin: r.provenance?.origin || null }));
    out(args, [...(ledger.tampered ? [`the recipe ledger FAILED verification: ${ledger.tamperReason}; no recipe is used automatically`] : []), ...rows.map((x) => `${x.recipe.padEnd(34)} ${x.family.padEnd(18)} ${x.state.padEnd(12)} ${x.origin}`)].join('\n'), { recipes: rows, tampered: !!ledger.tampered, tamperReason: ledger.tamperReason || null });
    return ledger.tampered ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
  }
  if (action === 'draft') {
    if (!args.flags.file) { err('recipes draft needs --file <recipe.json>'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
    const r = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .draftRecipe */ .kg)(root, readJsonFile(args.flags.file), { reason: args.flags.reason || 'drafted', actor: args.flags['approved-by'] });
    if (!r.ok) { err(r.reason); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
    out(args, 'drafted; a draft is never used automatically until it is evaluated and promoted', { ok: true });
    return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
  }
  const recipe = find(args._[3]);
  if (!recipe) { err(`no recipe ${args._[3] || '(none named)'}; see repair recipes list`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (action === 'evaluate') {
    if (!args.flags['allow-execution']) { err('evaluating a recipe executes its example applications: pass --allow-execution'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
    const { exampleRunner } = await __webpack_require__.e(/* import() */ 5117).then(__webpack_require__.bind(__webpack_require__, 35117));
    // the examples ship with the source checkout (scanner/test/fixtures), next to src/ or to the bundle's dist/
    const here = node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(new URL(import.meta.url).pathname);
    const repoRoot = [node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(here, '..', '..'), node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(here, '..')].find((d) => node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(d, 'test', 'fixtures', 'repair'))) || node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(here, '..', '..');
    const e = await (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .evaluateRecipe */ ._2)(recipe, { repoRoot, run: exampleRunner({ config: configFor(args, root) }) });
    if (e.problems) { err(e.problems.join('; ')); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
    if (e.results.some((x) => x.outcome === 'example-unavailable')) { out(args, 'the recipe\'s examples are not available in this installation (they ship with the source checkout); nothing was recorded', e); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
    let recorded = null;
    if (e.ok) recorded = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .transition */ .kY)(root, recipe, 'evaluated', { reason: args.flags.reason || 'every example met its expectation', evaluation: e, actor: args.flags['approved-by'] });
    out(args, [...e.results.map((x) => `${x.ok ? 'ok  ' : 'FAIL'} ${x.kind.padEnd(19)} ${x.id}: expected ${x.expect}, got ${x.outcome}`), e.ok ? (recorded?.ok ? 'recorded: evaluated' : `not recorded: ${recorded?.reason}`) : 'not recorded: an example did not meet its expectation'].join('\n'), { evaluation: e, recorded });
    return e.ok && recorded?.ok ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.failed;
  }
  const to = { promote: 'promoted', retire: 'retired', rollback: 'rolled-back' }[action];
  if (!to) { err(`unknown recipes action ${action}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (!args.flags.reason) { err(`recipes ${action} needs --reason <why>`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const r = (0,_recipes_js__WEBPACK_IMPORTED_MODULE_10__/* .transition */ .kY)(root, recipe, to, { reason: args.flags.reason, actor: args.flags['approved-by'] });
  if (!r.ok) { err(r.reason); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  out(args, `${recipe.recipeId}@${recipe.version}: ${r.from} -> ${r.to}`, r);
  return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
}

// `repair import`: external findings (SARIF 2.1.0 or the normalized format) into a signed import record. Executes nothing and writes no
// project file; an imported finding is planned with `repair plan --import <import-id> --finding <imported-id>`.
async function cmdImport(args, root) {
  const { importReport, saveImport, loadImport, decide } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 46777));
  if (args.flags.show) {
    const l = loadImport(root, String(args.flags.show));
    if (!l.record) { err(l.reason); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
    out(args, importText(l.record), l.record);
    return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
  }
  if (args.flags['accept-risk']) {
    if (!args.flags.import) { err('--accept-risk needs --import <import-id>'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
    const d = decide(root, String(args.flags.import), String(args.flags['accept-risk']), { disposition: 'accepted-risk', reason: args.flags.reason, actor: args.flags['approved-by'] });
    if (!d.ok) { err(d.reason); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
    out(args, `${args.flags['accept-risk']}: accepted risk recorded; it will not be planned for repair`, d);
    return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
  }
  if (!args.flags.file || !['sarif', 'normalized'].includes(args.flags.format)) { err('import needs --format sarif|normalized and --file <report.json>'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  let text;
  try { text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.file)), 'utf8'); } catch (e) { err(`the report could not be read: ${e.message}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const r = importReport({ root, format: args.flags.format, text, reportName: node_path__WEBPACK_IMPORTED_MODULE_1__.basename(String(args.flags.file)) });
  if (!r.ok) { err(r.problems.join('; ')); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const file = saveImport(root, r.record);
  out(args, `${importText(r.record)}\nrecord ${node_path__WEBPACK_IMPORTED_MODULE_1__.relative(root, file)} (signed); nothing was executed or changed`, { ...r.record, problems: r.problems });
  return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok;
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
  const r = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .readRun */ .cI)(root, id);
  if (r.error) { err(r.error); return (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .isRunId */ .Pk)(id) ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (!args.flags.image || !args.flags['app-dir']) { err('artifact needs --image <archive.tar> and --app-dir <dir> (where the application lives inside the image)'); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  if (r.record.disposition !== 'verified-for-contract' || !r.record.exactPatch) { err(`run ${id} has no verified patch to look for (disposition ${r.record.disposition})`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  const { readImage, compareArtifact, rerunOnArtifact, artifactVerdict } = await __webpack_require__.e(/* import() */ 4410).then(__webpack_require__.bind(__webpack_require__, 24410));
  let image;
  try { image = readImage(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.image)))); } catch (e) { err(`the image could not be read: ${String(e.message).slice(0, 200)}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  const comparison = compareArtifact({ record: r.record, plan: r.plan, image, appDir: args.flags['app-dir'] });
  let checks = [];
  if (args.flags['allow-execution'] && !comparison.problems.length) checks = await rerunOnArtifact({ record: r.record, plan: r.plan, image, appDir: args.flags['app-dir'], config: configFor(args, root) });
  const v = artifactVerdict({ image, appDir: args.flags['app-dir'], comparison, checks });
  const updated = { ...r.record, artifact: v.artifact, source: v.source };
  if (!args.flags['allow-execution'] && !comparison.problems.length) updated.source.problems.push('the contract checks were not re-run on the artifact (pass --allow-execution)');
  const valid = (0,_schemas_js__WEBPACK_IMPORTED_MODULE_5__/* .validateRepairRecord */ .bY)(updated);
  if (!valid.ok) { err(`the updated record failed its schema: ${valid.errors.map((e) => e.message).join('; ')}`); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(r.dir, 'record.json'), `${JSON.stringify(updated, null, 2)}\n`);
  out(args, [`artifact ${image.digest}: ${v.artifact}`, ...v.source.files.map((f) => `  ${f.state.padEnd(10)} ${f.file}`), ...v.source.packages.map((p) => `  ${p.state.padEnd(10)} ${p.path}@${p.version}`), ...v.source.checks.map((c) => `  ${c.status.padEnd(10)} ${c.obligation} on the artifact`), ...v.source.problems.map((p) => `  problem: ${p}`), 'staging and deployment are not observed'].join('\n'), { artifact: v.artifact, source: v.source });
  return v.artifact === 'artifact-verified' ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok : v.artifact === 'artifact-mismatch' ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.failed : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked;
}

async function cmdRepair(args, root) {
  const sub = args._[1];
  const handlers = { plan: cmdPlan, run: cmdRun, show: cmdShow, resume: cmdResume, cancel: cmdCancel, export: cmdExport, verify: cmdVerify, recipes: cmdRecipes, import: cmdImport, artifact: cmdArtifact };
  if (!handlers[sub] || args.flags.help) { (handlers[sub] ? process.stdout : process.stderr).write(`${USAGE}\n`); return args.flags.help ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  try { return await handlers[sub](args, root); } catch (e) { err(String(e?.message || e)); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
}




/***/ }),

/***/ 60681:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   $g: () => (/* binding */ allRecipes),
/* harmony export */   Hi: () => (/* binding */ recipeProposer),
/* harmony export */   L4: () => (/* binding */ stateOf),
/* harmony export */   YD: () => (/* binding */ usableRecipes),
/* harmony export */   _2: () => (/* binding */ evaluateRecipe),
/* harmony export */   dF: () => (/* binding */ recipeDigest),
/* harmony export */   eB: () => (/* binding */ loadRecipeLedger),
/* harmony export */   kY: () => (/* binding */ transition),
/* harmony export */   kg: () => (/* binding */ draftRecipe)
/* harmony export */ });
/* unused harmony exports RECIPE_SCHEMA, RECIPE_LEDGER_SCHEMA, RECIPE_STATES, containPathTransform, TRANSFORMS, SHIPPED_RECIPES, validateRecipe, applicability */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(76760);
/* harmony import */ var _posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(41877);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(31174);
/* harmony import */ var _posture_integrity_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(71130);
/* harmony import */ var _candidates_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(4370);
// Repair recipes (verified-remediation PRD FR-11, section 6.6, M3-01, M3-02): a structural transformation with preconditions, a
// declared scope and its own evidence, under a signed, reviewable lifecycle.
//
// What a recipe is here. The TRANSFORMATION is code shipped with the scanner and registered by id below; a recipe document names one,
// declares where it applies (family, language, runtime and driver ranges), the preconditions it checks, the obligations a candidate it
// produces must pass, its examples (positive, safe-negative, unsupported-version, and independent held-out ones) and its
// contraindications. A document cannot carry code or a command: it can only narrow a registered transformation (fewer files, an extra
// contraindication), never widen it (AC-11.3). Every candidate a recipe proposes still goes through the scope gate and every obligation
// of the contract; a recipe is a proposer, never a verifier ("a merged PR alone is not evidence").
//
// Identity. `recipeDigest` covers the document AND the source text of its transformation, so a changed transformation is a different
// recipe. An evaluation records the recipe digest, every example fixture's digest and every obligation digest of the contract each
// example was judged against; promotion records the evaluation digest. A recipe is used automatically only when its latest promotion's
// evidence still matches what the code and fixtures are now (AC-11.4).
//
// Lifecycle. Shipped recipes start `shipped` (evaluated by this repository's own recipe gate, `bench/repair/recipes.mjs`) and are used
// automatically until the operator retires or rolls one back. An operator's draft starts `draft` and is used automatically only once
// `promoted`. Retiring or rolling back stops new automatic use; the ledger keeps every past record (AC-11.6). The ledger is append-only,
// hash-chained and signed with the per-install key, like the rule compiler's; a ledger that fails either check refuses every change.
//
// Not claimed: no recipe is learned from examples. The two transformations were written by hand; "generalization" below means a
// transformation verified on a held-out project it was not developed against, authored by the same people (synthetic evidence).









const RECIPE_SCHEMA = 'agentic-security/repair-recipe';
const RECIPE_LEDGER_SCHEMA = 'agentic-security/repair-recipe-ledger';
const RECIPE_STATES = Object.freeze(['shipped', 'draft', 'evaluated', 'promoted', 'retired', 'rolled-back']);
const EDGES = Object.freeze({
  shipped: ['evaluated', 'retired', 'rolled-back'], draft: ['evaluated', 'retired'], evaluated: ['promoted', 'draft', 'retired'],
  promoted: ['retired', 'rolled-back'], 'rolled-back': ['evaluated', 'retired'], retired: [],
});
const USABLE = new Set(['shipped', 'promoted']);

// ---------------------------------------------------------------- registered transformations

/**
 * Path containment: `const <v> = path.resolve|join(<root>, <parts>);` becomes `const <v> = containedPath(<root>, '<mode>', <parts>);`
 * and one helper is appended. The helper resolves links before checking containment; a path that would leave the root becomes the
 * root itself, so the read the application already makes fails (a directory cannot be read as a file) and its existing error handling
 * refuses the request. Preconditions, all required: `fs` and `path` are bound by those names; the variable's next use is a read
 * (`readFile` with a callback, `readFileSync` inside a try block, `createReadStream`, or `promises.readFile`) whose failure the code
 * already handles; the root argument is an identifier or a member expression, not a literal.
 */
const CONTAIN_HELPER = [
  '',
  '// Added by the path-realpath-containment recipe: the real path of the joined parts under `root`, links resolved. A path that would',
  '// leave the root becomes the root itself, so reading it fails (a directory is not a file) and the existing error handling refuses it.',
  'function containedPath(root, mode, ...parts) {',
  '  const base = fs.realpathSync(root);',
  "  const target = mode === 'join' ? path.join(base, ...parts.map(String)) : path.resolve(base, ...parts.map(String));",
  '  let real;',
  '  try { real = fs.realpathSync(target); } catch { real = target; }',
  '  return real.startsWith(base + path.sep) ? real : base;',
  '}',
  '',
].join('\n');

const BINDS_FS = /^\s*import\s+fs\s+from\s+['"](?:node:)?fs['"]|^\s*const\s+fs\s*=\s*require\(\s*['"](?:node:)?fs['"]\s*\)/m;
const BINDS_PATH = /^\s*import\s+path\s+from\s+['"](?:node:)?path['"]|^\s*const\s+path\s*=\s*require\(\s*['"](?:node:)?path['"]\s*\)/m;
const DECL = /^([ \t]*)const ([A-Za-z_$][\w$]*) = path\.(resolve|join)\(\s*([A-Za-z_$][\w$.]*)\s*,\s*([^;\n]+?)\s*\);[ \t]*$/gm;

function containPathTransform(text) {
  const refused = [];
  if (!BINDS_FS.test(text) || !BINDS_PATH.test(text)) return { text, applied: 0, refused: ['fs and path are not bound by those names'] };
  if (/\bfunction\s+containedPath\s*\(/.test(text)) return { text, applied: 0, refused: ['a containedPath function already exists'] };
  let applied = 0;
  const out = text.replace(DECL, (whole, ind, v, mode, root, parts, offset) => {
    const rest = text.slice(offset + whole.length);
    const use = new RegExp(`\\bfs\\.(readFile|readFileSync|createReadStream|promises\\.readFile)\\(\\s*${v.replace(/\$/g, '\\$')}\\b([^\\n]*)`).exec(rest);
    if (!use) { refused.push(`${v}: its next use is not a file read this recipe can make fail`); return whole; }
    const before = text.slice(Math.max(0, offset - 400), offset) + rest.slice(0, use.index);
    const handled = use[1] === 'readFile' ? /\(\s*err\b/.test(use[2]) || /\(\s*err\b/.test(rest.slice(use.index, use.index + 200))
      : use[1] === 'createReadStream' ? /\.on\(\s*['"]error['"]/.test(rest.slice(use.index, use.index + 600))
        : /\btry\s*\{[^}]*$/.test(before) && /\bcatch\b/.test(rest.slice(use.index, use.index + 600));
    if (!handled) { refused.push(`${v}: the read's failure is not handled, so a refusal could not be expressed`); return whole; }
    applied++;
    return `${ind}const ${v} = containedPath(${root}, '${mode}', ${parts});`;
  });
  return applied ? { text: `${out.replace(/\s*$/, '\n')}${CONTAIN_HELPER}`, applied, refused } : { text, applied: 0, refused: refused.length ? refused : ['no path.resolve or path.join declaration matched'] };
}

const TRANSFORMS = Object.freeze({
  'sql-parameterize-template': { family: 'sql-injection', apply: _candidates_js__WEBPACK_IMPORTED_MODULE_7__/* .parameterizeTemplateSql */ .qW, source: _candidates_js__WEBPACK_IMPORTED_MODULE_7__/* .parameterizeTemplateSql */ .qW.toString() },
  'path-realpath-containment': { family: 'path-traversal', apply: containPathTransform, source: containPathTransform.toString() + CONTAIN_HELPER },
});

// ---------------------------------------------------------------- shipped recipe documents

const FIX = 'test/fixtures/repair';
const SHIPPED_RECIPES = Object.freeze([
  {
    schema: RECIPE_SCHEMA, recipeId: 'sql-parameterize-template', version: '2', transform: 'sql-parameterize-template',
    provenance: { origin: 'shipped', author: 'agentic-security maintainers', note: 'hand-written; not learned from examples' }, signer: 'shipped-with-scanner',
    supports: { family: 'sql-injection', languages: ['javascript'], runtime: { name: 'node', min: '22.5.0' }, driver: 'node:sqlite (prepare(sql).all|get|run|iterate with ? placeholders)', engine: 'sqlite' },
    preconditions: ['every interpolation sits exactly inside a single-quoted SQL literal', 'the statement is called immediately with no arguments', 'an interpolation in any other position (an identifier, a number, ORDER BY) is refused: a placeholder cannot carry it'],
    editScope: { maxFiles: 3, files: 'the contract\'s allowed files' },
    obligations: ['app-attack-blocked', 'app-attack-sealed', 'app-behaviour-preserved', 'app-behaviour-after', 'project-tests'],
    examples: [
      { id: 'notes', kind: 'positive', fixture: `${FIX}/sql-notes`, family: 'sql-injection', expect: 'verified-for-contract' },
      { id: 'tasks', kind: 'independent', fixture: `${FIX}/sql-tasks`, family: 'sql-injection', expect: 'verified-for-contract' },
      { id: 'sort-column', kind: 'safe-negative', fixture: `${FIX}/sql-sort`, entry: 'src/app.mjs', expect: 'refused' },
      { id: 'node-22.4', kind: 'unsupported-version', fixture: `${FIX}/sql-notes`, family: 'sql-injection', nodeVersion: '22.4.0', expect: 'not-applicable' },
    ],
    contraindications: ['a driver whose placeholder is not `?`', 'an identifier or keyword built from input'],
    rollback: 'retire the recipe: nothing it proposed was applied without its own verified record, and each applied patch has an apply-service backup',
  },
  {
    schema: RECIPE_SCHEMA, recipeId: 'path-realpath-containment', version: '1', transform: 'path-realpath-containment',
    provenance: { origin: 'shipped', author: 'agentic-security maintainers', note: 'hand-written; not learned from examples' }, signer: 'shipped-with-scanner',
    supports: { family: 'path-traversal', languages: ['javascript'], runtime: { name: 'node', min: '20.0.0' }, driver: 'node:fs and node:path bound as fs and path' },
    preconditions: ['fs and path are bound by those names', 'the joined path is declared with const from path.resolve or path.join of an identifier root', 'its next use is a read whose failure the code already handles'],
    editScope: { maxFiles: 1, files: 'the contract\'s allowed files' },
    obligations: ['app-attack-blocked', 'app-attack-sealed', 'app-behaviour-preserved', 'project-tests'],
    examples: [
      { id: 'downloads', kind: 'positive', fixture: `${FIX}/files-download`, family: 'path-traversal', expect: 'verified-for-contract' },
      { id: 'avatars', kind: 'independent', fixture: `${FIX}/avatar-store`, family: 'path-traversal', expect: 'verified-for-contract' },
      { id: 'unhandled-read', kind: 'safe-negative', text: "import fs from 'node:fs';\nimport path from 'node:path';\nexport const read = (root, n) => {\n  const p = path.join(root, n);\n  return fs.readFileSync(p, 'utf8');\n};\n", expect: 'refused' },
      { id: 'node-18', kind: 'unsupported-version', fixture: `${FIX}/files-download`, family: 'path-traversal', nodeVersion: '18.19.0', expect: 'not-applicable' },
    ],
    contraindications: ['an application that must serve links pointing outside its root', 'a read whose error handling reveals the reason'],
    rollback: 'retire the recipe; applied patches have apply-service backups',
  },
]);

const RECIPE_FIELDS = ['schema', 'recipeId', 'version', 'transform', 'provenance', 'signer', 'supports', 'preconditions', 'editScope', 'obligations', 'examples', 'contraindications', 'rollback'];

function validateRecipe(r) {
  const errs = [];
  if (!r || typeof r !== 'object' || Array.isArray(r)) return ['a recipe must be an object'];
  for (const k of Object.keys(r)) if (!RECIPE_FIELDS.includes(k)) errs.push(`unknown field '${k}'`);
  if (r.schema !== RECIPE_SCHEMA) errs.push(`schema must be '${RECIPE_SCHEMA}'`);
  if (typeof r.recipeId !== 'string' || !/^[a-z][a-z0-9-]{2,63}$/.test(r.recipeId)) errs.push('recipeId must be a slug');
  if (typeof r.version !== 'string' || !/^\d{1,4}(?:\.\d{1,4}){0,2}$/.test(r.version)) errs.push('version must be a dotted number');
  const t = TRANSFORMS[r.transform];
  if (!t) errs.push(`transform must be one of ${Object.keys(TRANSFORMS).join(', ')}: a recipe document cannot carry code`);
  if (t && r.supports?.family !== t.family) errs.push(`supports.family must be ${t?.family}`);
  // a document may narrow a shipped recipe of the same transformation, never widen it
  const base = SHIPPED_RECIPES.find((s) => s.transform === r.transform);
  if (base && (!Number.isInteger(r.editScope?.maxFiles) || r.editScope.maxFiles > base.editScope.maxFiles || r.editScope.maxFiles < 1)) errs.push(`editScope.maxFiles must be 1 to ${base.editScope.maxFiles}`);
  if (base && JSON.stringify(r.supports?.runtime) !== JSON.stringify(base.supports.runtime) && !(r.supports?.runtime?.name === 'node' && cmpVersion(r.supports.runtime.min, base.supports.runtime.min) >= 0)) errs.push('supports.runtime may only raise the minimum version');
  if (!Array.isArray(r.examples) || !r.examples.length) errs.push('examples must list at least one example');
  else for (const e of r.examples) if (!['positive', 'independent', 'safe-negative', 'unsupported-version', 'mutation'].includes(e?.kind)) errs.push(`example ${e?.id}: unknown kind`);
  if (!Array.isArray(r.obligations) || !r.obligations.includes('project-tests')) errs.push('obligations must include project-tests');
  return errs;
}

const cmpVersion = (a, b) => {
  const pa = String(a).split('.').map(Number); const pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
};

/** The recipe's identity: the document and the source of its transformation. */
const recipeDigest = (r) => (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__/* .digestOf */ .ol)({ doc: r, transform: (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__/* .digestOf */ .ol)(TRANSFORMS[r.transform]?.source || '') });

/** Does this recipe apply to this contract on this runtime? Returns {ok, reasons}. Pure. */
function applicability(recipe, contract, { nodeVersion = process.versions.node } = {}) {
  const reasons = [];
  if (contract.family !== recipe.supports.family) reasons.push(`the recipe repairs ${recipe.supports.family}, not ${contract.family}`);
  if ((contract.profile?.runtime || 'node') !== recipe.supports.runtime.name) reasons.push(`the recipe supports the ${recipe.supports.runtime.name} runtime only`);
  else if (cmpVersion(nodeVersion, recipe.supports.runtime.min) < 0) reasons.push(`node ${nodeVersion} is below the supported ${recipe.supports.runtime.min}`);
  if (recipe.supports.engine && contract.profile?.database?.engine !== recipe.supports.engine) reasons.push(`the recipe supports the ${recipe.supports.engine} driver only`);
  return { ok: reasons.length === 0, reasons };
}

/** A recipe as a proposer: one candidate in round 1, over at most `editScope.maxFiles` of the contract's allowed files. */
function recipeProposer(recipe, { nodeVersion } = {}) {
  const t = TRANSFORMS[recipe.transform];
  const identity = `${recipe.recipeId}@${recipe.version}#${recipeDigest(recipe).slice(7, 19)}`;
  return {
    id: identity,
    async propose({ contract, files, round }) {
      if (round !== 1) return { proposals: [], notes: [] };
      const a = applicability(recipe, contract, { nodeVersion });
      if (!a.ok) return { proposals: [], notes: a.reasons.map((x) => `${recipe.recipeId}: ${x}`) };
      const out = {}; const notes = [];
      for (const rel of contract.editScope.allowed) {
        if (!/\.(?:m?js|cjs|ts)$/.test(rel) || typeof files[rel] !== 'string') continue;
        const r = t.apply(files[rel]);
        if (r.applied) out[rel] = r.text;
        notes.push(...r.refused.map((x) => `${rel} ${x}`));
      }
      const changed = Object.keys(out);
      if (!changed.length) return { proposals: [], notes: notes.length ? notes : [`${recipe.recipeId}: the recipe matched nothing`] };
      if (changed.length > recipe.editScope.maxFiles) return { proposals: [], notes: [`${recipe.recipeId}: the recipe would change ${changed.length} files, more than its scope of ${recipe.editScope.maxFiles}`] };
      return { proposals: [{ generator: 'deterministic-recipe', generatorIdentity: identity, files: out, strategy: recipe.recipeId, rationale: recipe.preconditions.join('; ') }], notes };
    },
  };
}

// ---------------------------------------------------------------- the signed lifecycle ledger

const ledgerFile = (root) => (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_5__.statePath)(root, 'repair-recipes', 'ledger.json');
const hashOf = (e) => node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(JSON.stringify(e)).digest('hex');

function verifyChain(ledger) {
  let prev = null;
  for (const [i, e] of ledger.entries.entries()) {
    const { hash, ...rest } = e;
    if (rest.prev !== prev) return { ok: false, reason: `entry ${i} does not link the previous entry` };
    if (hashOf(rest) !== hash) return { ok: false, reason: `entry ${i} was modified` };
    prev = hash;
  }
  return { ok: true };
}

/** The ledger, verified: hash chain and the per-install signature. A ledger failing either is returned with `tampered`. */
function loadRecipeLedger(root) {
  const f = ledgerFile(root);
  let text; let ledger;
  try { text = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(f, 'utf8'); } catch (e) {
    if (e?.code === 'ENOENT') return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {} };
    return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {}, tampered: true, tamperReason: `the ledger cannot be read: ${String(e.message).slice(0, 80)}` };
  }
  try { ledger = JSON.parse(text); } catch (e) { return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {}, tampered: true, tamperReason: `the ledger cannot be read: ${String(e.message).slice(0, 80)}` }; }
  if (!Array.isArray(ledger?.entries)) return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {}, tampered: true, tamperReason: 'the ledger has no entries' };
  const v = verifyChain(ledger);
  if (!v.ok) return { ...ledger, tampered: true, tamperReason: v.reason };
  if ((0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_6__/* .verifyLastScan */ .Ef)(text, `${f}.sig`) !== true) return { ...ledger, tampered: true, tamperReason: 'the ledger signature does not verify under this installation\'s key' };
  return { drafts: {}, ...ledger };
}

function saveRecipeLedger(root, ledger) {
  if (ledger.tampered) throw new Error(`refusing to write a ledger that failed verification: ${ledger.tamperReason}`);
  (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_5__.ensureStateDir)(root);
  const f = ledgerFile(root);
  node_fs__WEBPACK_IMPORTED_MODULE_1__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_3__.dirname(f), { recursive: true });
  const text = `${JSON.stringify({ schema: RECIPE_LEDGER_SCHEMA, entries: ledger.entries, drafts: ledger.drafts || {} }, null, 2)}\n`;
  const tmp = `${f}.${process.pid}.tmp`;
  node_fs__WEBPACK_IMPORTED_MODULE_1__.writeFileSync(tmp, text);
  node_fs__WEBPACK_IMPORTED_MODULE_1__.renameSync(tmp, f);
  node_fs__WEBPACK_IMPORTED_MODULE_1__.writeFileSync(`${f}.sig`, (0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_6__/* .signLastScan */ .lU)(text));
}

/** Every recipe the ledger knows: shipped documents plus operator drafts. */
function allRecipes(ledger) {
  return [...SHIPPED_RECIPES, ...Object.values(ledger.drafts || {})];
}

function stateOf(ledger, recipe) {
  for (let i = ledger.entries.length - 1; i >= 0; i--) {
    const e = ledger.entries[i];
    if (e.recipeId === recipe.recipeId && e.version === recipe.version) return { state: e.to, entry: e };
  }
  return { state: recipe.provenance?.origin === 'shipped' ? 'shipped' : 'draft', entry: null };
}

/**
 * Record a transition the caller decided. Refuses an edge not in the lifecycle, a promotion without an evaluation of THIS recipe digest
 * that passed every example, and any change to a tampered ledger. Never throws.
 */
function transition(root, recipe, to, { reason, actor, evaluation = null }) {
  const ledger = loadRecipeLedger(root);
  if (ledger.tampered) return { ok: false, reason: ledger.tamperReason };
  if (!reason || !String(reason).trim()) return { ok: false, reason: 'a reason is required' };
  const { state, entry } = stateOf(ledger, recipe);
  if (!(EDGES[state] || []).includes(to)) return { ok: false, reason: `${recipe.recipeId}@${recipe.version} cannot go from ${state} to ${to}` };
  const digest = recipeDigest(recipe);
  let evidence = null;
  if (to === 'evaluated') {
    if (!evaluation?.ok || evaluation.recipeDigest !== digest) return { ok: false, reason: 'an evaluation of this exact recipe in which every example met its expectation is required' };
    evidence = evaluation.evaluationDigest;
  }
  if (to === 'promoted') {
    if (!entry || entry.to !== 'evaluated' || entry.recipeDigest !== digest) return { ok: false, reason: 'the recipe changed since it was evaluated: evaluate it again' };
    evidence = entry.evidence;
  }
  const rest = { recipeId: recipe.recipeId, version: recipe.version, recipeDigest: digest, from: state, to, reason: String(reason).slice(0, 500), actor: String(actor || node_os__WEBPACK_IMPORTED_MODULE_2__.userInfo().username || 'operator').slice(0, 80), evidence, prev: ledger.entries.length ? ledger.entries[ledger.entries.length - 1].hash : null };
  ledger.entries.push({ ...rest, hash: hashOf(rest) });
  try { saveRecipeLedger(root, ledger); } catch (e) { return { ok: false, reason: String(e.message).slice(0, 200) }; }
  return { ok: true, from: state, to };
}

/** Add an operator draft (a narrowed document over a registered transformation). */
function draftRecipe(root, doc, { reason, actor }) {
  const errs = validateRecipe(doc);
  if (errs.length) return { ok: false, reason: errs.join('; ') };
  if (doc.provenance?.origin === 'shipped' || SHIPPED_RECIPES.some((s) => s.recipeId === doc.recipeId && s.version === doc.version)) return { ok: false, reason: 'a draft cannot reuse a shipped recipe id and version, or claim shipped provenance' };
  const ledger = loadRecipeLedger(root);
  if (ledger.tampered) return { ok: false, reason: ledger.tamperReason };
  const key = `${doc.recipeId}@${doc.version}`;
  if (ledger.drafts?.[key]) return { ok: false, reason: `${key} already exists; drafts are immutable, draft a new version` };
  ledger.drafts = { ...(ledger.drafts || {}), [key]: doc };
  const rest = { recipeId: doc.recipeId, version: doc.version, recipeDigest: recipeDigest(doc), from: null, to: 'draft', reason: String(reason || 'drafted').slice(0, 500), actor: String(actor || 'operator').slice(0, 80), evidence: null, prev: ledger.entries.length ? ledger.entries[ledger.entries.length - 1].hash : null };
  ledger.entries.push({ ...rest, hash: hashOf(rest) });
  try { saveRecipeLedger(root, ledger); } catch (e) { return { ok: false, reason: String(e.message).slice(0, 200) }; }
  return { ok: true };
}

/**
 * The recipes a run may use automatically for a family: shipped ones that are not retired or rolled back, and promoted ones whose
 * promotion evidence names the recipe as it is now. A tampered ledger allows nothing but is reported.
 */
function usableRecipes(root, family) {
  const ledger = loadRecipeLedger(root);
  if (ledger.tampered) return { recipes: [], notes: [`the recipe ledger failed verification (${ledger.tamperReason}); no recipe is used`] };
  const recipes = []; const notes = [];
  for (const r of allRecipes(ledger).filter((x) => x.supports?.family === family)) {
    const { state, entry } = stateOf(ledger, r);
    if (!USABLE.has(state)) { notes.push(`${r.recipeId}@${r.version} is ${state}: not used`); continue; }
    if (state === 'promoted' && entry.recipeDigest !== recipeDigest(r)) { notes.push(`${r.recipeId}@${r.version} changed after promotion: not used`); continue; }
    recipes.push(r);
  }
  return { recipes, notes };
}

// ---------------------------------------------------------------- evaluation

/**
 * Evaluate a recipe on its examples. Positive and independent examples are planned and run through the full coordinator with the recipe
 * as the only proposer and must be `verified-for-contract`; a safe-negative must be refused by the transformation; an unsupported version
 * must be not-applicable. `deps.run({recipe, example, root})` performs a positive run (injected so this module adds no execution path).
 * Returns the evaluation with a digest over the recipe digest, every fixture digest and every obligation digest.
 */
async function evaluateRecipe(recipe, { repoRoot, run }) {
  const errs = validateRecipe(recipe);
  if (errs.length) return { ok: false, recipeId: recipe?.recipeId, problems: errs };
  const results = [];
  for (const ex of recipe.examples) {
    const dir = ex.fixture ? node_path__WEBPACK_IMPORTED_MODULE_3__.resolve(repoRoot, ex.fixture) : null;
    if (dir && !node_fs__WEBPACK_IMPORTED_MODULE_1__.existsSync(dir)) { results.push({ id: ex.id, kind: ex.kind, expect: ex.expect, outcome: 'example-unavailable', ok: false }); continue; }
    const fixtureDigest = dir ? (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__/* .digestOf */ .ol)(readTree(dir)) : (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__/* .digestOf */ .ol)(ex.text || '');
    let outcome; let obligations = null; let detail = null;
    if (ex.kind === 'safe-negative') {
      const text = ex.text ?? node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_3__.join(dir, ex.entry), 'utf8');
      const r = TRANSFORMS[recipe.transform].apply(text);
      outcome = r.applied ? 'applied' : 'refused';
      detail = r.refused.slice(0, 3);
    } else if (ex.kind === 'unsupported-version') {
      const r = await run({ recipe, example: ex, dir, planOnly: true });
      const a = applicability(recipe, r.contract, { nodeVersion: ex.nodeVersion });
      outcome = a.ok ? 'applicable' : 'not-applicable';
      detail = a.reasons;
    } else {
      const r = await run({ recipe, example: ex, dir });
      outcome = r.disposition;
      obligations = r.obligationDigests;
      detail = r.reasons?.slice(0, 3) || null;
    }
    results.push({ id: ex.id, kind: ex.kind, expect: ex.expect, outcome, ok: outcome === ex.expect, fixtureDigest, ...(obligations ? { obligations } : {}), ...(detail ? { detail } : {}) });
  }
  const digest = recipeDigest(recipe);
  const evaluation = { recipeId: recipe.recipeId, version: recipe.version, recipeDigest: digest, results, ok: results.every((r) => r.ok) };
  evaluation.evaluationDigest = (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_4__/* .digestOf */ .ol)({ recipeDigest: digest, results: results.map(({ id, outcome, fixtureDigest, obligations }) => ({ id, outcome, fixtureDigest, obligations: obligations ?? null })) });
  return evaluation;
}

function readTree(dir) {
  const out = {};
  const walk = (d, rel) => {
    for (const e of node_fs__WEBPACK_IMPORTED_MODULE_1__.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(node_path__WEBPACK_IMPORTED_MODULE_3__.join(d, e.name), r);
      else if (e.isFile()) out[r] = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_3__.join(d, e.name), 'utf8');
    }
  };
  walk(dir, '');
  return out;
}


/***/ })

};
