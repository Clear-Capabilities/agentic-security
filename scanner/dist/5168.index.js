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
/* harmony import */ var _coordinator_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(89330);
/* harmony import */ var _candidates_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(4370);
// `agentic-security repair plan|run|show|resume|cancel|verify|export` (verified-remediation PRD FR-18).
//
// Every subcommand delegates to the coordinator; none writes project files except `run --apply`, which goes through applyVerifiedFix.
// Exit codes (stable): 0 the requested operation completed (read the disposition), 1 a failed obligation or rejected repair, 2 usage or
// schema error, 3 a required prerequisite unavailable, unsupported or blocked, 4 cancelled or budget-exhausted before verification
// completed. A plan or export exiting 0 does not mean anything was verified.











const USAGE = `agentic-security repair <command>
  plan    --profile <profile.json> (--finding <id> | --family <family> --file <rel>) [--root <path>] [--out <plan.json>] [--json]
  run     --plan <plan.json> [--policy <policy.json>] [--candidates <file.json>] [--allow-execution] [--apply [--approved-by <who> --approval-reason <why>]] [--root <path>] [--json]
  show    <run-id> [--root <path>] [--json]
  resume  <run-id> [--allow-execution] [--root <path>] [--json]
  cancel  <run-id> [--root <path>]
  verify  <bundle-dir> [--root <path>] [--json]
  export  <run-id> --out <directory> [--root <path>]
families: sql-injection, object-authorization, ssrf, path-traversal
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

function proposersFor(plan, candidatesFile) {
  const ps = [];
  if (plan.contract.family === 'sql-injection') ps.push((0,_candidates_js__WEBPACK_IMPORTED_MODULE_9__/* .sqlParameterizeRecipe */ .uf)());
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
  const r = (0,_intake_js__WEBPACK_IMPORTED_MODULE_6__/* .planFromInputs */ .Zn)({ root, profilePath: node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.profile)), findingId: args.flags.finding ? String(args.flags.finding) : undefined, family: args.flags.family ? String(args.flags.family) : undefined, file: args.flags.file ? String(args.flags.file) : undefined });
  if (!r.plan) { err(r.problems.length ? `the profile or contract is invalid:\n  ${r.problems.join('\n  ')}` : `blocked: ${r.blocked.join('; ')}`); return r.status === 'usage' ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
  const dest = args.flags.out ? node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(String(args.flags.out)) : node_path__WEBPACK_IMPORTED_MODULE_1__.join((0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__/* .stateDir */ .Pn)(root), 'repair', 'plans', `${r.plan.contract.contractId.replace(':', '-')}.json`);
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(dest), { recursive: true });
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(dest, JSON.stringify(r.plan, null, 2) + '\n');
  const summary = (0,_contracts_js__WEBPACK_IMPORTED_MODULE_7__/* .obligationSummary */ .NL)(r.plan.contract);
  out(args, [`plan ${dest}`, `contract ${r.plan.contract.contractId} (${r.plan.contract.family}), profile facts ${r.plan.contract.policyFacts[0].approval}`, ...summary.map((o) => `  ${o.required ? 'required' : 'optional'} ${o.kind.padEnd(24)} ${o.id}: ${o.scope}${o.requests !== null ? ` (${o.requests} requests, ${o.stateChecks} state checks)` : ''}`), ...(r.blocked.length ? [`blocked: ${r.blocked.join('; ')}`] : []), ...r.plan.contract.knownUnknowns.map((k) => `  unknown: ${k}`), 'nothing was executed or applied'].join('\n'),
    { plan: dest, contractId: r.plan.contract.contractId, contractDigest: r.plan.contract.contractDigest, family: r.plan.contract.family, obligations: summary, blocked: r.blocked, knownUnknowns: r.plan.contract.knownUnknowns });
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
  try { proposers = proposersFor(plan, args.flags.candidates); } catch (e) { err(e.message); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
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
  const proposers = [...(r.plan.contract.family === 'sql-injection' ? [(0,_candidates_js__WEBPACK_IMPORTED_MODULE_9__/* .sqlParameterizeRecipe */ .uf)()] : []), ...(stored.length ? [(0,_candidates_js__WEBPACK_IMPORTED_MODULE_9__/* .queueProposer */ .uI)(stored, 'resumed-user-supplied')] : [])];
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
    patchDigest: r.record.patchDigest ?? null, patchFiles, approvalsRequired: r.plan.contract.policyFacts.filter((f) => f.approval !== 'approved').map((f) => `${f.id}: ${f.approval}`),
    rollback: 'the patch replaces whole files; the before digests in record.json name the content to restore, and an applied patch is reverted with `agentic-security undo`',
    redactions: 'request header values in the contract are replaced by digests; patch bytes are exported unchanged',
    claim: r.record.disposition === 'verified-for-contract' ? `verified for contract ${r.plan.contract.contractId} only; source-only, nothing built or deployed` : 'not verified',
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
    { ok, problems, sourceMatches, claim: m.claim, note: 'integrity establishes custody, not semantic correctness; nothing was executed' });
  return ok ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.failed;
}

async function cmdRepair(args, root) {
  const sub = args._[1];
  const handlers = { plan: cmdPlan, run: cmdRun, show: cmdShow, resume: cmdResume, cancel: cmdCancel, export: cmdExport, verify: cmdVerify };
  if (!handlers[sub] || args.flags.help) { (handlers[sub] ? process.stdout : process.stderr).write(`${USAGE}\n`); return args.flags.help ? _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.ok : _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.usage; }
  try { return await handlers[sub](args, root); } catch (e) { err(String(e?.message || e)); return _coordinator_js__WEBPACK_IMPORTED_MODULE_8__/* .EXIT */ .dc.blocked; }
}




/***/ })

};
