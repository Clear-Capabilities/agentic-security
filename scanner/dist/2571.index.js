export const id = 2571;
export const ids = [2571];
export const modules = {

/***/ 62571:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdContracts: () => (/* binding */ cmdContracts),
  draftContract: () => (/* binding */ draftContract),
  loadContractForHunt: () => (/* binding */ loadContractForHunt)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/contracts/schema.js
var schema = __webpack_require__(42207);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
;// CONCATENATED MODULE: ./src/contracts/pack.js
// The readable companion of a contract: `threat-pack.md`.
//
// The JSON contract is the machine representation. The pack is prose for people and, when the operator opts in, for a model: system
// purpose, trust boundaries, intended behaviour, review priorities, known controls. Two rules keep it honest. Its digest is bound
// into the contract (`threatPack.digest`) and therefore into every frozen manifest the pack influences, so a changed pack is a changed
// contract. And when the pack and the contract disagree (an invariant named in one and not the other) the result is a reviewable
// diagnostic for the operator, never a model's interpretation of which one is right.
//
// Parsing is deliberately shallow: headings, and invariant identifiers written as `INVARIANT-ID` tokens. Nothing in the pack can
// change policy; `stripUntrustedCommands` from the review path is applied before any model sees it.


// A bounded character class, no nested quantifier: the dash structure is checked on the match, not in the pattern.
const INVARIANT_TOKEN = /\b[A-Z][A-Z0-9-]{4,63}\b/g;
const looksLikeInvariantId = (s) => s.includes('-') && !s.endsWith('-') && !s.includes('--') && /[A-Z]/.test(s);
const HEADING = /^(#{1,3})\s+(.+?)\s*$/gm;
const MAX_PACK_BYTES = 256 * 1024;

function packDigest(text) { return (0,identity/* digestOfBytes */.by)(Buffer.from(String(text), 'utf8')); }

/** Headings and the invariant identifiers the prose names. Pure. */
function parsePack(text) {
  const t = String(text ?? '');
  const headings = [];
  let m;
  while ((m = HEADING.exec(t))) headings.push({ level: m[1].length, title: m[2].slice(0, 200) });
  const ids = new Set();
  while ((m = INVARIANT_TOKEN.exec(t))) if (looksLikeInvariantId(m[0]) && !/^(?:HTTP|HTTPS|JSON|CWE|OWASP|TODO)/.test(m[0])) ids.add(m[0]);
  return { headings, invariantIds: [...ids].sort(), bytes: Buffer.byteLength(t, 'utf8'), digest: packDigest(t) };
}

/**
 * Compare a contract with its pack. `issues` is empty when they agree. Each issue names both sources, so a reviewer sees the
 * disagreement as the two documents state it.
 */
function reconcilePack(contract, packText) {
  const issues = [];
  if (typeof packText !== 'string') return { ok: false, issues: [{ code: 'pack-unreadable', message: 'the readable companion could not be read' }], parsed: null };
  const parsed = parsePack(packText);
  if (parsed.bytes > MAX_PACK_BYTES) issues.push({ code: 'pack-too-large', message: `the pack is ${parsed.bytes} bytes; the limit is ${MAX_PACK_BYTES}` });
  if (contract?.threatPack?.digest && contract.threatPack.digest !== parsed.digest) {
    issues.push({ code: 'pack-digest-mismatch', message: 'the contract binds a different pack digest; the pack changed after the contract was written, or the contract names another pack', contract: contract.threatPack.digest, pack: parsed.digest });
  }
  const declared = new Set((contract?.invariants || []).map((i) => i.id));
  for (const id of parsed.invariantIds) if (!declared.has(id)) issues.push({ code: 'pack-names-undeclared-invariant', message: `the pack names ${id}, which the contract does not declare`, invariantId: id });
  for (const id of declared) if (!parsed.invariantIds.includes(id)) issues.push({ code: 'pack-omits-invariant', message: `the contract declares ${id}, which the pack never mentions`, invariantId: id });
  return { ok: issues.length === 0, issues, parsed };
}

// EXTERNAL MODULE: external "node:fs/promises"
var promises_ = __webpack_require__(51455);
// EXTERNAL MODULE: ./src/posture/invariants/lifecycle.js
var lifecycle = __webpack_require__(80891);
;// CONCATENATED MODULE: ./src/contracts/approval.js
// Approval of a service contract through the existing invariant ledger (Epic A-02).
//
// There is one approval authority in this codebase: the hash-chained, HMAC-signed ledger of posture/invariants/lifecycle.js, with
// human reviewers named by the operator's policy or approver registry. A service contract is proposed and approved there as a
// `service-contract` subject, so a forged file, a copied ledger head, a model's statement or an `approved` claim in the document
// can satisfy nothing. The approval binds to the contract's content digest and its version: an edited contract has a new digest and
// the old approval does not apply to it (`wrong-scope`), an expired review policy makes the approval `expired` (still visible), a
// revoked approval stays in the ledger as `revoked`.
//
// `now` is always supplied by the caller: this module never reads the clock, so a state is reproducible from its inputs.





const APPROVAL_STATES = Object.freeze(['proposed', 'approved', 'rejected', 'superseded', 'revoked', 'expired', 'wrong-scope', 'not-recorded', 'approval-unverifiable']);

/** The ledger subject id of a contract: the same derivation `recordTransition` uses, so callers never guess it. */
function contractSubjectId(contract) {
  const d = (0,schema/* contractDigest */.vE)(contract);
  return `${schema/* CONTRACT_SCHEMA */.f8}#${d.slice('sha256:'.length, 'sha256:'.length + 32)}`;
}

function daysBetween(a, b) { return Math.floor((Date.parse(b) - Date.parse(a)) / 86400000); }

/**
 * The approval state of a contract under a ledger, re-verified against the current reviewer policy.
 * @returns {{ state, current: boolean, contractRef, subjectId, transitionId, reviewer, authority, ledgerHead, reasons: string[] }}
 */
function approvalState(contract, ledger, { policy = null, registry = null, signer, now } = {}) {
  const base = { contractRef: null, subjectId: null, transitionId: null, reviewer: null, authority: null, ledgerHead: null, reasons: [] };
  const v = (0,schema/* validateContract */.T7)(contract);
  if (!v.ok) return { ...base, state: 'approval-unverifiable', current: false, reasons: ['the contract does not validate: ' + v.errors.map((e) => `${e.path}: ${e.message}`).join('; ')] };
  base.contractRef = (0,schema/* contractRef */.sB)(contract);
  base.subjectId = contractSubjectId(contract);
  if (!ledger) return { ...base, state: 'not-recorded', current: false, reasons: ['no approval ledger was supplied'] };
  const verified = (0,lifecycle/* verifyLedger */.xy)(ledger, { signer, policy, registry });
  if (!verified.ok) return { ...base, state: 'approval-unverifiable', current: false, reasons: verified.errors.map((e) => `${e.code}: ${e.message}`) };
  base.ledgerHead = ledger.records.length ? ledger.records[ledger.records.length - 1].id : null;
  const state = verified.states[base.subjectId];
  if (!state) {
    // Is a different content of the same contract id and version approved? That is the classic forged or stale approval: the
    // document changed after the review. Report it as wrong-scope with both digests so the reviewer sees what moved.
    const other = ledger.records.find((r) => r.action === 'propose' && r.subjectKind === 'service-contract' && r.key === contract.id && r.revision === contract.version);
    if (other) return { ...base, state: 'wrong-scope', current: false, reasons: [`the ledger approves ${contract.id}@${contract.version} with digest ${other.subjectDigest}, not this content (${(0,schema/* contractDigest */.vE)(contract)}); the contract changed after review`] };
    return { ...base, state: 'not-recorded', current: false, reasons: ['this contract content has never been proposed in the ledger'] };
  }
  const last = [...ledger.records].reverse().find((r) => r.invariantId === base.subjectId && r.to === state);
  const out = { ...base, transitionId: last?.id ?? null, reviewer: last?.actor?.id ?? null, authority: last?.policyId ?? null };
  if (state !== 'approved') return { ...out, state, current: false, reasons: [`the ledger's latest transition for this content is '${state}'`] };
  if (typeof now === 'string') {
    const exp = contract.expiry?.expiresAt;
    if (exp && Date.parse(now) > Date.parse(exp)) return { ...out, state: 'expired', current: false, reasons: [`the contract expired on ${exp}; the approval is on record but is no longer current authority`] };
    const age = daysBetween(contract.reviewedAt, now);
    if (Number.isFinite(age) && age > contract.expiry.reviewEveryDays) return { ...out, state: 'expired', current: false, reasons: [`reviewed ${age} days ago, more than the ${contract.expiry.reviewEveryDays} the contract allows between reviews`] };
  } else out.reasons.push('no `now` was supplied, so expiry was not evaluated');
  return { ...out, state: 'approved', current: true };
}

/** Propose a contract into a ledger (creates one when none is given). A proposer may be code or a model; approval may not. */
function proposeContract(ledger, contract, { actor, reason, signer } = {}) {
  return recordTransition(ledger || emptyLedger(), { action: 'propose', contract, actor, reason }, { signer });
}

function approveContract(ledger, contract, { actor, reason, policy, registry, signer } = {}) {
  return recordTransition(ledger, { action: 'approve', invariantId: contractSubjectId(contract), actor, reason }, { policy, registry, signer });
}

function revokeContract(ledger, contract, { actor, reason, policy, registry, signer } = {}) {
  return recordTransition(ledger, { action: 'revoke', invariantId: contractSubjectId(contract), actor, reason }, { policy, registry, signer });
}



// ---- ledger persistence (E-04: the harness under interruption) -----------------------------------------------------------------
// The ledger is plain data the caller persists. These two helpers make that persistence recoverable: a write goes to a sibling temp file
// and is renamed into place (an interrupted write leaves the previous ledger intact and the temp file behind, which a read ignores), a
// link is refused, and a read that does not parse is `corrupt`, never an empty ledger: a corrupted checkpoint can never come back as
// "no approvals yet, start over" and never as approval.

async function writeLedgerFile(file, ledger) {
  const target = pathMod.resolve(file);
  try { const st = await fsp.lstat(target); if (st.isSymbolicLink()) return { ok: false, reason: 'the ledger path is a link; refused' }; } catch { /* new file */ }
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  await fsp.writeFile(tmp, JSON.stringify(ledger, null, 1) + '\n', { flag: 'wx' });
  await fsp.rename(tmp, target);
  return { ok: true, file: target };
}

async function readLedgerFile(file) {
  let text;
  try { text = await fsp.readFile(pathMod.resolve(file), 'utf8'); } catch (e) { return { ok: false, state: 'missing', reason: e.code || 'unreadable' }; }
  try {
    const ledger = JSON.parse(text);
    if (!ledger || ledger.schema !== LEDGER_SCHEMA || !Array.isArray(ledger.records)) return { ok: false, state: 'corrupt', reason: 'not an approval ledger' };
    return { ok: true, ledger };
  } catch { return { ok: false, state: 'corrupt', reason: 'the ledger does not parse; it is not treated as empty' }; }
}

// EXTERNAL MODULE: ./src/context-intelligence/store.js
var store = __webpack_require__(65535);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
;// CONCATENATED MODULE: ./src/contracts/cli.js
// `agentic-security contracts validate|inspect|draft` and the loader `hunt --contract` uses.
//
//   contracts validate <contract.json>                       schema, refusals, pack reconciliation; exit 0 valid, 1 invalid
//   contracts inspect <contract.json> [--ledger f] [--root r] approval state (re-verified against the root's reviewer policy, if any),
//                                                            bindings and gaps, pack agreement, context build coverage for the root
//   contracts draft --root <dir> [--out contract.json]       a PROPOSED contract drafted deterministically from the context build's
//                                                            entry points and observed controls; no model, no network, never approval
//
// Read-only except `draft --out`, which writes one file the operator named. Nothing here contacts an owner, requests an approval or
// grants one: approval is a reviewer's recorded transition in the ledger (`approval.js`).








const SAFE = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]/g, '?').slice(0, 300);

async function readJson(file) {
  try { return { ok: true, value: JSON.parse(await external_node_fs_.promises.readFile(file, 'utf8')) }; } catch (e) { return { ok: false, reason: `${file}: ${String(e?.message || e).slice(0, 120)}` }; }
}
async function readText(file) { try { return await external_node_fs_.promises.readFile(file, 'utf8'); } catch { return null; } }

/** Load a contract, its pack and (optionally) its ledger for a hunt. Pure of the clock: `now` is given. */
async function loadContractForHunt({ contractPath, ledgerPath = null, scanRoot = null, now }) {
  const c = await readJson(contractPath);
  if (!c.ok) return { ok: false, reason: `the contract could not be read: ${c.reason}` };
  const v = (0,schema/* validateContract */.T7)(c.value);
  if (!v.ok) return { ok: false, reason: 'the contract does not validate', errors: v.errors.map((e) => `${e.path}: ${e.message}`) };
  const warnings = [];
  if (c.value.threatPack) {
    const r = reconcilePack(c.value, await readText(external_node_path_.join(external_node_path_.dirname(contractPath), c.value.threatPack.path)));
    for (const i of r.issues) warnings.push(`threat pack: ${i.code}: ${SAFE(i.message)}`);
  }
  let approval = null;
  if (ledgerPath) {
    const l = await readJson(ledgerPath);
    if (!l.ok) return { ok: false, reason: `the ledger could not be read: ${l.reason}` };
    const policy = await reviewerPolicyFor(scanRoot);
    approval = approvalState(c.value, l.value, { policy, now });
    if (approval.state !== 'approved') warnings.push(`approval: ${approval.state}: ${approval.reasons.join('; ')}`);
  } else warnings.push('no --ledger given: the contract is treated as proposed, and nothing it says is authority');
  return { ok: true, contractMode: { contract: c.value, approval }, warnings };
}

// The operator's reviewer policy, when the project carries one. Read, never written; a project file cannot add a reviewer to a policy
// the operator did not configure, which is why a missing policy means no approval verifies.
async function reviewerPolicyFor(scanRoot) {
  if (!scanRoot) return null;
  const r = await readJson((0,state_dir.statePath)(scanRoot, 'reviewer-policy.json'));
  if (!r.ok || !r.value || !Array.isArray(r.value.reviewers)) return null;
  return { id: typeof r.value.id === 'string' ? r.value.id : 'local', reviewers: r.value.reviewers.filter((x) => typeof x === 'string') };
}

async function cmdContracts(args) {
  const sub = args._[1];
  const file = args._[2] ? external_node_path_.resolve(String(args._[2])) : null;
  const now = new Date().toISOString().slice(0, 10);
  if (sub === 'validate') {
    if (!file) { console.error('usage: agentic-security contracts validate <contract.json>'); return 2; }
    const c = await readJson(file); if (!c.ok) { console.error(c.reason); return 1; }
    const v = (0,schema/* validateContract */.T7)(c.value);
    if (!v.ok) { console.log(`INVALID ${SAFE(file)}`); for (const e of v.errors) console.log(`  ${e.code} ${e.path}: ${SAFE(e.message)}`); return 1; }
    console.log(`valid ${(0,schema/* contractRef */.sB)(c.value)}`);
    if (c.value.threatPack) {
      const r = reconcilePack(c.value, await readText(external_node_path_.join(external_node_path_.dirname(file), c.value.threatPack.path)));
      if (!r.ok) { for (const i of r.issues) console.log(`  pack: ${i.code}: ${SAFE(i.message)}`); return 1; }
      console.log(`  pack: ${c.value.threatPack.path} agrees (${r.parsed.invariantIds.length} invariant id(s) named)`);
    }
    return 0;
  }
  if (sub === 'inspect') {
    if (!file) { console.error('usage: agentic-security contracts inspect <contract.json> [--ledger <file>] [--root <dir>]'); return 2; }
    const c = await readJson(file); if (!c.ok) { console.error(c.reason); return 1; }
    const v = (0,schema/* validateContract */.T7)(c.value);
    if (!v.ok) { console.log(`INVALID ${SAFE(file)}`); for (const e of v.errors) console.log(`  ${e.code} ${e.path}: ${SAFE(e.message)}`); return 1; }
    const root = args.flags.root ? external_node_path_.resolve(String(args.flags.root)) : null;
    const out = { schema: 'agentic-security/contract-inspection', contractRef: (0,schema/* contractRef */.sB)(c.value), id: c.value.id, version: c.value.version, owner: c.value.owner, reviewPriority: c.value.reviewPriority, reviewedAt: c.value.reviewedAt, expiry: c.value.expiry, scope: c.value.scope, approval: null, bindings: (0,schema/* bindingView */.Lk)(c.value), pack: null, context: null };
    if (args.flags.ledger) {
      const l = await readJson(external_node_path_.resolve(String(args.flags.ledger)));
      out.approval = l.ok ? approvalState(c.value, l.value, { policy: await reviewerPolicyFor(root), now }) : { state: 'approval-unverifiable', reasons: [l.reason] };
    } else out.approval = { state: 'not-recorded', current: false, reasons: ['no --ledger given'] };
    if (c.value.threatPack) {
      const r = reconcilePack(c.value, await readText(external_node_path_.join(external_node_path_.dirname(file), c.value.threatPack.path))); out.pack = { path: c.value.threatPack.path, agrees: r.ok, issues: r.issues };
    }
    if (root) {
      const idx = (0,store/* readStoreJson */.WS)(root, 'index.json'); // the store's own reader (link-safe)
      out.context = idx.ok ? { built: true, entrypoints: (idx.value.entrypoints || []).length, complete: (idx.value.entrypoints || []).filter((e) => e.integrity === 'complete').length, graphHash: idx.value.graph?.hash ?? null } : { built: false, reason: `no context build (${idx.code}); run \`context build --root ${SAFE(root)}\`` };
    }
    if (args.flags.json) { console.log(JSON.stringify(out, null, 2)); return 0; }
    console.log(`${out.contractRef}  owner ${SAFE(out.owner)}  priority ${out.reviewPriority}  reviewed ${out.reviewedAt} (every ${out.expiry.reviewEveryDays} days${out.expiry.expiresAt ? ', expires ' + out.expiry.expiresAt : ''})`);
    console.log(`  approval: ${out.approval.state}${out.approval.current ? '' : ' (not current authority)'}${out.approval.reasons?.length ? ': ' + out.approval.reasons.map(SAFE).join('; ') : ''}`);
    console.log(`  scope: ${out.scope.environment}; repositories ${out.scope.repositories.map((r) => `${r.id}@${r.revision.slice(0, 12)}`).join(', ')}`);
    for (const b of out.bindings) console.log(`  ${b.invariantId}: ${Object.entries(b.bindings).map(([k, s]) => `${k}=${s}`).join(' ')}${b.gaps.length ? `  gaps: ${b.gaps.join(', ')}` : ''}${b.checkable ? '' : '  NOT CHECKABLE'}`);
    if (out.pack) console.log(`  pack: ${out.pack.agrees ? 'agrees' : out.pack.issues.map((i) => i.code).join(', ')}`);
    if (out.context) console.log(`  context build: ${out.context.built ? `${out.context.complete}/${out.context.entrypoints} entry points complete` : out.context.reason}`);
    return 0;
  }
  if (sub === 'draft') {
    const root = args.flags.root ? external_node_path_.resolve(String(args.flags.root)) : null;
    if (!root) { console.error('usage: agentic-security contracts draft --root <dir> [--out <contract.json>] [--id <service-id>]'); return 2; }
    const d = await draftContract(root, { id: args.flags.id ? String(args.flags.id) : external_node_path_.basename(root).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'service', now });
    if (!d.ok) { console.error(d.reason); return 1; }
    const text = JSON.stringify(d.contract, null, 2) + '\n';
    if (args.flags.out) { await external_node_fs_.promises.writeFile(external_node_path_.resolve(String(args.flags.out)), text); console.log(`drafted ${(0,schema/* contractRef */.sB)(d.contract)} -> ${SAFE(args.flags.out)} (PROPOSED: a reviewer approves it in the ledger, or nothing it says is authority)`); }
    else process.stdout.write(text);
    for (const n of d.notes) console.error(`note: ${SAFE(n)}`);
    return 0;
  }
  console.error('usage: agentic-security contracts validate|inspect|draft ...');
  return sub ? 1 : 0;
}

/**
 * A deterministic draft from the context build: one invariant per protection dimension the build observed on at least one entry point
 * (authentication, authorization-role, ownership), each listing the entry points it applies to; declared controls from the observed
 * ones. No model is consulted. The draft is PROPOSED with origin `inferred`, and the repository revision is the build's commit when
 * the build recorded one, otherwise the draft is refused (a contract names an exact revision or nothing).
 */
async function draftContract(root, { id, now }) {
  const idx = (0,store/* readStoreJson */.WS)(root, 'index.json');
  if (!idx.ok) return { ok: false, reason: `no context build for ${root} (${idx.code}); run \`context build\` first` };
  const index = idx.value;
  const commit = index.repository?.commit;
  if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(String(commit || ''))) return { ok: false, reason: 'the context build records no exact commit for this root; a contract names an exact revision, so commit the tree and rebuild the context first' };
  const notes = [];
  const byDim = { authentication: [], 'authorization-role': [], ownership: [] };
  const controls = new Map();
  for (const e of index.entrypoints || []) {
    if (!e.contextHash) continue;
    const m = (0,store/* readStoreJson */.WS)(root, `bundles/${e.contextHash}/manifest.json`);
    if (!m.ok) { notes.push(`bundle ${e.contextHash.slice(0, 12)} unreadable (${m.code})`); continue; }
    const prot = m.value.protection || {};
    for (const dim of Object.keys(byDim)) if (prot[dim]?.state === 'present') byDim[dim].push(e.label);
    for (const c of m.value.controls || []) {
      const key = `${c.kind}|${c.file}|${c.line}`;
      if (!controls.has(key)) controls.set(key, { id: `${c.kind}-${c.file}-${c.line}`.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60), kind: c.kind, statement: `${c.kind} control observed at ${c.file}:${c.line} (${c.basis}, ${c.evidence})`, source: 'declared', provenance: { file: c.file, line: c.line }, scope: { environment: 'isolated-test', routes: [] } });
      controls.get(key).scope.routes.push(e.label);
    }
  }
  const statements = { authentication: 'Every listed entry point requires an authenticated principal.', 'authorization-role': 'Every listed entry point requires the role the route is reserved for.', ownership: 'A principal reads and modifies only records owned by its own tenant or account.' };
  const invariants = [];
  for (const [dim, labels] of Object.entries(byDim)) {
    if (!labels.length) continue;
    const uniq = [...new Set(labels)].sort().slice(0, 64);
    invariants.push({ id: `${dim.toUpperCase().replace(/[^A-Z0-9]+/g, '-')}-001`, statement: statements[dim], attacker: { principal: dim === 'authentication' ? 'anonymous' : 'authenticated', assumptions: ['reaches the entry point over the network'], entryPoints: uniq }, scope: { routes: uniq }, boundaries: [dim === 'ownership' ? 'tenant' : 'identity'], requiredEvidence: [dim === 'ownership' ? 'cross-tenant-attempt' : 'forbidden-request'] });
  }
  if (!invariants.length) notes.push('the context build observed no present control on any entry point; the draft declares no invariant and a reviewer must write them');
  const contract = (0,schema/* createContract */.NF)({
    id, version: '0.1.0', owner: 'reviewer assigns the owner', summary: `Draft from the context build of ${external_node_path_.basename(root)}: ${(index.entrypoints || []).length} entry point(s), ${invariants.length} inferred invariant(s). A reviewer rewrites this summary.`,
    reviewPriority: 'normal', reviewedAt: now, expiry: { reviewEveryDays: 90 },
    scope: { environment: 'isolated-test', repositories: [{ id, revision: commit }] },
    invariants: invariants.length ? invariants : [{ id: 'REVIEWER-WRITES-001', statement: 'A reviewer states the first invariant of this service.', attacker: { principal: 'anonymous', assumptions: ['none stated'] }, requiredEvidence: ['forbidden-request'] }],
    controls: [...controls.values()].slice(0, 64).map((c) => ({ ...c, scope: { ...c.scope, routes: [...new Set(c.scope.routes)].sort().slice(0, 64) } })),
    review: { state: 'proposed', origin: 'inferred', note: 'drafted deterministically from the context build; no model consulted' },
  });
  const v = (0,schema/* validateContract */.T7)(contract);
  if (!v.ok) return { ok: false, reason: `the draft does not validate: ${v.errors.map((e) => `${e.path}: ${e.message}`).join('; ')}` };
  return { ok: true, contract, notes };
}


/***/ })

};
