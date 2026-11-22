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
import * as fs from 'node:fs';
import * as path from 'node:path';
import { validateContract, contractRef, bindingView, createContract } from './schema.js';
import { reconcilePack } from './pack.js';
import { approvalState } from './approval.js';
import { readStoreJson } from '../context-intelligence/store.js';

const SAFE = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]/g, '?').slice(0, 300);

async function readJson(file) {
  try { return { ok: true, value: JSON.parse(await fs.promises.readFile(file, 'utf8')) }; } catch (e) { return { ok: false, reason: `${file}: ${String(e?.message || e).slice(0, 120)}` }; }
}
async function readText(file) { try { return await fs.promises.readFile(file, 'utf8'); } catch { return null; } }

/** Load a contract, its pack and (optionally) its ledger for a hunt. Pure of the clock: `now` is given. */
export async function loadContractForHunt({ contractPath, ledgerPath = null, scanRoot = null, now }) {
  const c = await readJson(contractPath);
  if (!c.ok) return { ok: false, reason: `the contract could not be read: ${c.reason}` };
  const v = validateContract(c.value);
  if (!v.ok) return { ok: false, reason: 'the contract does not validate', errors: v.errors.map((e) => `${e.path}: ${e.message}`) };
  const warnings = [];
  if (c.value.threatPack) {
    const r = reconcilePack(c.value, await readText(path.join(path.dirname(contractPath), c.value.threatPack.path)));
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
  const r = await readJson(path.join(scanRoot, '.agentic-security', 'reviewer-policy.json'));
  if (!r.ok || !r.value || !Array.isArray(r.value.reviewers)) return null;
  return { id: typeof r.value.id === 'string' ? r.value.id : 'local', reviewers: r.value.reviewers.filter((x) => typeof x === 'string') };
}

export async function cmdContracts(args) {
  const sub = args._[1];
  const file = args._[2] ? path.resolve(String(args._[2])) : null;
  const now = new Date().toISOString().slice(0, 10);
  if (sub === 'validate') {
    if (!file) { console.error('usage: agentic-security contracts validate <contract.json>'); return 2; }
    const c = await readJson(file); if (!c.ok) { console.error(c.reason); return 1; }
    const v = validateContract(c.value);
    if (!v.ok) { console.log(`INVALID ${SAFE(file)}`); for (const e of v.errors) console.log(`  ${e.code} ${e.path}: ${SAFE(e.message)}`); return 1; }
    console.log(`valid ${contractRef(c.value)}`);
    if (c.value.threatPack) {
      const r = reconcilePack(c.value, await readText(path.join(path.dirname(file), c.value.threatPack.path)));
      if (!r.ok) { for (const i of r.issues) console.log(`  pack: ${i.code}: ${SAFE(i.message)}`); return 1; }
      console.log(`  pack: ${c.value.threatPack.path} agrees (${r.parsed.invariantIds.length} invariant id(s) named)`);
    }
    return 0;
  }
  if (sub === 'inspect') {
    if (!file) { console.error('usage: agentic-security contracts inspect <contract.json> [--ledger <file>] [--root <dir>]'); return 2; }
    const c = await readJson(file); if (!c.ok) { console.error(c.reason); return 1; }
    const v = validateContract(c.value);
    if (!v.ok) { console.log(`INVALID ${SAFE(file)}`); for (const e of v.errors) console.log(`  ${e.code} ${e.path}: ${SAFE(e.message)}`); return 1; }
    const root = args.flags.root ? path.resolve(String(args.flags.root)) : null;
    const out = { schema: 'agentic-security/contract-inspection', contractRef: contractRef(c.value), id: c.value.id, version: c.value.version, owner: c.value.owner, reviewPriority: c.value.reviewPriority, reviewedAt: c.value.reviewedAt, expiry: c.value.expiry, scope: c.value.scope, approval: null, bindings: bindingView(c.value), pack: null, context: null };
    if (args.flags.ledger) {
      const l = await readJson(path.resolve(String(args.flags.ledger)));
      out.approval = l.ok ? approvalState(c.value, l.value, { policy: await reviewerPolicyFor(root), now }) : { state: 'approval-unverifiable', reasons: [l.reason] };
    } else out.approval = { state: 'not-recorded', current: false, reasons: ['no --ledger given'] };
    if (c.value.threatPack) {
      const r = reconcilePack(c.value, await readText(path.join(path.dirname(file), c.value.threatPack.path))); out.pack = { path: c.value.threatPack.path, agrees: r.ok, issues: r.issues };
    }
    if (root) {
      const idx = readStoreJson(root, 'index.json'); // the store's own reader (link-safe)
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
    const root = args.flags.root ? path.resolve(String(args.flags.root)) : null;
    if (!root) { console.error('usage: agentic-security contracts draft --root <dir> [--out <contract.json>] [--id <service-id>]'); return 2; }
    const d = await draftContract(root, { id: args.flags.id ? String(args.flags.id) : path.basename(root).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'service', now });
    if (!d.ok) { console.error(d.reason); return 1; }
    const text = JSON.stringify(d.contract, null, 2) + '\n';
    if (args.flags.out) { await fs.promises.writeFile(path.resolve(String(args.flags.out)), text); console.log(`drafted ${contractRef(d.contract)} -> ${SAFE(args.flags.out)} (PROPOSED: a reviewer approves it in the ledger, or nothing it says is authority)`); }
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
export async function draftContract(root, { id, now }) {
  const idx = readStoreJson(root, 'index.json');
  if (!idx.ok) return { ok: false, reason: `no context build for ${root} (${idx.code}); run \`context build\` first` };
  const index = idx.value;
  const commit = index.repository?.commit;
  if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(String(commit || ''))) return { ok: false, reason: 'the context build records no exact commit for this root; a contract names an exact revision, so commit the tree and rebuild the context first' };
  const notes = [];
  const byDim = { authentication: [], 'authorization-role': [], ownership: [] };
  const controls = new Map();
  for (const e of index.entrypoints || []) {
    if (!e.contextHash) continue;
    const m = readStoreJson(root, `bundles/${e.contextHash}/manifest.json`);
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
  const contract = createContract({
    id, version: '0.1.0', owner: 'reviewer assigns the owner', summary: `Draft from the context build of ${path.basename(root)}: ${(index.entrypoints || []).length} entry point(s), ${invariants.length} inferred invariant(s). A reviewer rewrites this summary.`,
    reviewPriority: 'normal', reviewedAt: now, expiry: { reviewEveryDays: 90 },
    scope: { environment: 'isolated-test', repositories: [{ id, revision: commit }] },
    invariants: invariants.length ? invariants : [{ id: 'REVIEWER-WRITES-001', statement: 'A reviewer states the first invariant of this service.', attacker: { principal: 'anonymous', assumptions: ['none stated'] }, requiredEvidence: ['forbidden-request'] }],
    controls: [...controls.values()].slice(0, 64).map((c) => ({ ...c, scope: { ...c.scope, routes: [...new Set(c.scope.routes)].sort().slice(0, 64) } })),
    review: { state: 'proposed', origin: 'inferred', note: 'drafted deterministically from the context build; no model consulted' },
  });
  const v = validateContract(contract);
  if (!v.ok) return { ok: false, reason: `the draft does not validate: ${v.errors.map((e) => `${e.path}: ${e.message}`).join('; ')}` };
  return { ok: true, contract, notes };
}
