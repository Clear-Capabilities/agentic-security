// CLI surface: `agentic-security rules synthesize|evaluate|promote|status|rollback|cost|regress`.
//
// Distinct from the pre-existing `labs synthesize-rule` (posture/rule-synthesis.js), which proposes SUPPRESSION
// rules from repeated false-positive triage verdicts — a different input, a different output and a different
// command group on purpose, so the two are never confused at the CLI.
//
// Non-interactive by construction: no command reads stdin, every corpus evaluation is bounded (no network, no
// model call — this is the deterministic half; a model may PROPOSE the candidate pattern this CLI is handed, but
// it never decides promotion).
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { statePath } from '../state-dir.js';
import { packTrust, signPublishedRule, publicKeyOf } from './store.js';
import { sharedFalsePositiveCorpus, falsePositiveHits, regressRules, promotedRuleIds, corpusHash } from './regression.js';
import { draftRuleIR, validateRuleIR, ruleIRDigest } from './ir.js';
import { checkEligibility } from './eligibility.js';
import { buildCorpus } from './corpus.js';
import { gatePromotion, checkLeakage, PROMOTION_DEFAULTS } from './promotion.js';
import { recordTransition, stateOf, historyFor } from './lifecycle.js';
import { loadLedger, saveLedger, saveIR, loadIR, saveEvaluation, writeFixtures, publishCustomRule, unpublishCustomRule, saveCorpus, loadCorpus, saveSynthesis, loadSynthesis, loadProvenance, saveProvenance } from './store.js';
import { synthesizeCandidate } from './proposal.js';
import { mutatorCoverage } from './mutation.js';
import { sha256 } from '../proof-fabric/reproducer.js';

function loadFinding(root, id) {
  const p = statePath(root, 'last-scan.json');
  if (!fs.existsSync(p)) return null;
  const last = JSON.parse(fs.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

function readJsonArg(pathOrInline) {
  if (!pathOrInline) return null;
  try { return JSON.parse(fs.existsSync(pathOrInline) ? fs.readFileSync(pathOrInline, 'utf8') : pathOrInline); } catch { return null; }
}

export async function cmdRules(args, root) {
  const sub = args._[1];
  // GA-07: a ledger that failed its integrity check (broken chain, bad or missing signature) refuses EVERY command, not only the
  // ones that change state; nothing below can read a tampered history as fact or write over it.
  if (['synthesize', 'evaluate', 'promote', 'status', 'rollback', 'deprecate', 'cost', 'regress'].includes(sub)) {
    const guard = loadLedger(root);
    if (guard.tampered) { console.error(`Refusing: rule lifecycle ledger failed its integrity check (${guard.tamperReason}).`); return 4; }
  }
  if (sub === 'synthesize') return cmdSynthesize(args, root);
  if (sub === 'evaluate') return cmdEvaluate(args, root);
  if (sub === 'promote') return cmdPromote(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'rollback') return cmdRollback(args, root);
  if (sub === 'deprecate') return cmdDeprecate(args, root);
  if (sub === 'cost') return cmdCost(args, root);
  if (sub === 'regress') return cmdRegress(args, root);
  console.error('usage: rules synthesize <finding-id> --spec <file.json> [--auto] [--max-attempts N] | evaluate <rule-id> | promote <rule-id> --reviewed-by <person> --scope <text> [--sign-key <base64>] | status [rule-id] | rollback <rule-id> | deprecate <rule-id> | cost <rule-id> | regress [rule-id]');
  return 4;
}

/** The operator's Ed25519 key, when given: it signs the published rule AND the ledger, so a clone without this install's HMAC key can
 * still verify the lifecycle history (store.js loadLedger). Never stored. */
function authorKeyFrom(args) { return args.flags['sign-key'] ?? process.env.AGENTIC_SECURITY_PRIVATE_KEY ?? null; }

/** Every command that changes the ledger saves it through here, so an author signature made at promotion is renewed by a later
 * rollback or evaluation run with the same key instead of going stale (a stale one would read as tampering on the next clone). */
function persistLedger(root, ledger, args) {
  const r = saveLedger(root, ledger, { authorKey: authorKeyFrom(args) });
  if (!r.ok && r.reason) console.error(r.reason);
  return r;
}

// `--spec` carries exactly what a model or a human proposed: id/title/severity/cwe/family/languages/match/
// remediation plus the corpus inputs (originalCode/patchedCode/nearbyCleanCode/protectedVariantsCode). This
// command never invents a pattern; it only drafts the IR, checks eligibility and records DRAFT->CANDIDATE.
async function cmdSynthesize(args, root) {
  const findingId = args._[2];
  const spec = readJsonArg(args.flags.spec);
  if (!findingId || !spec) { console.error('usage: rules synthesize <finding-id> --spec <file.json>'); return 4; }
  const finding = loadFinding(root, findingId);
  if (!finding) { console.error(`Finding ${findingId} not found in last scan.`); return 4; }
  const elig = checkEligibility(finding, { proofState: args.flags['proof-state'] || null });
  if (!elig.eligible) { console.error(`Not eligible for rule synthesis: ${elig.reasons.join('; ')}`); return 4; }

  // The candidate pattern is the model's or the person's, when they gave one. Without one, or with --auto, the synthesis loop proposes
  // from the vulnerable and patched code, scores each attempt on the real corpus and its mutations, and revises (see proposal.js).
  let finalSpec = spec; let synthesis = null;
  const corpusSpec = { originalCode: spec.originalCode, patchedCode: spec.patchedCode ?? null, nearbyCleanCode: spec.nearbyCleanCode ?? [], protectedVariantsCode: spec.protectedVariantsCode ?? [], independentVulnerableCode: spec.independentVulnerableCode ?? [], independentCleanCode: spec.independentCleanCode ?? [] };
  const leak = checkLeakage(JSON.stringify(corpusSpec), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: spec.fileNames ?? [] });
  if (!leak.ok) { console.error(`Refusing: the material for this rule shows benchmark or answer-key signals (${leak.offendingTerms.join('; ')}). Nothing was written.`); return 4; }
  if (args.flags.auto || (!spec.match && !spec.sink)) {
    if (!isStr(spec.originalCode)) { console.error('Automatic proposal needs originalCode (the vulnerable snippet) in the spec.'); return 4; }
    const { id, title, severity, cwe, family, languages, remediation } = spec;
    synthesis = synthesizeCandidate({ base: { id, title, severity, cwe, family, languages, remediation, originatingFindingId: finding.stableId ?? finding.id, evidenceState: elig.evidenceState }, corpusSpec, proposed: spec.match ?? null, maxAttempts: Number(args.flags['max-attempts']) || 6, leakageOk: true });
    for (const a of synthesis.attempts) console.log(`  attempt ${a.n}: ${a.strategy.padEnd(34)} ${a.valid ? `precision ${fmtPct(a.score.precision)}  recall ${fmtPct(a.score.recall)}  protected-failures ${a.score.protectedFailures}${a.pass ? '  PASS' : ''}` : `invalid (${a.errors[0]})`}`);
    if (!synthesis.best) { console.error('No valid candidate could be proposed from this material.'); return 1; }
    finalSpec = { ...spec, ...(synthesis.best.match ? { match: synthesis.best.match } : {}), ...(synthesis.best.structure ?? {}) };
    console.log(synthesis.best.pass ? `  candidate meets the promotion gate on this corpus (not yet recorded as VALIDATED).` : `  no attempt met the gate; the best is kept as a CANDIDATE only: ${synthesis.best.reasons.join('; ')}`);
  }
  const ir = draftRuleIR({ ...finalSpec, originatingFindingId: finding.stableId ?? finding.id, originatingCommit: spec.originatingCommit ?? null, evidenceState: elig.evidenceState });
  const errs = validateRuleIR(ir);
  if (errs.length) { console.error(`Invalid rule: ${errs.join('; ')}`); return 4; }

  const ledger = loadLedger(root);
  // GA-07 (0.195.27): a rule that was rolled back re-enters as a CANDIDATE (the ledger's ROLLED_BACK -> CANDIDATE edge), keeping its
  // history; any other existing state refuses, so a promoted or validated rule cannot be silently re-drafted over.
  const current = stateOf(ledger, ir.id);
  if (current !== null && current !== 'ROLLED_BACK') { console.error(`Rule ${ir.id} already exists in state ${current}; roll it back first, or choose another id.`); return 4; }
  if (current === null) {
    const draft = recordTransition(ledger, { ruleId: ir.id, from: null, to: 'DRAFT', reason: `drafted from ${findingId}`, actor: args.flags.actor || 'agent' });
    if (!draft.ok) { console.error(draft.reason); return 4; }
  }
  const cand = recordTransition(ledger, { ruleId: ir.id, from: current === null ? 'DRAFT' : 'ROLLED_BACK', to: 'CANDIDATE', reason: current === null ? 'eligibility passed' : `re-entered after rollback; eligibility passed (drafted again from ${findingId})`, evidence: { eligibility: elig }, actor: args.flags.actor || 'agent' });
  persistLedger(root, ledger, args);
  saveIR(root, { ...ir, state: 'CANDIDATE' });
  saveCorpus(root, ir.id, { ...corpusSpec, fileNames: spec.fileNames ?? [], discoveryCost: spec.discoveryCost ?? (args.flags['discovery-cost-usd'] ? { usd: Number(args.flags['discovery-cost-usd']), tokens: Number(args.flags['discovery-tokens']) || null, model: spec.model ?? null } : null) });
  if (synthesis) saveSynthesis(root, ir.id, { attempts: synthesis.attempts, best: synthesis.best });
  console.log(`Rule ${ir.id}: DRAFT -> CANDIDATE (digest ${ruleIRDigest(ir).slice(0, 12)})`);
  if (!cand.ok) console.error(cand.reason);
  return 0;
}

async function cmdEvaluate(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules evaluate <rule-id> --corpus <file.json>'); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}. Run rules synthesize first.`); return 4; }
  const corpusSpec = readJsonArg(args.flags.corpus) ?? loadCorpus(root, id);
  if (!corpusSpec) { console.error('No corpus supplied. Pass --corpus <file.json> with originalCode (and optionally patchedCode/nearbyCleanCode/protectedVariantsCode).'); return 4; }
  const corpus = buildCorpus(ir, corpusSpec);
  // the corpus a rule is evaluated on is the evidence for it: keep it, so `rules regress` and the shared false-positive corpus use the SAME code
  if (args.flags.corpus) saveCorpus(root, id, { ...(loadCorpus(root, id) ?? {}), ...corpusSpec });
  const leakage = checkLeakage(JSON.stringify({ ...corpusSpec, fileNames: undefined, discoveryCost: undefined }), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: corpusSpec.fileNames ?? [] });
  const gate = gatePromotion({ ir, corpus, leakageCheck: leakage, thresholds: args.flags.thresholds ? readJsonArg(args.flags.thresholds) : PROMOTION_DEFAULTS });

  const ledger = loadLedger(root);
  // the shared false-positive corpus: the safe code of every other promoted rule, plus the operator's own files. Part of the gate.
  const fpItems = sharedFalsePositiveCorpus(root, ledger, id);
  const fpHits = falsePositiveHits(ir, fpItems);
  gate.fpCorpus = { items: fpItems.length, hits: fpHits.map((h) => h.label) };
  if (fpHits.length) { gate.pass = false; gate.reasons.push(`fires on ${fpHits.length} of ${fpItems.length} item(s) in the shared false-positive corpus: ${fpHits.slice(0, 3).map((h) => h.label).join(', ')}${fpHits.length > 3 ? ', ...' : ''}`); }
  const cur = stateOf(ledger, id);
  if (gate.pass && cur === 'CANDIDATE') recordTransition(ledger, { ruleId: id, from: 'CANDIDATE', to: 'VALIDATED', reason: 'promotion gate passed', evidence: { score: gate.evaluation.score }, actor: args.flags.actor || 'agent' });
  persistLedger(root, ledger, args);
  saveEvaluation(root, id, gate);
  const prev = loadProvenance(root, id);
  saveProvenance(root, id, {
    schema: 'agentic-security/rule-provenance', version: 1, ruleId: id, ruleVersion: 1, ruleHash: ruleIRDigest(ir),
    originatingFinding: ir.provenance.originatingFindingId, originatingCommit: ir.provenance.originatingCommit, evidenceState: ir.provenance.evidenceState,
    generatingModel: ir.provenance.model, promptConfigVersion: ir.provenance.promptConfigVersion,
    positiveCorpusHash: corpusHash(corpus.positives), negativeCorpusHash: corpusHash(corpus.negatives),
    benchmarkResults: { precision: gate.evaluation.score.precision, recall: gate.evaluation.score.recall, tp: gate.evaluation.score.tp, fp: gate.evaluation.score.fp, fn: gate.evaluation.score.fn, tn: gate.evaluation.score.tn, protectedFailures: gate.evaluation.score.protectedFailures, independent: gate.independent, thresholds: gate.evaluation.thresholds, gate: gate.pass ? 'passed' : 'failed', reasons: gate.reasons },
    leakageCheck: leakage, mutatorCoverage: mutatorCoverage(corpusSpec.originalCode), discoveryCost: corpusSpec.discoveryCost ?? prev?.discoveryCost ?? null,
    promotionEvent: prev?.promotionEvent ?? null, evaluatedAt: new Date().toISOString(),
  });
  if (args.flags.json) console.log(JSON.stringify(gate, null, 2));
  else {
    console.log(`Rule ${id}: ${gate.pass ? 'VALIDATED' : 'gate FAILED'}`);
    console.log(`  precision ${fmtPct(gate.evaluation.score.precision)}  recall ${fmtPct(gate.evaluation.score.recall)}  protected-failures ${gate.evaluation.score.protectedFailures}`);
    for (const r of gate.reasons) console.log(`  - ${r}`);
  }
  if (gate.pass) { const f = writeFixtures(root, ir, corpus); if (f.ok) console.log(`  regression fixtures written: ${f.written.length} file(s) under .agentic-security/rule-compiler/${id}/fixtures/`); }
  return gate.pass ? 0 : 1;
}
function isStr(v) { return typeof v === 'string' && v.length > 0; }
const fmtPct = (n) => (n == null ? 'unmeasured' : `${(n * 100).toFixed(1)}%`);

/** Does this commit exist in the project's history? `true`, `false`, or `null` when the project is not a git repository. */
function commitExists(root, sha) {
  if (!fs.existsSync(path.join(root, '.git'))) return null;
  try { execFileSync('git', ['cat-file', '-e', `${sha}^{commit}`], { cwd: root, stdio: 'ignore' }); return true; } catch { return false; }
}

const NOT_A_REVIEWER = /^(?:agent|model|auto|bot|llm|ai)$/i;

// Promotion is a reviewed, human decision (GA-07). It needs the reviewer's name, a rule that is exactly the one that was evaluated, a
// provenance that checks out, and no conflict with a rule that already exists; a model's recommendation on its own promotes nothing.
async function cmdPromote(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules promote <rule-id> --reviewed-by <person> [--scope <text>] [--reason <text>]'); return 4; }
  const reviewer = args.flags['reviewed-by'];
  if (!isStr(reviewer) || NOT_A_REVIEWER.test(reviewer.trim())) {
    console.error('usage: rules promote <rule-id> --reviewed-by <person> --scope <text>. A promotion records the person who reviewed the rule and its scope; a model or agent recommendation is not a review, so nothing is promoted without a named reviewer.');
    return 4;
  }
  // GA-07 §3 (0.195.27): the reviewed SCOPE (what the rule is for, where it applies, what it must not flag) is part of the review
  // record, not an optional note; a promotion without one records nothing a later reader could hold the rule to.
  if (!isStr(args.flags.scope)) {
    console.error('usage: rules promote <rule-id> --reviewed-by <person> --scope <text>. The reviewed scope is recorded with the promotion; state what the rule covers and where it applies.');
    return 4;
  }
  const ledger = loadLedger(root);
  if (ledger.tampered) { console.error(`Refusing: rule lifecycle ledger failed its integrity check (${ledger.tamperReason}).`); return 4; }
  if (stateOf(ledger, id) !== 'VALIDATED') { console.error(`Rule ${id} is not VALIDATED (run rules evaluate first); refusing to promote.`); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}.`); return 4; }
  // the rule promoted must be the rule evaluated: an IR edited after `rules evaluate` has no evidence
  const prov = loadProvenance(root, id);
  if (!prov) { console.error(`Promotion refused: no evaluation record for ${id}; run rules evaluate first.`); return 4; }
  if (prov.ruleHash !== ruleIRDigest(ir)) { console.error(`Promotion refused: the rule ${id} changed after it was evaluated (evaluated ${String(prov.ruleHash).slice(0, 12)}, now ${ruleIRDigest(ir).slice(0, 12)}); run rules evaluate again.`); return 4; }
  // a named originating commit must be real history, not a typed-in string
  const commit = ir.provenance?.originatingCommit;
  if (commit) {
    const exists = commitExists(root, commit);
    if (exists === false) { console.error(`Promotion refused: originating commit ${commit} is not in this repository's history (invalid provenance).`); return 4; }
    if (exists === null) { console.error(`Promotion refused: originating commit ${commit} cannot be verified because this project is not a git repository.`); return 4; }
  }
  // conflicts: a hand-written rule file with the same id, or a promoted rule with the identical match
  const live = statePath(root, 'rules', `${id}.yml`);
  let firstLine = null; // null: no file there (or unreadable, which is treated as absent below only when the read fails with ENOENT)
  try { firstLine = fs.readFileSync(live, 'utf8').split('\n')[0]; } catch (e) { if (e.code !== 'ENOENT') firstLine = ''; }
  if (firstLine !== null && !firstLine.startsWith('# Compiled by the rule compiler')) { console.error(`Promotion refused: a rule file that the compiler did not write already exists at ${live}; choose another rule id or remove that file deliberately.`); return 4; }
  for (const other of promotedRuleIds(ledger)) {
    if (other === id) continue;
    const oir = loadIR(root, other);
    if (oir && JSON.stringify(oir.match) === JSON.stringify(ir.match) && JSON.stringify(oir.languages) === JSON.stringify(ir.languages)) {
      console.error(`Promotion refused: ${id} duplicates the promoted rule ${other} (identical match on the same languages); roll one back or narrow this one.`);
      return 4;
    }
  }
  // other rules may have been promoted since this one was evaluated: hold it to the false-positive corpus as it is NOW
  const fpNow = falsePositiveHits(ir, sharedFalsePositiveCorpus(root, ledger, id));
  if (fpNow.length) { console.error(`Promotion refused: ${id} fires on ${fpNow.length} item(s) of the shared false-positive corpus (${fpNow.slice(0, 3).map((h) => h.label).join(', ')}). Re-evaluate or narrow the rule.`); return 1; }
  const pub = publishCustomRule(root, ir);
  if (!pub.ok) { console.error(`Promotion refused: ${pub.reason}`); return 4; }
  const scope = args.flags.scope.trim();
  // GA-07 §3 (0.195.27): the evidence the reviewer looked at, digested into the promotion: the evaluation and provenance records
  // as they stood, and the two corpus halves. `rules regress` re-derives the corpus digests and reports a rule whose corpus moved
  // after the review as no longer the reviewed one.
  const corpusNow = buildCorpus(ir, loadCorpus(root, id) ?? {});
  const evidence = {
    reviewer: reviewer.trim(), scope, independent: prov.benchmarkResults?.independent ?? null, ruleHash: ruleIRDigest(ir),
    evaluationDigest: sha256(JSON.stringify(readJsonArg(path.join(statePath(root, 'rule-compiler', id), 'evaluation.json')))),
    provenanceDigest: sha256(JSON.stringify({ ...prov, promotionEvent: undefined })),
    positiveCorpusHash: corpusHash(corpusNow.positives), negativeCorpusHash: corpusHash(corpusNow.negatives),
    sharedFalsePositiveItems: sharedFalsePositiveCorpus(root, ledger, id).length,
  };
  const t = recordTransition(ledger, { ruleId: id, from: 'VALIDATED', to: 'PROMOTED', reason: args.flags.reason || 'promoted', evidence, actor: args.flags.actor || reviewer.trim() });
  const saved = persistLedger(root, ledger, args);
  saveProvenance(root, id, { ...prov, promotionEvent: { at: new Date().toISOString(), actor: args.flags.actor || reviewer.trim(), reviewer: reviewer.trim(), scope, reason: args.flags.reason || 'promoted', ruleHash: ruleIRDigest(ir), evidence } });
  console.log(`Rule ${id}: VALIDATED -> PROMOTED. Published to ${pub.file}.`);
  // Publishing is not trusting. Rule packs are signature-checked so a rule dropped into a repository cannot run in someone's CI; sign this
  // one with the operator's key when there is one, and say plainly whether the scanner will load it. The same key author-signs the
  // ledger, which is what lets `rules regress` on another machine (CI) verify the history without this install's HMAC key.
  const key = authorKeyFrom(args);
  if (key) {
    const sg = signPublishedRule(pub.file, key); console.log(sg.ok ? `  signed: ${pub.file}.sig` : `  could not sign (${sg.reason}); the rule is published unsigned`);
    console.log(saved.authorSigned ? `  ledger author-signed; another machine verifies it with AGENTIC_SECURITY_RULES_PUBLIC_KEY=${publicKeyOf(key)}` : '  ledger NOT author-signed; rules regress on another machine will refuse it');
  } else {
    console.log('  no --sign-key: the ledger carries only this install\'s signature, so rules regress on another machine (CI) will refuse it; promote with --sign-key <base64> to make it portable');
  }
  const trust = packTrust(root, id);
  console.log(trust.live ? `  The scanner will load it (${trust.via}).` : `  NOT LIVE YET: the scanner will refuse this rule (${trust.reason}). To make it live: ${trust.remediation}.`);
  if (!t.ok) console.error(t.reason);
  return 0;
}

/** `rules regress [rule-id]`: re-score every PROMOTED rule against its own corpus and the shared false-positive corpus. Exit 1 on any regression. */
async function cmdRegress(args, root) {
  const ledger = loadLedger(root);
  if (ledger.tampered) { console.error(`Refusing: rule lifecycle ledger failed its integrity check (${ledger.tamperReason}).`); return 4; }
  const only = args._[2] ?? null;
  const results = regressRules(root, ledger, { only, thresholds: args.flags.thresholds ? readJsonArg(args.flags.thresholds) : undefined });
  if (args.flags.json) console.log(JSON.stringify({ ledgerVerifiedBy: ledger.verifiedBy ?? null, results }, null, 2));
  else if (!results.length) console.log(only ? `No promoted rule ${only}.` : 'No rule is PROMOTED; nothing to regress.');
  else for (const r of results) { console.log(`${r.id}: ${r.status.toUpperCase()}${r.precision != null ? `  precision ${fmtPct(r.precision)}  recall ${fmtPct(r.recall)}  false-positive corpus hits ${r.fpCorpusHits}` : ''}`); for (const m of r.reasons) console.log(`  - ${m}`); }
  if (!args.flags.json && results.length) console.log(`ledger verified by ${ledger.verifiedBy === 'author-key' ? `the author key (${ledger.authorKeyId})` : ledger.verifiedBy === 'install-key' ? 'this install\'s key' : 'nothing (unsigned, accepted by AGENTIC_SECURITY_RULES_UNSIGNED=1)'}`);
  if (only && !results.length) return 4;
  return results.every((r) => r.status === 'ok') ? 0 : 1;
}

async function cmdRollback(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules rollback <rule-id> [--reason text]'); return 4; }
  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (cur !== 'PROMOTED') { console.error(`Rule ${id} is not PROMOTED (current: ${cur ?? 'unknown'}); nothing to roll back.`); return 4; }
  const un = unpublishCustomRule(root, id);
  const t = recordTransition(ledger, { ruleId: id, from: 'PROMOTED', to: 'ROLLED_BACK', reason: args.flags.reason || 'operator rollback', actor: args.flags.actor || 'operator' });
  persistLedger(root, ledger, args);
  console.log(`Rule ${id}: PROMOTED -> ROLLED_BACK.${un.ok ? '' : ` (warning: could not remove published rule file: ${un.reason})`}`);
  return t.ok ? 0 : 1;
}

/** `rules deprecate <rule-id>`: retire a promoted rule for good (PROMOTED -> DEPRECATED, a terminal state); the published file is removed. */
async function cmdDeprecate(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules deprecate <rule-id> [--reason text]'); return 4; }
  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (cur !== 'PROMOTED') { console.error(`Rule ${id} is not PROMOTED (current: ${cur ?? 'unknown'}); only a promoted rule can be deprecated (roll back a candidate instead).`); return 4; }
  const un = unpublishCustomRule(root, id);
  const t = recordTransition(ledger, { ruleId: id, from: 'PROMOTED', to: 'DEPRECATED', reason: args.flags.reason || 'operator deprecation', actor: args.flags.actor || 'operator' });
  persistLedger(root, ledger, args);
  console.log(`Rule ${id}: PROMOTED -> DEPRECATED (terminal).${un.ok ? '' : ` (warning: could not remove published rule file: ${un.reason})`}`);
  return t.ok ? 0 : 1;
}

async function cmdStatus(args, root) {
  const ledger = loadLedger(root);
  const id = args._[2];
  if (id) {
    const h = historyFor(ledger, id);
    if (!h.length) { console.error(`No history for rule ${id}.`); return 4; }
    if (args.flags.json) console.log(JSON.stringify(h, null, 2));
    else { console.log(`Rule ${id}: ${stateOf(ledger, id)}`);
      if (stateOf(ledger, id) === 'PROMOTED') { const tr = packTrust(root, id); console.log(tr.live ? `  live: yes (${tr.via})` : `  live: NO, the scanner refuses it (${tr.reason}). ${tr.remediation}.`); }
      for (const e of h) console.log(`  ${e.at}  ${e.from ?? '(new)'} -> ${e.to}  (${e.reason || ''})`); 
      const syn = loadSynthesis(root, id);
      if (syn?.attempts?.length) { console.log(`  synthesis: ${syn.attempts.length} attempt(s), best ${syn.best ? `${syn.best.strategy}${syn.best.pass ? ' (met the gate)' : ' (did not meet the gate)'}` : 'none'}`); }
    }
    return 0;
  }
  const ids = [...new Set(ledger.entries.map((e) => e.ruleId))];
  if (args.flags.json) { console.log(JSON.stringify(ids.map((rid) => ({ id: rid, state: stateOf(ledger, rid), ...(stateOf(ledger, rid) === 'PROMOTED' ? { live: packTrust(root, rid).live } : {}) })), null, 2)); return 0; }
  if (!ids.length) { console.log('No rules in the lifecycle ledger yet.'); return 0; }
  for (const rid of ids) console.log(`  ${rid.padEnd(40)} ${stateOf(ledger, rid)}${stateOf(ledger, rid) === 'PROMOTED' && !packTrust(root, rid).live ? '  (NOT LIVE: the scanner refuses it)' : ''}`);
  return 0;
}

// PRD 3 business metric: what the first, model-assisted discovery cost, against what every later deterministic detection costs.
// The discovery cost is whatever the agent run reported for it (recorded at synthesis); a deterministic detection makes no model
// call and is $0 of model spend. The count of later detections is read from the LAST scan only, so it is a floor, not a history.
async function cmdCost(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules cost <rule-id>'); return 4; }
  const prov = loadProvenance(root, id);
  if (!prov) { console.error(`No provenance for ${id}. Run rules evaluate first.`); return 4; }
  let detections = null;
  try { const last = JSON.parse(fs.readFileSync(statePath(root, 'last-scan.json'), 'utf8')); detections = (last.findings || []).filter((f) => String(f.id || '').startsWith(`custom:rule-compiler/${id}:`)).length; } catch { /* no scan */ }
  const first = prov.discoveryCost;
  const out = { ruleId: id, firstDiscovery: first ? { usd: first.usd ?? null, tokens: first.tokens ?? null, model: first.model ?? null } : null, laterDeterministicDetections: detections, laterDeterministicModelUsd: 0, state: prov.promotionEvent ? 'promoted' : 'not promoted' };
  if (args.flags.json) { console.log(JSON.stringify(out, null, 2)); return 0; }
  console.log(`Rule ${id} (${out.state})`);
  console.log(first ? `  first discovery: ${first.usd != null ? `$${first.usd}` : 'cost not recorded'}${first.tokens ? `, ${first.tokens} tokens` : ''}${first.model ? `, ${first.model}` : ''}` : '  first discovery: cost was not recorded for this rule');
  console.log(`  later detections by this rule in the last scan: ${detections ?? 'no scan available'}, each at $0 of model spend`);
  if (first?.usd != null && detections) console.log(`  discovery cost spread over ${detections + 1} detection(s): $${(first.usd / (detections + 1)).toFixed(4)} each, falling with every further one`);
  return 0;
}
