export const id = 4168;
export const ids = [4168];
export const modules = {

/***/ 12090:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   KF: () => (/* binding */ toProofTier),
/* harmony export */   g3: () => (/* binding */ stateRank),
/* harmony export */   jn: () => (/* binding */ fromProofTier),
/* harmony export */   np: () => (/* binding */ advance)
/* harmony export */ });
/* unused harmony exports EVIDENCE_STATES, COMPLETENESS */
// Evidence state ladder for the Universal Exploit Proof Fabric.
//
// Evidence state is SEPARATE from severity and confidence. It extends, never replaces, the vocabulary that already
// exists: `proof-tier.js` (execution-proven / proof-failed / taint-proven / unproven) and the fix-verify legs
// (`verifiedFull`, `degradedLegs`). `toProofTier` / `fromProofTier` are the explicit bridges.
//
// Transitions are guarded: a state can only be reached from the state directly before it (or by dropping back), so no
// caller can jump a finding to EXPLOIT_CONFIRMED without passing REPRODUCED, or to FIX_VERIFIED without
// FIX_REPLAY_BLOCKED. A degraded or incomplete run NEVER advances a state.
const EVIDENCE_STATES = Object.freeze([
  'CANDIDATE',
  'STATICALLY_CORROBORATED',
  'REPRODUCER_GENERATED',
  'REPRODUCED',
  'EXPLOIT_CONFIRMED',
  'FIX_REPLAY_BLOCKED',
  'FIX_VERIFIED',
]);

const stateRank = (s) => EVIDENCE_STATES.indexOf(s);

const REQUIRES_PREDECESSOR = Object.freeze(Object.fromEntries(EVIDENCE_STATES.map((s, i) => [s, i === 0 ? null : EVIDENCE_STATES[i - 1]])));

/**
 * Advance `from` to `to`. Returns { ok, state, reason }. Moving up requires `to` to be exactly the next rung; moving
 * down or staying is always allowed (evidence can be lost, never invented). Unknown states are rejected.
 */
function advance(from, to) {
  if (!EVIDENCE_STATES.includes(from)) return { ok: false, state: 'CANDIDATE', reason: `unknown current state: ${String(from)}` };
  if (!EVIDENCE_STATES.includes(to)) return { ok: false, state: from, reason: `unknown target state: ${String(to)}` };
  if (stateRank(to) <= stateRank(from)) return { ok: true, state: to, reason: null };
  if (REQUIRES_PREDECESSOR[to] !== from) return { ok: false, state: from, reason: `cannot reach ${to} from ${from}: ${REQUIRES_PREDECESSOR[to]} is required first` };
  return { ok: true, state: to, reason: null };
}

// Bridges to the older vocabulary so existing consumers keep working.
function toProofTier(state) {
  const r = stateRank(state);
  if (r >= stateRank('EXPLOIT_CONFIRMED')) return 'execution-proven';
  if (r >= stateRank('STATICALLY_CORROBORATED')) return 'taint-proven';
  return 'unproven';
}

function fromProofTier(tier) {
  if (tier === 'taint-proven') return 'STATICALLY_CORROBORATED';
  // execution-proven under the older single-run marker path is one run, not the 3/3 + independent replay the fabric
  // requires, so it maps to REPRODUCED and never to EXPLOIT_CONFIRMED.
  if (tier === 'execution-proven') return 'REPRODUCED';
  return 'CANDIDATE';
}

// Completeness vocabulary shared with fix-verify: FULL only when nothing was skipped.
const COMPLETENESS = Object.freeze(['FULL', 'DEGRADED', 'INCOMPLETE']);


/***/ }),

/***/ 44168:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdRules: () => (/* binding */ cmdRules)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/rule-compiler/ir.js
var rule_compiler_ir = __webpack_require__(87539);
// EXTERNAL MODULE: ./src/posture/proof-fabric/states.js
var states = __webpack_require__(12090);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/eligibility.js
// X-eligibility (PRD 3 "Eligibility"): a finding may enter synthesis only with a stable id, a vulnerable span, a
// CWE/family, code-flow evidence, and deterministic corroboration OR exploit proof. Reuses the existing
// vocabularies rather than inventing a third: proof-fabric's evidence-state ladder when present, else the older
// proof-tier (`taint-proven`/`execution-proven`), else the finding's own `parser` (an IR-TAINT/MULTI-SINK parser
// origin is code-flow evidence even with no execution).


const ANALYSED_PARSERS = new Set(['IR-TAINT', 'MULTI-SINK']);

function checkEligibility(finding, { proofState = null } = {}) {
  const reasons = [];
  if (!finding?.stableId && !finding?.id) reasons.push('no stable id');
  if (finding?.file == null || finding?.line == null) reasons.push('no vulnerable span (file:line)');
  if (!finding?.cwe && !finding?.family) reasons.push('no CWE or family');
  const hasFlowEvidence = ANALYSED_PARSERS.has(finding?.parser) || !!finding?.snippet;
  if (!hasFlowEvidence) reasons.push('no code-flow evidence (parser not IR-TAINT/MULTI-SINK, no snippet)');

  let evidenceState = 'none';
  if (proofState && (0,states/* stateRank */.g3)(proofState) >= (0,states/* stateRank */.g3)('EXPLOIT_CONFIRMED')) evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'execution-proven') evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'taint-proven' || ANALYSED_PARSERS.has(finding?.parser)) evidenceState = 'taint-proven';
  if (evidenceState === 'none') reasons.push('no deterministic corroboration or exploit proof');

  return { eligible: reasons.length === 0, reasons, evidenceState };
}

// EXTERNAL MODULE: ./src/posture/rule-compiler/corpus.js
var rule_compiler_corpus = __webpack_require__(43556);
// EXTERNAL MODULE: ./src/posture/rule-compiler/promotion.js
var promotion = __webpack_require__(57711);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/lifecycle.js
// Rule lifecycle ledger: DRAFT -> CANDIDATE -> VALIDATED -> PROMOTED -> DEPRECATED/ROLLED_BACK.
//
// Append-only, hash-chained (same idiom as remediation-ledger.js / invariants/lifecycle.js): each entry links the
// previous entry's hash, so a dropped or edited middle record breaks the chain and `verifyLedger` catches it. A
// rule cannot promote itself: `transition` only records a transition a caller already decided; `advance`-style
// guarding on VALID edges lives here so no caller can jump DRAFT straight to PROMOTED.



const LEDGER_SCHEMA = 'agentic-security/rule-lifecycle-ledger';
const EDGES = Object.freeze({
  DRAFT: ['CANDIDATE'], CANDIDATE: ['VALIDATED', 'DRAFT'], VALIDATED: ['PROMOTED', 'DRAFT'],
  PROMOTED: ['DEPRECATED', 'ROLLED_BACK'], DEPRECATED: [], ROLLED_BACK: ['CANDIDATE'],
});

const hashOf = (entry) => (0,external_node_crypto_.createHash)('sha256').update(JSON.stringify(entry)).digest('hex');

function newLedger() { return { schema: LEDGER_SCHEMA, entries: [] }; }

function currentState(ledger, ruleId) {
  for (let i = ledger.entries.length - 1; i >= 0; i--) if (ledger.entries[i].ruleId === ruleId) return ledger.entries[i].to;
  return null;
}

/**
 * Record a transition. Refuses an edge not in EDGES, and refuses DRAFT->DRAFT re-entry for a rule that has never
 * existed (the first entry for a rule id must be `from: null, to: 'DRAFT'`).
 */
function recordTransition(ledger, { ruleId, from, to, reason, evidence = null, actor }) {
  if (!rule_compiler_ir/* RULE_STATES */.UQ.includes(to)) return { ok: false, reason: `unknown target state: ${to}` };
  const cur = currentState(ledger, ruleId);
  if (cur === null) {
    if (from !== null || to !== 'DRAFT') return { ok: false, reason: 'first transition for a rule must be null -> DRAFT' };
  } else {
    if (from !== cur) return { ok: false, reason: `stale transition: current state is ${cur}, not ${from}` };
    if (!EDGES[cur].includes(to)) return { ok: false, reason: `cannot go from ${cur} to ${to}` };
  }
  const prevHash = ledger.entries.length ? ledger.entries[ledger.entries.length - 1].entryHash : null;
  const entry = { ruleId, from: cur, to, reason: reason ?? null, evidence, actor: actor ?? 'unknown', at: new Date().toISOString(), prevHash };
  entry.entryHash = hashOf({ ...entry, entryHash: undefined });
  ledger.entries.push(entry);
  return { ok: true, entry };
}

function verifyLedger(ledger) {
  let prevHash = null;
  for (const e of ledger.entries) {
    if (e.prevHash !== prevHash) return { ok: false, reason: 'chain broken: prevHash mismatch' };
    const recomputed = hashOf({ ...e, entryHash: undefined });
    if (recomputed !== e.entryHash) return { ok: false, reason: `entry hash mismatch for ${e.ruleId} at ${e.at}` };
    prevHash = e.entryHash;
  }
  return { ok: true };
}

function historyFor(ledger, ruleId) { return ledger.entries.filter((e) => e.ruleId === ruleId); }
function stateOf(ledger, ruleId) { return currentState(ledger, ruleId); }

// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/store.js
// Persistence for the rule compiler: one directory per rule under `.agentic-security/rule-compiler/<id>/`
// (`ir.json`, `ledger.json`, `evaluation.json`), the promoted custom-rule document at
// `.agentic-security/rules/<id>.yml` (so the EXISTING `loadCustomRules`/`rule test` machinery picks it up with no
// change), and a regression fixture pair at `.agentic-security/rule-compiler/fixtures/<id>/{vulnerable,clean}/`
// using the SAME filename convention `runRuleTests` already reads (`vulnerable`/`clean` in the path).






const DIR = 'rule-compiler';
const EXT = { javascript: 'js', typescript: 'ts', python: 'py', go: 'go', ruby: 'rb', java: 'java', rust: 'rs', csharp: 'cs', php: 'php', any: 'txt' };

function ruleDir(scanRoot, id) { return (0,state_dir.statePath)(scanRoot, DIR, id); }

function loadLedger(scanRoot) {
  const f = (0,state_dir.statePath)(scanRoot, DIR, 'ledger.json');
  if (!external_node_fs_.existsSync(f)) return newLedger();
  try {
    const ledger = JSON.parse(external_node_fs_.readFileSync(f, 'utf8'));
    const v = verifyLedger(ledger);
    return v.ok ? ledger : { ...newLedger(), tampered: true, tamperReason: v.reason };
  } catch { return newLedger(); }
}

function saveLedger(scanRoot, ledger) {
  if (!(0,state_dir.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = (0,state_dir.statePath)(scanRoot, DIR, 'ledger.json');
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(ledger, null, 2)) };
}

function saveIR(scanRoot, ir) {
  if (!(0,state_dir.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, ir.id), 'ir.json');
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(ir, null, 2)), file: f };
}

function loadIR(scanRoot, id) {
  const f = external_node_path_.join(ruleDir(scanRoot, id), 'ir.json');
  try { return JSON.parse(external_node_fs_.readFileSync(f, 'utf8')); } catch { return null; }
}

function saveJson(scanRoot, id, name, doc) {
  if (!(0,state_dir.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, id), name);
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(doc, null, 2)), file: f };
}
function loadJson(scanRoot, id, name) { try { return JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(ruleDir(scanRoot, id), name), 'utf8')); } catch { return null; } }
/** The corpus a rule was synthesized on, kept so `rules evaluate <id>` needs no flag and the evidence is the same corpus. */
const saveCorpus = (r, id, spec) => saveJson(r, id, 'corpus.json', spec);
const loadCorpus = (r, id) => loadJson(r, id, 'corpus.json');
/** Every synthesis attempt: strategy, match, score and why it did not pass. */
const saveSynthesis = (r, id, syn) => saveJson(r, id, 'synthesis.json', syn);
const loadSynthesis = (r, id) => loadJson(r, id, 'synthesis.json');
/** The rule's provenance record (PRD 3 requirement 7). */
const saveProvenance = (r, id, doc) => saveJson(r, id, 'provenance.json', doc);
const loadProvenance = (r, id) => loadJson(r, id, 'provenance.json');

function saveEvaluation(scanRoot, id, evaluation) {
  if (!(0,state_dir.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, id), 'evaluation.json');
  return { ok: (0,state_dir.safeWriteState)(f, JSON.stringify(evaluation, null, 2)) };
}

/** Write the regression fixtures a promoted rule needs: the SAME vulnerable/clean convention `runRuleTests`
 * already reads, scored against the exact corpus the rule was promoted on. */
function writeFixtures(scanRoot, ir, corpus) {
  const ext = EXT[ir.languages[0]] || 'txt';
  const base = external_node_path_.join(ruleDir(scanRoot, ir.id), 'fixtures');
  if (!(0,state_dir.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const written = [];
  for (const p of corpus.positives) {
    const f = external_node_path_.join(base, 'vulnerable', `${p.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if ((0,state_dir.safeWriteState)(f, p.code)) written.push(f);
  }
  for (const n of corpus.negatives) {
    const f = external_node_path_.join(base, 'clean', `${n.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if ((0,state_dir.safeWriteState)(f, n.code)) written.push(f);
  }
  return { ok: true, written, glob: external_node_path_.join(base, '**', '*') };
}

/** Promote: write the compiled custom-rule document to the live rules directory. Does not touch the ledger —
 * the caller records the PROMOTED transition itself, so a failed write here can never produce an inconsistent
 * "promoted but not live" or "live but not recorded" state silently. */
function publishCustomRule(scanRoot, ir) {
  const { ok, doc, errs } = (0,rule_compiler_ir/* compileToCustomRule */.Mo)(ir);
  if (!ok) return { ok: false, reason: `invalid rule IR: ${errs.join('; ')}` };
  if (!(0,state_dir.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${ir.id}.yml`);
  const yamlText = [
    `# Compiled by the rule compiler from finding ${ir.provenance.originatingFindingId} (${ir.provenance.evidenceState}).`,
    `- id: ${doc.id}`,
    `  title: ${JSON.stringify(doc.title)}`,
    `  severity: ${doc.severity}`,
    `  cwe: ${doc.cwe}`,
    `  languages: [${doc.languages.join(', ')}]`,
    `  match:`,
    ...(doc.match.pattern ? [`    pattern: ${JSON.stringify(doc.match.pattern)}`] : []),
    ...(doc.match.allOf ? [`    allOf:`, ...doc.match.allOf.map((p) => `      - ${JSON.stringify(p)}`), `    window: ${doc.match.window}`] : []),
    ...(doc.match.notMatch ? [`    notMatch: ${JSON.stringify(doc.match.notMatch)}`] : []),
    `  message: ${JSON.stringify(doc.message)}`,
    '',
  ].join('\n');
  return { ok: (0,state_dir.safeWriteState)(f, yamlText), file: f };
}

function unpublishCustomRule(scanRoot, id) {
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${id}.yml`);
  try { if (external_node_fs_.existsSync(f)) external_node_fs_.unlinkSync(f); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}

// EXTERNAL MODULE: ./src/posture/rule-compiler/proposal.js
var proposal = __webpack_require__(47838);
// EXTERNAL MODULE: ./src/posture/rule-compiler/mutation.js
var mutation = __webpack_require__(85127);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(37055);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/cli.js
// CLI surface: `agentic-security rules synthesize|evaluate|promote|status|rollback`.
//
// Distinct from the pre-existing `labs synthesize-rule` (posture/rule-synthesis.js), which proposes SUPPRESSION
// rules from repeated false-positive triage verdicts — a different input, a different output and a different
// command group on purpose, so the two are never confused at the CLI.
//
// Non-interactive by construction: no command reads stdin, every corpus evaluation is bounded (no network, no
// model call — this is the deterministic half; a model may PROPOSE the candidate pattern this CLI is handed, but
// it never decides promotion).












function loadFinding(root, id) {
  const p = (0,state_dir.statePath)(root, 'last-scan.json');
  if (!external_node_fs_.existsSync(p)) return null;
  const last = JSON.parse(external_node_fs_.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

function readJsonArg(pathOrInline) {
  if (!pathOrInline) return null;
  try { return JSON.parse(external_node_fs_.existsSync(pathOrInline) ? external_node_fs_.readFileSync(pathOrInline, 'utf8') : pathOrInline); } catch { return null; }
}

async function cmdRules(args, root) {
  const sub = args._[1];
  if (sub === 'synthesize') return cmdSynthesize(args, root);
  if (sub === 'evaluate') return cmdEvaluate(args, root);
  if (sub === 'promote') return cmdPromote(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'rollback') return cmdRollback(args, root);
  if (sub === 'cost') return cmdCost(args, root);
  console.error('usage: rules synthesize <finding-id> --spec <file.json> [--auto] [--max-attempts N] | evaluate <rule-id> | promote <rule-id> | status [rule-id] | rollback <rule-id> | cost <rule-id>');
  return 4;
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
  const corpusSpec = { originalCode: spec.originalCode, patchedCode: spec.patchedCode ?? null, nearbyCleanCode: spec.nearbyCleanCode ?? [], protectedVariantsCode: spec.protectedVariantsCode ?? [] };
  const leak = (0,promotion/* checkLeakage */.r_)(JSON.stringify(corpusSpec), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: spec.fileNames ?? [] });
  if (!leak.ok) { console.error(`Refusing: the material for this rule shows benchmark or answer-key signals (${leak.offendingTerms.join('; ')}). Nothing was written.`); return 4; }
  if (args.flags.auto || !spec.match) {
    if (!isStr(spec.originalCode)) { console.error('Automatic proposal needs originalCode (the vulnerable snippet) in the spec.'); return 4; }
    const { id, title, severity, cwe, family, languages, remediation } = spec;
    synthesis = (0,proposal/* synthesizeCandidate */._7)({ base: { id, title, severity, cwe, family, languages, remediation, originatingFindingId: finding.stableId ?? finding.id, evidenceState: elig.evidenceState }, corpusSpec, proposed: spec.match ?? null, maxAttempts: Number(args.flags['max-attempts']) || 6, leakageOk: true });
    for (const a of synthesis.attempts) console.log(`  attempt ${a.n}: ${a.strategy.padEnd(34)} ${a.valid ? `precision ${fmtPct(a.score.precision)}  recall ${fmtPct(a.score.recall)}  protected-failures ${a.score.protectedFailures}${a.pass ? '  PASS' : ''}` : `invalid (${a.errors[0]})`}`);
    if (!synthesis.best) { console.error('No valid candidate could be proposed from this material.'); return 1; }
    finalSpec = { ...spec, match: synthesis.best.match };
    console.log(synthesis.best.pass ? `  candidate meets the promotion gate on this corpus (not yet recorded as VALIDATED).` : `  no attempt met the gate; the best is kept as a CANDIDATE only: ${synthesis.best.reasons.join('; ')}`);
  }
  const ir = (0,rule_compiler_ir/* draftRuleIR */.pc)({ ...finalSpec, originatingFindingId: finding.stableId ?? finding.id, originatingCommit: spec.originatingCommit ?? null, evidenceState: elig.evidenceState });
  const errs = (0,rule_compiler_ir/* validateRuleIR */.g)(ir);
  if (errs.length) { console.error(`Invalid rule: ${errs.join('; ')}`); return 4; }

  const ledger = loadLedger(root);
  const draft = recordTransition(ledger, { ruleId: ir.id, from: null, to: 'DRAFT', reason: `drafted from ${findingId}`, actor: args.flags.actor || 'agent' });
  if (!draft.ok) { console.error(draft.reason); return 4; }
  const cand = recordTransition(ledger, { ruleId: ir.id, from: 'DRAFT', to: 'CANDIDATE', reason: 'eligibility passed', evidence: { eligibility: elig }, actor: args.flags.actor || 'agent' });
  saveLedger(root, ledger);
  saveIR(root, { ...ir, state: 'CANDIDATE' });
  saveCorpus(root, ir.id, { ...corpusSpec, fileNames: spec.fileNames ?? [], discoveryCost: spec.discoveryCost ?? (args.flags['discovery-cost-usd'] ? { usd: Number(args.flags['discovery-cost-usd']), tokens: Number(args.flags['discovery-tokens']) || null, model: spec.model ?? null } : null) });
  if (synthesis) saveSynthesis(root, ir.id, { attempts: synthesis.attempts, best: synthesis.best });
  console.log(`Rule ${ir.id}: DRAFT -> CANDIDATE (digest ${(0,rule_compiler_ir/* ruleIRDigest */.GE)(ir).slice(0, 12)})`);
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
  const corpus = (0,rule_compiler_corpus/* buildCorpus */.F)(ir, corpusSpec);
  const leakage = (0,promotion/* checkLeakage */.r_)(JSON.stringify({ ...corpusSpec, fileNames: undefined, discoveryCost: undefined }), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: corpusSpec.fileNames ?? [] });
  const gate = (0,promotion/* gatePromotion */.z)({ ir, corpus, leakageCheck: leakage, thresholds: args.flags.thresholds ? readJsonArg(args.flags.thresholds) : promotion/* PROMOTION_DEFAULTS */.V2 });

  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (gate.pass && cur === 'CANDIDATE') recordTransition(ledger, { ruleId: id, from: 'CANDIDATE', to: 'VALIDATED', reason: 'promotion gate passed', evidence: { score: gate.evaluation.score }, actor: args.flags.actor || 'agent' });
  saveLedger(root, ledger);
  saveEvaluation(root, id, gate);
  const corpusHash = (list) => (0,reproducer/* sha256 */.sc)(JSON.stringify(list.map((x) => [x.label, x.code]).sort()));
  const prev = loadProvenance(root, id);
  saveProvenance(root, id, {
    schema: 'agentic-security/rule-provenance', version: 1, ruleId: id, ruleVersion: 1, ruleHash: (0,rule_compiler_ir/* ruleIRDigest */.GE)(ir),
    originatingFinding: ir.provenance.originatingFindingId, originatingCommit: ir.provenance.originatingCommit, evidenceState: ir.provenance.evidenceState,
    generatingModel: ir.provenance.model, promptConfigVersion: ir.provenance.promptConfigVersion,
    positiveCorpusHash: corpusHash(corpus.positives), negativeCorpusHash: corpusHash(corpus.negatives),
    benchmarkResults: { precision: gate.evaluation.score.precision, recall: gate.evaluation.score.recall, tp: gate.evaluation.score.tp, fp: gate.evaluation.score.fp, fn: gate.evaluation.score.fn, tn: gate.evaluation.score.tn, protectedFailures: gate.evaluation.score.protectedFailures, thresholds: gate.evaluation.thresholds, gate: gate.pass ? 'passed' : 'failed', reasons: gate.reasons },
    leakageCheck: leakage, mutatorCoverage: (0,mutation/* mutatorCoverage */.xv)(corpusSpec.originalCode), discoveryCost: corpusSpec.discoveryCost ?? prev?.discoveryCost ?? null,
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

async function cmdPromote(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules promote <rule-id>'); return 4; }
  const ledger = loadLedger(root);
  if (ledger.tampered) { console.error(`Refusing: rule lifecycle ledger failed its integrity check (${ledger.tamperReason}).`); return 4; }
  if (stateOf(ledger, id) !== 'VALIDATED') { console.error(`Rule ${id} is not VALIDATED (run rules evaluate first); refusing to promote.`); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}.`); return 4; }
  const pub = publishCustomRule(root, ir);
  if (!pub.ok) { console.error(`Promotion refused: ${pub.reason}`); return 4; }
  const t = recordTransition(ledger, { ruleId: id, from: 'VALIDATED', to: 'PROMOTED', reason: args.flags.reason || 'promoted', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  const prov = loadProvenance(root, id);
  if (prov) saveProvenance(root, id, { ...prov, promotionEvent: { at: new Date().toISOString(), actor: args.flags.actor || 'operator', reason: args.flags.reason || 'promoted', ruleHash: (0,rule_compiler_ir/* ruleIRDigest */.GE)(ir) } });
  console.log(`Rule ${id}: VALIDATED -> PROMOTED. Published to ${pub.file}.`);
  if (!t.ok) console.error(t.reason);
  return 0;
}

async function cmdRollback(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules rollback <rule-id> [--reason text]'); return 4; }
  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (cur !== 'PROMOTED') { console.error(`Rule ${id} is not PROMOTED (current: ${cur ?? 'unknown'}); nothing to roll back.`); return 4; }
  const un = unpublishCustomRule(root, id);
  const t = recordTransition(ledger, { ruleId: id, from: 'PROMOTED', to: 'ROLLED_BACK', reason: args.flags.reason || 'operator rollback', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  console.log(`Rule ${id}: PROMOTED -> ROLLED_BACK.${un.ok ? '' : ` (warning: could not remove published rule file: ${un.reason})`}`);
  return t.ok ? 0 : 1;
}

async function cmdStatus(args, root) {
  const ledger = loadLedger(root);
  const id = args._[2];
  if (id) {
    const h = historyFor(ledger, id);
    if (!h.length) { console.error(`No history for rule ${id}.`); return 4; }
    if (args.flags.json) console.log(JSON.stringify(h, null, 2));
    else { console.log(`Rule ${id}: ${stateOf(ledger, id)}`); for (const e of h) console.log(`  ${e.at}  ${e.from ?? '(new)'} -> ${e.to}  (${e.reason || ''})`); 
      const syn = loadSynthesis(root, id);
      if (syn?.attempts?.length) { console.log(`  synthesis: ${syn.attempts.length} attempt(s), best ${syn.best ? `${syn.best.strategy}${syn.best.pass ? ' (met the gate)' : ' (did not meet the gate)'}` : 'none'}`); }
    }
    return 0;
  }
  const ids = [...new Set(ledger.entries.map((e) => e.ruleId))];
  if (args.flags.json) { console.log(JSON.stringify(ids.map((rid) => ({ id: rid, state: stateOf(ledger, rid) })), null, 2)); return 0; }
  if (!ids.length) { console.log('No rules in the lifecycle ledger yet.'); return 0; }
  for (const rid of ids) console.log(`  ${rid.padEnd(40)} ${stateOf(ledger, rid)}`);
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
  try { const last = JSON.parse(external_node_fs_.readFileSync((0,state_dir.statePath)(root, 'last-scan.json'), 'utf8')); detections = (last.findings || []).filter((f) => String(f.id || '').startsWith(`custom:rule-compiler/${id}:`)).length; } catch { /* no scan */ }
  const first = prov.discoveryCost;
  const out = { ruleId: id, firstDiscovery: first ? { usd: first.usd ?? null, tokens: first.tokens ?? null, model: first.model ?? null } : null, laterDeterministicDetections: detections, laterDeterministicModelUsd: 0, state: prov.promotionEvent ? 'promoted' : 'not promoted' };
  if (args.flags.json) { console.log(JSON.stringify(out, null, 2)); return 0; }
  console.log(`Rule ${id} (${out.state})`);
  console.log(first ? `  first discovery: ${first.usd != null ? `$${first.usd}` : 'cost not recorded'}${first.tokens ? `, ${first.tokens} tokens` : ''}${first.model ? `, ${first.model}` : ''}` : '  first discovery: cost was not recorded for this rule');
  console.log(`  later detections by this rule in the last scan: ${detections ?? 'no scan available'}, each at $0 of model spend`);
  if (first?.usd != null && detections) console.log(`  discovery cost spread over ${detections + 1} detection(s): $${(first.usd / (detections + 1)).toFixed(4)} each, falling with every further one`);
  return 0;
}


/***/ })

};
