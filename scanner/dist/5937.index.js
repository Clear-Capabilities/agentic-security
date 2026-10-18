export const id = 5937;
export const ids = [5937];
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

/***/ 65937:
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
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: ./src/posture/rule-compiler/ir.js
var rule_compiler_ir = __webpack_require__(87539);
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

// EXTERNAL MODULE: ./src/posture/rule-pack-signing.js
var rule_pack_signing = __webpack_require__(99527);
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
    ...(doc.match.fileRequires ? [`    fileRequires:`, ...doc.match.fileRequires.map((p) => `      - ${JSON.stringify(p)}`)] : []),
    ...(doc.match.guardedBy ? [`    guardedBy: ${JSON.stringify(doc.match.guardedBy)}`, `    guardWindow: ${doc.match.guardWindow}`] : []),
    ...(doc.match.excludeLine ? [`    excludeLine:`, ...doc.match.excludeLine.map((p) => `      - ${JSON.stringify(p)}`)] : []),
    `  message: ${JSON.stringify(doc.message)}`,
    '',
  ].join('\n');
  return { ok: (0,state_dir.safeWriteState)(f, yamlText), file: f };
}

/** Sign a published rule with the operator's key (the same Ed25519 scheme `agentic-security-rule sign` uses). The key is never stored here. */
function signPublishedRule(file, privateKeyB64) {
  try { (0,rule_pack_signing/* signRulePack */.pV)(file, privateKeyB64); return { ok: true }; } catch (e) { return { ok: false, reason: String(e.message).slice(0, 120) }; }
}

/**
 * Will the scanner actually LOAD this promoted rule? Publishing a file is not the same as the scanner trusting it: rule packs are
 * signature-checked (posture/rule-pack-signing.js) so that a rule dropped into a repository cannot run in someone's CI. A promoted rule
 * the scanner would refuse is not a capability yet, so this is reported next to the lifecycle state instead of being assumed.
 */
function packTrust(scanRoot, id) {
  const file = (0,state_dir.statePath)(scanRoot, 'rules', `${id}.yml`);
  if (!external_node_fs_.existsSync(file)) return { live: false, reason: 'not published', remediation: null };
  let r;
  const origErr = console.error; console.error = () => {};
  try { r = (0,rule_pack_signing/* verifyRulePack */.Ig)(file, (0,rule_pack_signing/* loadTrustedKeys */.CW)(scanRoot)); } finally { console.error = origErr; }
  if (r.ok) return { live: true, via: r.passThrough ? 'signed, accepted in pass-through mode (no trusted keys are configured)' : `signed by ${r.keyId}`, reason: null, remediation: null };
  if (r.reason === 'unsigned' && r.allowUnsigned) return { live: true, via: 'unsigned, accepted because AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1', reason: null, remediation: null };
  const remediation = r.reason === 'unsigned'
    ? `sign it (agentic-security-rule sign ${external_node_path_.relative(process.cwd(), file) || file} with your key, or re-run promote with --sign-key <base64>), or opt in for this environment with AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1`
    : (r.remediation ?? 'see the signing setup in bin/agentic-security-rule.js');
  return { live: false, reason: r.reason, remediation };
}

function unpublishCustomRule(scanRoot, id) {
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${id}.yml`);
  try { for (const x of [f, `${f}.sig`]) if (external_node_fs_.existsSync(x)) external_node_fs_.unlinkSync(x); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}

// EXTERNAL MODULE: ./src/posture/rule-compiler/corpus.js
var rule_compiler_corpus = __webpack_require__(43556);
// EXTERNAL MODULE: ./src/posture/rule-compiler/promotion.js
var promotion = __webpack_require__(57711);
// EXTERNAL MODULE: ./src/posture/custom-rules.js
var custom_rules = __webpack_require__(69400);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/regression.js
// Regression integration for promoted rules (PRD 3, requirement 8): a promoted rule joins a corpus every later rule and every later
// run is held to, instead of being checked once at promotion and forgotten.
//
//   shared false-positive corpus   the SAFE code of every promoted rule (its patched, nearby-clean and protected variants) plus any file
//                                  the operator drops in `.agentic-security/rule-compiler/fp-corpus/`. A new candidate must not fire
//                                  on any of it, so rule N+1 cannot reintroduce the false positive rule N was built to avoid.
//   regression run                 `rules regress` re-scores every PROMOTED rule against its own corpus, then against the shared false
//                                  positive corpus, and reports any rule that no longer clears its gate (the matcher, the loader or
//                                  another rule changed underneath it).
// The rule-specific unit tests are the fixtures written at evaluation (the existing `rule test` convention); this module adds the cross-rule
// part, which a per-rule check cannot see.










const FP_DIR = 'rule-compiler/fp-corpus';
const MAX_FP_FILE = 256 * 1024;
const MAX_FP_FILES = 500;
const EXT_OF = { '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.py': 'python', '.go': 'go', '.rb': 'ruby', '.java': 'java', '.rs': 'rust', '.cs': 'csharp', '.php': 'php' };

/** Operator-supplied false positives (real code a rule should never flag). Plain files; symlinks and oversized files are ignored. */
function operatorFalsePositives(root) {
  const dir = (0,state_dir.statePath)(root, ...FP_DIR.split('/'));
  const out = [];
  let names = [];
  try { names = external_node_fs_.readdirSync(dir).sort(); } catch { return out; }
  for (const n of names.slice(0, MAX_FP_FILES)) {
    const f = external_node_path_.join(dir, n);
    try {
      const st = external_node_fs_.lstatSync(f);
      if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_FP_FILE) continue;
      out.push({ label: `operator-fp:${n}`, file: n, language: EXT_OF[external_node_path_.extname(n).toLowerCase()] ?? 'any', code: external_node_fs_.readFileSync(f, 'utf8') });
    } catch { /* unreadable: skipped */ }
  }
  return out;
}

function promotedRuleIds(ledger) {
  return [...new Set(ledger.entries.map((e) => e.ruleId))].filter((id) => stateOf(ledger, id) === 'PROMOTED');
}

/** The shared false-positive corpus as seen by `exceptId`: the safe code of every OTHER promoted rule, plus the operator's files. */
function sharedFalsePositiveCorpus(root, ledger, exceptId = null) {
  const items = [];
  for (const id of promotedRuleIds(ledger)) {
    if (id === exceptId) continue;
    const ir = loadIR(root, id); const spec = loadCorpus(root, id);
    if (!ir || !spec || typeof spec.originalCode !== 'string') continue;
    let corpus; try { corpus = (0,rule_compiler_corpus/* buildCorpus */.F)(ir, spec); } catch { continue; }
    for (const n of corpus.negatives) items.push({ label: `rule:${id}:${n.label}`, language: ir.languages[0] ?? 'any', code: n.code });
  }
  return [...items, ...operatorFalsePositives(root)];
}

const FILE_FOR_LANG = { javascript: 'x.js', typescript: 'x.ts', python: 'x.py', go: 'x.go', ruby: 'x.rb', java: 'x.java', rust: 'x.rs', csharp: 'x.cs', php: 'x.php', any: 'x.txt' };

/** Which shared false-positive items does this rule fire on? A rule is only run against items written in a language it applies to. */
function falsePositiveHits(ir, items) {
  const { ok, doc } = (0,rule_compiler_ir/* compileToCustomRule */.Mo)(ir);
  if (!ok) return [{ label: '(rule does not compile)' }];
  const rule = (0,custom_rules/* normalizeCustomRule */.Lj)(doc);
  if (!rule) return [{ label: '(rule would be rejected by the loader)' }];
  const hits = [];
  for (const it of items) {
    const lang = it.language && it.language !== 'any' ? it.language : (ir.languages[0] ?? 'any');
    if (!ir.languages.includes('any') && !ir.languages.includes(lang)) continue;
    if ((0,custom_rules/* runRule */.OA)(rule, FILE_FOR_LANG[lang] ?? 'x.txt', it.code).length > 0) hits.push({ label: it.label });
  }
  return hits;
}

/** Re-score every promoted rule (or one) against its own corpus and the shared false-positive corpus. */
function regressRules(root, ledger, { only = null, thresholds } = {}) {
  const results = [];
  for (const id of promotedRuleIds(ledger)) {
    if (only && id !== only) continue;
    const ir = loadIR(root, id); const spec = loadCorpus(root, id);
    if (!ir || !spec || typeof spec.originalCode !== 'string') { results.push({ id, status: 'unverifiable', reasons: [!ir ? 'the rule IR is missing' : 'no evaluated corpus was kept for this rule (run rules evaluate --corpus again)'] }); continue; }
    let ev; let corpus;
    try { corpus = (0,rule_compiler_corpus/* buildCorpus */.F)(ir, spec); ev = (0,promotion/* evaluateRule */.kx)(ir, corpus, thresholds); } catch (e) { results.push({ id, status: 'broken', reasons: [`cannot be scored: ${String(e.message).slice(0, 120)}`] }); continue; }
    const fp = falsePositiveHits(ir, sharedFalsePositiveCorpus(root, ledger, id));
    const baseline = loadProvenance(root, id)?.benchmarkResults ?? null;
    const reasons = [...ev.reasons];
    if (fp.length) reasons.push(`fires on ${fp.length} item(s) of the shared false-positive corpus: ${fp.slice(0, 3).map((h) => h.label).join(', ')}${fp.length > 3 ? ', ...' : ''}`);
    if (baseline && ev.score.recall != null && baseline.recall != null && ev.score.recall < baseline.recall) reasons.push(`recall fell from ${(baseline.recall * 100).toFixed(1)}% to ${(ev.score.recall * 100).toFixed(1)}% since promotion`);
    results.push({ id, status: reasons.length ? 'regressed' : 'ok', reasons, precision: ev.score.precision, recall: ev.score.recall, protectedFailures: ev.score.protectedFailures, fpCorpusHits: fp.length });
  }
  return results;
}

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

// EXTERNAL MODULE: ./src/posture/rule-compiler/proposal.js
var proposal = __webpack_require__(47838);
// EXTERNAL MODULE: ./src/posture/rule-compiler/mutation.js
var mutation = __webpack_require__(85127);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(37055);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/cli.js
// CLI surface: `agentic-security rules synthesize|evaluate|promote|status|rollback|cost|regress`.
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
  if (sub === 'regress') return cmdRegress(args, root);
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
  if (args.flags.auto || (!spec.match && !spec.sink)) {
    if (!isStr(spec.originalCode)) { console.error('Automatic proposal needs originalCode (the vulnerable snippet) in the spec.'); return 4; }
    const { id, title, severity, cwe, family, languages, remediation } = spec;
    synthesis = (0,proposal/* synthesizeCandidate */._7)({ base: { id, title, severity, cwe, family, languages, remediation, originatingFindingId: finding.stableId ?? finding.id, evidenceState: elig.evidenceState }, corpusSpec, proposed: spec.match ?? null, maxAttempts: Number(args.flags['max-attempts']) || 6, leakageOk: true });
    for (const a of synthesis.attempts) console.log(`  attempt ${a.n}: ${a.strategy.padEnd(34)} ${a.valid ? `precision ${fmtPct(a.score.precision)}  recall ${fmtPct(a.score.recall)}  protected-failures ${a.score.protectedFailures}${a.pass ? '  PASS' : ''}` : `invalid (${a.errors[0]})`}`);
    if (!synthesis.best) { console.error('No valid candidate could be proposed from this material.'); return 1; }
    finalSpec = { ...spec, ...(synthesis.best.match ? { match: synthesis.best.match } : {}), ...(synthesis.best.structure ?? {}) };
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
  // the corpus a rule is evaluated on is the evidence for it: keep it, so `rules regress` and the shared false-positive corpus use the SAME code
  if (args.flags.corpus) saveCorpus(root, id, { ...(loadCorpus(root, id) ?? {}), ...corpusSpec });
  const leakage = (0,promotion/* checkLeakage */.r_)(JSON.stringify({ ...corpusSpec, fileNames: undefined, discoveryCost: undefined }), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [], fileNames: corpusSpec.fileNames ?? [] });
  const gate = (0,promotion/* gatePromotion */.z)({ ir, corpus, leakageCheck: leakage, thresholds: args.flags.thresholds ? readJsonArg(args.flags.thresholds) : promotion/* PROMOTION_DEFAULTS */.V2 });

  const ledger = loadLedger(root);
  // the shared false-positive corpus: the safe code of every other promoted rule, plus the operator's own files. Part of the gate.
  const fpItems = sharedFalsePositiveCorpus(root, ledger, id);
  const fpHits = falsePositiveHits(ir, fpItems);
  gate.fpCorpus = { items: fpItems.length, hits: fpHits.map((h) => h.label) };
  if (fpHits.length) { gate.pass = false; gate.reasons.push(`fires on ${fpHits.length} of ${fpItems.length} item(s) in the shared false-positive corpus: ${fpHits.slice(0, 3).map((h) => h.label).join(', ')}${fpHits.length > 3 ? ', ...' : ''}`); }
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
  // other rules may have been promoted since this one was evaluated: hold it to the false-positive corpus as it is NOW
  const fpNow = falsePositiveHits(ir, sharedFalsePositiveCorpus(root, ledger, id));
  if (fpNow.length) { console.error(`Promotion refused: ${id} fires on ${fpNow.length} item(s) of the shared false-positive corpus (${fpNow.slice(0, 3).map((h) => h.label).join(', ')}). Re-evaluate or narrow the rule.`); return 1; }
  const pub = publishCustomRule(root, ir);
  if (!pub.ok) { console.error(`Promotion refused: ${pub.reason}`); return 4; }
  const t = recordTransition(ledger, { ruleId: id, from: 'VALIDATED', to: 'PROMOTED', reason: args.flags.reason || 'promoted', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  const prov = loadProvenance(root, id);
  if (prov) saveProvenance(root, id, { ...prov, promotionEvent: { at: new Date().toISOString(), actor: args.flags.actor || 'operator', reason: args.flags.reason || 'promoted', ruleHash: (0,rule_compiler_ir/* ruleIRDigest */.GE)(ir) } });
  console.log(`Rule ${id}: VALIDATED -> PROMOTED. Published to ${pub.file}.`);
  // Publishing is not trusting. Rule packs are signature-checked so a rule dropped into a repository cannot run in someone's CI; sign this
  // one with the operator's key when there is one, and say plainly whether the scanner will load it.
  const key = args.flags['sign-key'] ?? process.env.AGENTIC_SECURITY_PRIVATE_KEY;
  if (key) { const sg = signPublishedRule(pub.file, key); console.log(sg.ok ? `  signed: ${pub.file}.sig` : `  could not sign (${sg.reason}); the rule is published unsigned`); }
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
  if (args.flags.json) console.log(JSON.stringify({ results }, null, 2));
  else if (!results.length) console.log(only ? `No promoted rule ${only}.` : 'No rule is PROMOTED; nothing to regress.');
  else for (const r of results) { console.log(`${r.id}: ${r.status.toUpperCase()}${r.precision != null ? `  precision ${fmtPct(r.precision)}  recall ${fmtPct(r.recall)}  false-positive corpus hits ${r.fpCorpusHits}` : ''}`); for (const m of r.reasons) console.log(`  - ${m}`); }
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
