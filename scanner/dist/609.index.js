export const id = 609;
export const ids = [609,499];
export const modules = {

/***/ 4609:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  runDiscovery: () => (/* binding */ runDiscovery)
});

// UNUSED EXPORTS: makeTaintProbe

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(7598);
;// CONCATENATED MODULE: ./src/discovery/partition.js
//
// Split the codebase into disjoint focus areas so parallel hunters cannot
// converge on the same code.
//
// WHY THE CALL GRAPH AND NOT DIRECTORIES: a directory split hands one
// subsystem to several hunters whenever a feature spans folders, and hands
// unrelated code to one hunter whenever a folder is a grab bag. Weakly-
// connected components over call edges group code that actually talks to
// itself, which is the unit a hunter can reason about end to end.
//
// FILES, NOT FUNCTIONS, ARE THE ATOM. A hunter reads whole files. If two
// components share a file they are merged, otherwise the same source lands in
// two hunters' context and the convergence this module exists to prevent
// comes straight back.


function focusAreaId(files) {
  const canon = [...new Set(files || [])].sort().join('\n');
  return external_node_crypto_.createHash('sha256').update(canon).digest('hex').slice(0, 12);
}

// Union-find over file paths.
function makeDSU() {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r);
    while (parent.get(x) !== r) { const n = parent.get(x); parent.set(x, r); x = n; }
    return r;
  };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb); };
  return { find, union };
}

function labelFor(files) {
  if (files.length === 1) return files[0];
  const parts = files[0].split('/');
  for (let i = parts.length - 1; i > 0; i--) {
    const prefix = parts.slice(0, i).join('/') + '/';
    if (files.every(f => f.startsWith(prefix))) return prefix;
  }
  return files[0] + ` (+${files.length - 1})`;
}

function partitionCallGraph(callGraph, opts = {}) {
  const fns = callGraph?.functions;
  if (!fns || typeof fns.get !== 'function' || fns.size === 0) return [];
  const maxAreas = Number.isInteger(opts.maxAreas) && opts.maxAreas > 0 ? opts.maxAreas : 8;

  const dsu = makeDSU();
  for (const fn of fns.values()) if (fn?.file) dsu.find(fn.file);
  for (const e of callGraph.edges || []) {
    const a = fns.get(e?.caller)?.file;
    const b = fns.get(e?.callee)?.file;
    if (a && b) dsu.union(a, b);
  }

  const filesByRoot = new Map();
  for (const fn of fns.values()) {
    if (!fn?.file) continue;
    const root = dsu.find(fn.file);
    if (!filesByRoot.has(root)) filesByRoot.set(root, new Set());
    filesByRoot.get(root).add(fn.file);
  }

  const fnsByFile = new Map();
  for (const fn of fns.values()) {
    if (!fn?.file) continue;
    if (!fnsByFile.has(fn.file)) fnsByFile.set(fn.file, []);
    fnsByFile.get(fn.file).push(fn.qid);
  }

  const build = (files, label) => {
    const sorted = [...files].sort();
    const functions = sorted.flatMap(f => (fnsByFile.get(f) || [])).sort();
    return { id: focusAreaId(sorted), label: label ?? labelFor(sorted), files: sorted, functions, size: functions.length };
  };

  let areas = [...filesByRoot.values()].map(s => build(s));
  // Deterministic ranking: biggest first, ties broken by id so two runs on the
  // same graph produce the same order.
  areas.sort((a, b) => b.size - a.size || (a.id < b.id ? -1 : 1));

  if (areas.length > maxAreas) {
    const kept = areas.slice(0, maxAreas - 1);
    const tail = areas.slice(maxAreas - 1);
    kept.push(build(tail.flatMap(a => a.files), 'misc'));
    areas = kept;
  }
  return areas;
}

// EXTERNAL MODULE: ./src/discovery/lenses.js
var discovery_lenses = __webpack_require__(3499);
;// CONCATENATED MODULE: ./src/discovery/llm-invoke.js
//
// Shared LLM endpoint caller. Both the hunter and the refutation panel need
// the same default endpoint caller when tests don't inject a mock. Two copies
// of a network call is one copy too many — if one path gets fixed and the
// other does not, the bug stays buried in one direction.
//

const DEFAULT_TIMEOUT_MS = 60000;

async function defaultLlmInvoke(prompt, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  // The URL is the operator's own configured endpoint, read from an environment
  // variable they set. Reaching it is this module's entire purpose; no
  // request-controlled input exists anywhere on this path, and an operator who
  // can set this variable can already run code.
  const res = await fetch(process.env.AGENTIC_SECURITY_LLM_ENDPOINT, { // agentic-security-ignore: CWE-918
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

function resolveLlmInvoke(opts = {}) {
  if (opts.llmInvoke) return opts.llmInvoke;
  if (!process.env.AGENTIC_SECURITY_LLM_ENDPOINT) return null;
  return (prompt) => defaultLlmInvoke(prompt, { timeoutMs: opts.timeoutMs });
}

;// CONCATENATED MODULE: ./src/discovery/hunter.js
//
// One bounded hunter run = one focus area seen through one lens.
//
// A hunter PROPOSES. Nothing here is a finding: every candidate must survive
// `confirm.js` and `disprove.js` first. That separation is the whole design —
// the model is allowed to be imaginative precisely because something
// deterministic checks it afterwards.
//
// FAILURE IS ALWAYS DEGRADATION, NEVER AN EXCEPTION. A missing endpoint, a
// rate limit, or unparseable output yields `degraded:true` with a reason. A
// discovery pass that cannot run must leave the rest of the scan intact.




function appendEntry(transcript, entry) {
  const prev = transcript.length ? transcript[transcript.length - 1].hash : null;
  // Named `serialized`, not `body`: this is the canonical serialisation of a
  // transcript entry being fed to a hash, and calling it `body` made the
  // mass-assignment detector read it as a request payload. The name was simply
  // wrong for what it holds, so this is a fix at the source rather than a
  // suppression — and that detector's finding carries no line number, so a
  // line-scoped ignore pragma could not have matched it anyway.
  const serialized = JSON.stringify({ ...entry, prev });
  const hash = external_node_crypto_.createHash('sha256').update(serialized).digest('hex');
  transcript.push({ ...entry, prev, hash });
  return transcript;
}

function extractJsonWithFlag(raw) {
  if (typeof raw !== 'string') return { parsed: null, found: false };
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return { parsed: null, found: false };
  try { return { parsed: JSON.parse(raw.slice(start, end + 1)), found: true }; } catch { return { parsed: null, found: false }; }
}

function candidateId(focusAreaId, lensKey, file, line, title) {
  return external_node_crypto_.createHash('sha256')
    .update(`${focusAreaId}|${lensKey}|${file}|${line}|${title}`)
    .digest('hex').slice(0, 12);
}

function candidatesFromParsed(parsed, focusArea, lens) {
  const list = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  const out = [];
  for (const c of list) {
    const file = typeof c?.file === 'string' ? c.file : null;
    const line = Number.isInteger(c?.line) ? c.line : Number.parseInt(c?.line, 10);
    if (!file || !Number.isInteger(line)) continue;      // no location, no candidate
    const title = typeof c?.title === 'string' && c.title ? c.title : `${lens.title} candidate`;
    out.push({
      id: candidateId(focusArea.id, lens.key, file, line, title),
      focusAreaId: focusArea.id,
      lens: lens.key,
      title,
      file,
      line,
      family: lens.family,
      cwe: lens.cwe,
      rationale: typeof c?.rationale === 'string' ? c.rationale : '',
      entryPoint: typeof c?.entryPoint === 'string' ? c.entryPoint : '',
      sink: typeof c?.sink === 'string' ? c.sink : '',
    });
  }
  return out;
}

function parseCandidates(raw, focusArea, lens) {
  const { parsed } = extractJsonWithFlag(raw);
  return candidatesFromParsed(parsed, focusArea, lens);
}

async function runHunter(focusArea, lens, ctx = {}, opts = {}) {
  const transcript = [];
  const lensKey = lens?.key || 'unknown';
  const base = { focusAreaId: focusArea.id, lens: lensKey, transcript };
  const llmInvoke = resolveLlmInvoke(opts);

  if (typeof llmInvoke !== 'function') {
    const reason = 'no llmInvoke supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set';
    appendEntry(transcript, { phase: 'init', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  let prompt;
  try {
    prompt = (0,discovery_lenses/* buildHunterPrompt */.j)(focusArea, lens, ctx);
  } catch (err) {
    const reason = `failed to build hunter prompt: ${err?.message || String(err)}`;
    appendEntry(transcript, { phase: 'prompt_error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  appendEntry(transcript, { phase: 'prompt', promptChars: prompt.length, files: focusArea.files.length });

  let raw;
  try {
    raw = await llmInvoke(prompt);
  } catch (err) {
    const reason = `hunter llm call failed: ${err?.message || String(err)}`;
    appendEntry(transcript, { phase: 'error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  const { parsed, found } = extractJsonWithFlag(raw);
  if (!found) {
    const reason = 'hunter output was not parseable JSON';
    appendEntry(transcript, { phase: 'parse_error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  const candidates = candidatesFromParsed(parsed, focusArea, lens);
  appendEntry(transcript, { phase: 'result', candidateCount: candidates.length });
  return { ...base, candidates, degraded: false, reason: null };
}

;// CONCATENATED MODULE: ./src/discovery/confirm.js
//
// Route every model-proposed candidate back through the deterministic layer.
//
// WHY THIS EXISTS. A hunter's output is a hypothesis. The engine underneath it
// can already decide, for a given file and line, whether tainted data reaches a
// modelled sink there. Asking it turns "the model thinks so" into "the model
// thinks so AND the taint engine agrees", which is a materially stronger claim
// than either layer makes alone.
//
// THE ASYMMETRY IS DELIBERATE. Confirmation raises standing; the absence of
// confirmation NEVER lowers it below `unconfirmed` and is never recorded as a
// refutation. The taint engine models a subset of the program — an
// unconfirmed candidate may be a real bug in a construct the engine does not
// model, and calling that a false positive would launder a coverage gap into a
// verdict. Refutation is `disprove.js`'s job, and it must be argued, not
// inferred from silence.
const CONFIRMATION_TIERS = Object.freeze(['taint-confirmed', 'sink-adjacent', 'unconfirmed']);

function unconfirmed(probedBy, reason) {
  return { tier: 'unconfirmed', evidence: null, probedBy, reason: reason || null };
}

async function confirmCandidate(candidate, opts = {}) {
  const probe = typeof opts.taintProbe === 'function' ? opts.taintProbe : null;
  if (!probe) return { ...candidate, confirmation: unconfirmed(null, 'no taintProbe supplied') };

  let res;
  try {
    res = await probe(candidate);
  } catch (err) {
    return { ...candidate, confirmation: unconfirmed('taintProbe', `probe failed: ${err?.message || String(err)}`) };
  }
  if (!res) return { ...candidate, confirmation: unconfirmed('taintProbe', null) };
  if (!CONFIRMATION_TIERS.includes(res.tier)) {
    return { ...candidate, confirmation: unconfirmed('taintProbe', `unknown tier: ${res.tier}`) };
  }
  return {
    ...candidate,
    confirmation: { tier: res.tier, evidence: res.evidence ?? null, probedBy: 'taintProbe', reason: null },
  };
}

async function confirmAll(candidates, opts = {}) {
  const out = [];
  for (const c of candidates || []) out.push(await confirmCandidate(c, opts));
  return out;
}

;// CONCATENATED MODULE: ./src/discovery/disprove.js
//
// Adversarial refutation. Each voter is told to REFUTE the candidate, not to
// assess it: a model asked "is this real?" agrees with the premise far more
// often than one asked "show me why this cannot happen", and the second
// question is the one that kills plausible-but-wrong findings.
//
// THREE ANGLES, NOT THREE COPIES. A candidate can fail in more than one way,
// and three identical voters mostly measure sampling noise. Reachability,
// attacker preconditions, and sanitization are the three ways these candidates
// actually die.
//
// SILENCE NEVER REFUTES. A voter that errors or returns unparseable output did
// not vote, and is excluded from the denominator rather than counted as
// agreement. If nobody votes the panel is `undecided` and the candidate
// SURVIVES — an outage must not quietly delete findings.


const DEFAULT_ANGLES = ['reachability', 'preconditions', 'sanitization'];
const REFUTE_ANGLES = Object.freeze([...DEFAULT_ANGLES]);

const ANGLE_BRIEF = {
  reachability: 'Can attacker-controlled data actually reach this line at runtime? Name the caller chain or show there is none.',
  preconditions: 'What must the attacker already have — a session, a role, a tenant, a race window? If the prerequisites exceed the impact, it is refuted.',
  sanitization: 'Is the value validated, escaped, parameterised, or type-constrained anywhere on the path? A framework default counts.',
};

function buildRefutePrompt(candidate, angle) {
  return [
    `Your job is to REFUTE the security finding below. Assume it is wrong and look for the reason.`,
    `Refute it on this angle only: ${angle}. ${ANGLE_BRIEF[angle] || ''}`,
    ``,
    `Finding: ${candidate.title}`,
    `Location: ${candidate.file}:${candidate.line}`,
    `Claimed reason: ${candidate.rationale || '(none given)'}`,
    `Deterministic confirmation: ${candidate.confirmation?.tier || 'unknown'}`,
    ``,
    `If you cannot refute it on this angle, say so honestly.`,
    `Return JSON: {"refuted":true|false,"reason":"..."}`,
  ].join('\n');
}

function parseVote(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.indexOf('{'), e = raw.lastIndexOf('}');
  if (s < 0 || e <= s) return null;
  let p;
  try { p = JSON.parse(raw.slice(s, e + 1)); } catch { return null; }
  if (typeof p?.refuted !== 'boolean') return null;
  return { refuted: p.refuted, reason: typeof p.reason === 'string' ? p.reason : '' };
}

async function disproveCandidate(candidate, opts = {}) {
  const angles = Array.isArray(opts.angles) && opts.angles.length ? opts.angles : DEFAULT_ANGLES;
  const llmInvoke = resolveLlmInvoke(opts);

  const votes = [];
  if (typeof llmInvoke === 'function') {
    for (const angle of angles) {
      let vote = null;
      try { vote = parseVote(await llmInvoke(buildRefutePrompt(candidate, angle))); } catch { vote = null; }
      if (vote) votes.push({ angle, ...vote });
    }
  }

  const voterCount = votes.length;
  const refuteCount = votes.filter(v => v.refuted).length;
  const undecided = voterCount === 0;
  const refuted = !undecided && refuteCount * 2 > voterCount;
  return { ...candidate, refutation: { votes, voterCount, refuteCount, refuted, undecided } };
}

async function disprovePanel(candidates, opts = {}) {
  const survivors = [], refuted = [];
  for (const c of candidates || []) {
    const judged = await disproveCandidate(c, opts);
    (judged.refutation.refuted ? refuted : survivors).push(judged);
  }
  return { survivors, refuted };
}

// EXTERNAL MODULE: ./src/posture/stable-id.js
var stable_id = __webpack_require__(838);
;// CONCATENATED MODULE: ./src/discovery/judge.js
//
// Turn surviving candidates into findings, then decide which are actually new.
//
// SEVERITY IS DRIVEN BY EVIDENCE, NOT BY THE MODEL'S ADJECTIVES. A hunter has
// no calibrated view of impact and will call everything critical. What we can
// defend is how well-evidenced the candidate is, so the confirmation tier sets
// the ceiling: taint-confirmed → high, sink-adjacent → medium, unconfirmed →
// low. A human or the existing triage path can raise it; the discovery layer
// never claims critical on its own.
//
// A PRIOR TRUE POSITIVE IS NOT A DUPLICATE. Triage feedback suppresses only
// `fp` verdicts. A `tp` verdict means the finding was real, and re-reporting it
// while it is still in the code is correct behaviour.
//
// STABLE IDS ARE LOCATION-FUZZY BY DESIGN, AND THAT MATTERS HERE. `stable-id.js`
// hashes ruleId, snippet, path shape, and BASENAME — deliberately not the line,
// so an id survives code moving down a file. The consequence for this layer:
// two different candidates of the same lens in the same file collide on one
// stableId. That is why file+line+family is the PRIMARY duplicate key and the
// stableId check is only a secondary net. It also means an `fp` verdict
// suppresses the whole (lens, file) pair rather than one line — the same
// breadth the rest of the engine already has, kept rather than silently
// diverged from. `ruleId` is set explicitly so ids partition by lens rather
// than falling back to the CWE.


const SEVERITY_BY_TIER = { 'taint-confirmed': 'high', 'sink-adjacent': 'medium', 'unconfirmed': 'low' };

// Guards against a malformed candidate producing a schema-invalid finding
// (root CLAUDE.md requires { id, severity, file, line, vuln, cwe, ... } on
// every finding). `hunter.js` already filters out candidates with no usable
// file/line before they reach here, so this should never trigger in the
// normal pipeline — but toFindingShape is exported and callable directly, and
// degrading with `null` (rather than throwing) matches this subsystem's
// degrade-don't-throw style everywhere else. Callers must skip a `null`.
function toFindingShape(candidate) {
  const file = typeof candidate?.file === 'string' && candidate.file ? candidate.file : null;
  const line = Number.isInteger(candidate?.line) ? candidate.line : null;
  if (!file || line === null) return null;

  const tier = candidate?.confirmation?.tier || 'unconfirmed';
  const lensTitle = candidate?.lens ? `${candidate.lens} candidate` : 'discovery candidate';
  const title = typeof candidate?.title === 'string' && candidate.title ? candidate.title : lensTitle;
  const base = {
    id: `discovery-${candidate.lens}-${candidate.id}`,
    severity: SEVERITY_BY_TIER[tier] || 'low',
    file,
    line,
    vuln: title,
    cwe: candidate.cwe || 'CWE-710',
    description: candidate.rationale
      ? `${candidate.rationale} (entry point: ${candidate.entryPoint || 'unstated'}; sink: ${candidate.sink || 'unstated'})`
      : `Proposed by the ${candidate.lens} lens; no rationale supplied.`,
    remediation: `Review ${candidate.file}:${candidate.line}. Confirm whether ${candidate.entryPoint || 'attacker-controlled input'} can reach ${candidate.sink || 'this operation'}, and constrain it at the boundary if so.`,
    parser: 'DISCOVERY',
    family: candidate.family || 'other',
    ruleId: `discovery:${candidate.lens}`,
    // snippet discriminates findings so computeStableId has material to hash. An empty
    // snippet collapses distinct findings of the same lens in the same file onto one id.
    snippet: candidate.sink || candidate.entryPoint || candidate.title || '',
  };
  return {
    ...base,
    stableId: (0,stable_id/* computeStableId */._)(base),
    discovery: {
      lens: candidate.lens,
      focusAreaId: candidate.focusAreaId,
      confirmation: candidate.confirmation || null,
      refutation: candidate.refutation || null,
    },
  };
}

function judgeCandidates(candidates, priorScan, triageFeedback) {
  const prior = Array.isArray(priorScan?.findings) ? priorScan.findings : [];
  const priorByLoc = new Map();
  const priorIds = new Set();
  for (const p of prior) {
    if (p?.stableId) priorIds.add(p.stableId);
    priorByLoc.set(`${p?.file}|${p?.line}|${p?.family}`, p?.stableId || null);
  }
  const feedback = triageFeedback && typeof triageFeedback === 'object' ? triageFeedback : {};

  const fresh = [], duplicates = [], suppressed = [];
  for (const c of candidates || []) {
    const f = toFindingShape(c);
    if (!f) continue; // malformed candidate (no usable file/line) — degrade by skipping, never throw
    if (feedback[f.stableId] === 'fp') { suppressed.push({ ...f, suppressedBy: 'triage-fp' }); continue; }
    const locKey = `${f.file}|${f.line}|${f.family}`;
    // Location key is PRIMARY: same file, line, and family match existing findings.
    if (priorByLoc.has(locKey)) { duplicates.push({ ...f, duplicateOf: priorByLoc.get(locKey) }); continue; }
    // stableId is SECONDARY: same lens, file, and sink at a moved line is likely the same bug.
    if (priorIds.has(f.stableId)) { duplicates.push({ ...f, duplicateOf: f.stableId }); continue; }
    fresh.push(f);
  }
  return { fresh, duplicates, suppressed };
}

;// CONCATENATED MODULE: ./src/discovery/index.js
//
// Compose the discovery pipeline:
//
//   partition → (area × lens) hunters → confirm → disprove → judge
//
// COVERAGE IS PART OF THE OUTPUT. Every report states how many areas were
// planned versus hunted and how many runs degraded, with reasons. A discovery
// pass that half failed and reports "no findings" is indistinguishable from a
// clean codebase unless it says so.







// Bridge a candidate to the deterministic layer. A taint finding at or within
// two lines of the candidate corroborates it; a modelled sink on the line
// without a full path is weaker corroboration ("sink-adjacent").
//
// NOTE: `runDeepAnalysis(perFileIR, callGraph, opts)` returns a BARE ARRAY of
// findings (see scanner/src/dataflow/index.js), not an object with a
// `.findings` property. Treat anything else defensively.
function makeTaintProbe(perFileIR, callGraph) {
  let cache = null;
  return async (candidate) => {
    if (!callGraph || !perFileIR) return null;
    try {
      if (!cache) cache = runDeepAnalysisSafe(perFileIR, callGraph);
      const deep = await cache;
      if (!Array.isArray(deep)) return null;
      const hits = deep.filter(f => f.file === candidate.file);
      const exact = hits.find(f => Math.abs((f.line ?? -1) - candidate.line) <= 2);
      if (exact) {
        return { tier: 'taint-confirmed', evidence: { matchedFinding: exact.id ?? null, line: exact.line, vuln: exact.vuln ?? null } };
      }
      return hits.length ? { tier: 'sink-adjacent', evidence: { sameFileFindings: hits.length } } : null;
    } catch {
      return null;
    }
  };
}

async function runDeepAnalysisSafe(perFileIR, callGraph) {
  try {
    const { runDeepAnalysis } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 6732));
    return runDeepAnalysis(perFileIR, callGraph, {});
  } catch {
    return null;
  }
}

// ctx = { perFileIR, callGraph, fileContents, priorScan, triageFeedback }
// where { perFileIR, callGraph } come from buildProjectIR(fileContents),
// which returns { perFile, callGraph } — callers must pass perFile as
// perFileIR (see scanner/src/ir/index.js).
async function runDiscovery(ctx = {}, opts = {}) {
  const areas = partitionCallGraph(ctx.callGraph, { maxAreas: opts.maxAreas ?? 8 });

  const reasons = [];

  // An explicit array (including an empty one) is honoured exactly — a caller
  // narrowing a run to no lenses must get no lenses, not a silent fallback to
  // all seven. Only an absent/non-array value falls back to the full set.
  const lensKeys = Array.isArray(opts.lenses) ? opts.lenses : discovery_lenses.LENSES.map(l => l.key);

  const lenses = [];
  for (const key of lensKeys) {
    const lens = (0,discovery_lenses/* lensByKey */.H)(key);
    // An unknown key must degrade visibly, not vanish via a silent filter.
    if (lens) lenses.push(lens);
    else reasons.push(`unresolved lens key: "${key}"`);
  }
  if (lenses.length === 0) {
    reasons.push('no lenses resolved for this run (empty or fully-unresolved lens selection); nothing was hunted');
  }

  const runs = [];
  let candidates = [];
  // areasHunted: areas where AT LEAST ONE lens run completed without degrading.
  const hunted = new Set();
  // areasFullyHunted: areas where EVERY lens run completed without degrading.
  // Distinct from areasHunted so a partially-degraded area (e.g. 6 of 7 lenses
  // failed) cannot be read as fully covered from a single number.
  const fullyHunted = new Set();

  for (const area of areas) {
    let areaDegradedCount = 0;
    for (const lens of lenses) {
      const run = await runHunter(area, lens, { fileContents: ctx.fileContents || {} }, { llmInvoke: opts.llmInvoke });
      runs.push({ focusAreaId: run.focusAreaId, lens: run.lens, degraded: run.degraded, reason: run.reason, candidateCount: run.candidates.length });
      if (run.degraded && run.reason) reasons.push(`${area.label} × ${lens.key}: ${run.reason}`);
      if (run.degraded) areaDegradedCount += 1;
      else hunted.add(area.id);
      candidates = candidates.concat(run.candidates);
    }
    if (lenses.length > 0 && areaDegradedCount === 0) fullyHunted.add(area.id);
  }

  const taintProbe = makeTaintProbe(ctx.perFileIR, ctx.callGraph);
  const confirmed = await confirmAll(candidates, { taintProbe });
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke: opts.llmInvoke });
  const { fresh, duplicates, suppressed } = judgeCandidates(survivors, ctx.priorScan, ctx.triageFeedback);

  // Coverage must not stop at the hunter stage. `confirm.js` correctly never
  // lowers a candidate below `unconfirmed`, and `disprove.js` correctly lets
  // a candidate survive when no voter votes — each rule is right on its own,
  // but composed, a run where BOTH later stages died silently would still
  // report clean hunter coverage while 100% of raw, uncorroborated model
  // output landed in `fresh`. These counters and reasons make that visible.
  const confirmedByTier = { 'taint-confirmed': 0, 'sink-adjacent': 0, 'unconfirmed': 0 };
  for (const c of confirmed) {
    const tier = c?.confirmation?.tier;
    if (tier && Object.prototype.hasOwnProperty.call(confirmedByTier, tier)) confirmedByTier[tier] += 1;
  }
  if (confirmed.length > 0 && confirmedByTier['taint-confirmed'] === 0 && confirmedByTier['sink-adjacent'] === 0) {
    reasons.push(`confirmation stage corroborated nothing for ${confirmed.length} candidate(s) — all remain "unconfirmed"; the deterministic gate may not have run, and the findings below are uncorroborated, not vetted`);
  }

  const panelled = [...survivors, ...refuted];
  const panelsRun = panelled.length;
  const undecidedPanels = panelled.filter(c => c?.refutation?.undecided === true).length;
  if (panelsRun > 0 && undecidedPanels === panelsRun) {
    reasons.push(`refutation panel returned no votes for any of ${panelsRun} candidate(s) — every finding below survived unrefuted, not because it withstood scrutiny`);
  }

  return {
    schema: 'agentic-security/discovery@1',
    focusAreas: areas.map(a => ({ id: a.id, label: a.label, files: a.files.length, size: a.size })),
    runs,
    fresh,
    duplicates,
    suppressed,
    // `refutedCandidates` holds RAW candidates straight from `disprovePanel`,
    // NOT findings — no `vuln`, `severity`, `parser`, or `stableId`. It is
    // deliberately not run through `toFindingShape`: a refuted candidate is
    // deliberately not promoted to a finding, and giving it finding shape
    // would misrepresent it as one. Unlike `fresh`/`duplicates`/`suppressed`,
    // do not iterate this array as if it were finding-shaped.
    refutedCandidates: refuted,
    coverage: {
      areasPlanned: areas.length,
      // At least one lens run completed for the area. Does NOT mean every
      // lens succeeded there — see areasFullyHunted for that stronger claim.
      areasHunted: hunted.size,
      // Every lens run for the area completed without degrading.
      areasFullyHunted: fullyHunted.size,
      lensesPerArea: lenses.length,
      degradedRuns: runs.filter(r => r.degraded).length,
      // Per-tier count of every candidate that went through confirm.js.
      confirmedByTier,
      // How many candidates went through the refutation panel, and how many
      // of those came back with no votes at all (undecided, not refuted).
      panelsRun,
      undecidedPanels,
      reasons,
    },
  };
}


/***/ }),

/***/ 3499:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   H: () => (/* binding */ lensByKey),
/* harmony export */   LENSES: () => (/* binding */ LENSES),
/* harmony export */   j: () => (/* binding */ buildHunterPrompt)
/* harmony export */ });
//
// The seven hunting lenses. Each hunter run is one (focus area × lens) pair.
//
// WHY DIVERSE LENSES RATHER THAN N IDENTICAL HUNTERS: redundancy raises
// confidence in what was already found and adds nothing to coverage. A lens
// that is told to look only at authorization asks different questions of the
// same code than one told to look at crypto, so the union covers failure modes
// no single prompt reaches. `wildcard` exists because a fixed taxonomy is a
// ceiling, and the classes worth finding are the ones not on the list.
const LENSES = Object.freeze([
  { key: 'injection', title: 'Injection', family: 'injection', cwe: 'CWE-74',
    brief: 'Untrusted input reaching an interpreter: SQL, shell, template, XPath, LDAP, or deserialization. Follow the value, not the function name.' },
  { key: 'authz', title: 'Authorization', family: 'access-control', cwe: 'CWE-285',
    brief: 'Missing, partial, or bypassable authorization: object references not scoped to the caller, tier checks applied on one path but not another, checks performed after the effect.' },
  { key: 'crypto', title: 'Cryptography', family: 'crypto', cwe: 'CWE-327',
    brief: 'Misuse rather than choice of primitive: reused nonces, unauthenticated ciphertext, comparisons that are not constant time, keys derived from guessable material.' },
  { key: 'business-logic', title: 'Business logic', family: 'business-logic', cwe: 'CWE-840',
    brief: 'The code does what it says and what it says is wrong: state machines that accept out-of-order transitions, quantities that may be negative, refunds that exceed charges, limits enforced client side.' },
  { key: 'feature-abuse', title: 'Feature abuse', family: 'abuse', cwe: 'CWE-799',
    brief: 'A working feature used as a weapon: unbounded fan-out, expensive endpoints with no cost to the caller, invitations or exports that leak across tenants.' },
  { key: 'chained', title: 'Chained', family: 'attack-chain', cwe: 'CWE-1173',
    brief: 'Two behaviours that are each acceptable alone and unacceptable together. State the chain as an ordered sequence of steps with the attacker capability required at each.' },
  { key: 'wildcard', title: 'Wildcard', family: 'other', cwe: 'CWE-710',
    brief: 'Anything the other lenses do not cover. Prefer the surprising and specific over the generic; report nothing rather than something already obvious.' },
]);

function lensByKey(key) {
  if (typeof key !== 'string') return null;
  return LENSES.find(l => l.key === key) || null;
}

const DEFAULT_MAX_CHARS = 60_000;

function buildHunterPrompt(focusArea, lens, ctx = {}) {
  const maxChars = Number.isInteger(ctx.maxChars) && ctx.maxChars > 0 ? ctx.maxChars : DEFAULT_MAX_CHARS;
  const contents = ctx.fileContents || {};
  const files = (focusArea?.files || []).filter(f => typeof contents[f] === 'string');

  let budget = maxChars;
  const blocks = [];
  for (const f of files) {
    const src = contents[f];
    const slice = src.length > budget ? src.slice(0, Math.max(0, budget)) : src;
    const truncated = slice.length < src.length;
    blocks.push(`--- ${f}${truncated ? ' (truncated)' : ''} ---\n${slice}`);
    budget -= slice.length;
    if (budget <= 0) break;
  }
  const omitted = files.length - blocks.length;

  return [
    `You are hunting for security vulnerabilities in one area of a codebase.`,
    `Area: ${focusArea?.label ?? 'unknown'} (${files.length} files)`,
    ``,
    `Your lens is ${lens.title}. ${lens.brief}`,
    `Report ONLY through this lens. Another hunter covers the others.`,
    ``,
    `Rules:`,
    `- Report a candidate only if you can name the entry point an attacker controls and the effect they achieve.`,
    `- Do not report defence-in-depth gaps, style, or "could be hardened". Those are not candidates.`,
    `- Cite a real file and line from the source below. A candidate with no location is discarded.`,
    ``,
    `Return JSON: {"candidates":[{"title","file","line","rationale","entryPoint","sink"}]}`,
    `Return {"candidates":[]} if you find nothing. An empty result is a valid and useful answer.`,
    ``,
    omitted > 0 ? `NOTE: ${omitted} file(s) omitted, prompt budget exhausted (truncated context).\n` : ``,
    ...blocks,
  ].join('\n');
}


/***/ })

};
