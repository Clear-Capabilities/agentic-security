export const id = 905;
export const ids = [905,499];
export const modules = {

/***/ 4286:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  runDiscovery: () => (/* binding */ runDiscovery)
});

// UNUSED EXPORTS: makeBudget, makeTaintProbe

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
// EXTERNAL MODULE: ./src/egress/policy.js
var policy = __webpack_require__(5712);
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
  // `opts.endpoint` lets the consensus caller target one specific provider.
  // Absent, it falls back to the single configured endpoint — so the ordinary
  // single-model path is byte-identical to what it was before consensus existed.
  const endpoint = opts.endpoint || process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const res = await fetch(endpoint, { // agentic-security-ignore: CWE-918
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

// --- PRD Phase 3 / C2: multi-model consensus --------------------------------
//
// One model's opinion is one model's opinion. Asking several INDEPENDENT
// endpoints the same question and keeping only what a majority agree on
// collapses the idiosyncratic failures of any single one — a model that
// hallucinates a sink, or that is simply having a bad day on a prompt shape.
//
// WHY IT LIVES HERE AND NOWHERE ELSE. Every LLM call in the discovery layer
// already funnels through `resolveLlmInvoke`. Consensus is therefore a property
// of the seam, not of the hunter or the panel, and adding a provider cannot
// require touching either.
//
// WHAT CONSENSUS DOES AND DOES NOT MEAN. It reduces variance. It does NOT make
// the answer true — three models can agree and all be wrong, which is precisely
// why the deterministic confirmation gate still runs afterwards and still sets
// severity. Consensus is a noise filter in front of the real check, never a
// replacement for it.
//
// A provider that errors is EXCLUDED from the vote, not counted as dissent —
// the same rule `disprove.js` applies to its voters, for the same reason: an
// outage must never look like disagreement.
// Internal: read by resolveLlmInvoke below. Exporting it with no external
// caller is shipped dead code by the dead-module guard's definition.
const DEFAULT_CONSENSUS_ENV = 'AGENTIC_SECURITY_LLM_ENDPOINTS';

/** Split a comma-separated endpoint list into distinct URLs. */
function parseEndpoints(raw) {
  return String(raw || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .filter((v, i, a) => a.indexOf(v) === i); // duplicates would fake agreement
}

/**
 * Combine N responses into one, keeping the most common answer.
 *
 * Ties are resolved towards the FIRST endpoint listed, deterministically, rather
 * than arbitrarily — a caller ordering their endpoints by trust should get the
 * behaviour that ordering implies, and a random tie-break would make the whole
 * pipeline non-reproducible.
 */
function consensusOf(responses) {
  const usable = (responses || []).filter(r => typeof r === 'string' && r.trim());
  if (usable.length === 0) return { value: null, agreement: 0, voters: 0 };
  const counts = new Map();
  for (const r of usable) counts.set(r, (counts.get(r) || 0) + 1);
  let best = usable[0];
  let bestCount = counts.get(best);
  for (const r of usable) {
    const c = counts.get(r);
    if (c > bestCount) { best = r; bestCount = c; }
  }
  return { value: best, agreement: bestCount / usable.length, voters: usable.length };
}

/**
 * An llmInvoke that queries several endpoints and returns the consensus answer.
 * Returns null when no endpoint answered — the callers already treat a null or
 * a throw as degradation, so an all-providers-down run degrades honestly.
 *
 * FR-605 (assurance-hardening PRD): each endpoint gets its OWN egress
 * decision before being included — `mode: local-only` / `deniedProviders`
 * must not be smuggled past just because the SINGLE-endpoint path already
 * checks it. A policy-denied endpoint is EXCLUDED from the vote, the exact
 * same treatment an unreachable endpoint already gets a few lines below
 * (never counted as dissent) — the module's own established pattern
 * extended to a second exclusion reason. Returns `{invoke, decisions}`:
 * `invoke` is null only when EVERY endpoint was denied (the all-down
 * equivalent); `decisions` is the full per-endpoint array for a caller
 * that wants it, kept alongside the single aggregate `decision` the
 * pre-existing callers already read.
 */
function makeConsensusInvoke(endpoints, { timeoutMs, scanRoot, purpose } = {}) {
  const list = parseEndpoints(endpoints);
  if (list.length === 0) return { invoke: null, decisions: [] };
  const decisions = list.map(url => (0,policy/* evaluateEgress */.nn)({ scanRoot, purpose: purpose || 'discovery-consensus', endpoint: url }));
  const allowedList = list.filter((_, i) => decisions[i].allowed);
  if (allowedList.length === 0) return { invoke: null, decisions };
  const invoke = async (prompt) => {
    const answers = await Promise.all(allowedList.map(async (url) => {
      try { return await defaultLlmInvoke(prompt, { timeoutMs, endpoint: url }); }
      catch { return null; } // excluded from the vote, never counted as dissent
    }));
    const { value } = consensusOf(answers);
    if (value === null) throw new Error('no LLM endpoint answered');
    return value;
  };
  return { invoke, decisions };
}

// FR-601: egress policy is evaluated here, BEFORE returning a callable and
// therefore before either caller (hunter.js, disprove.js) builds a prompt —
// a denied decision makes this resolve to `invoke: null`, which both callers
// already treat as "nothing to call" via their existing degrade path, so a
// denial produces no network request through the exact same code path a
// missing endpoint always has. `decision` carries the machine-readable
// reason so callers can distinguish "not configured" from "configured but
// policy-denied" in their own degrade message, rather than reporting a
// generic "not set" that would be actively wrong once policy is what
// blocked the call.
//
// FR-605 (assurance-hardening PRD): consensus mode (multiple endpoints) is
// now egress-filtered per endpoint, same as the single-endpoint path below —
// this is what closes the actual "a remote URL cannot be smuggled into
// local-only configuration" gap the paragraph below used to describe as
// open. Per-endpoint CONSTRAINT dimensions beyond allow/deny/local-only
// (role/region/repository/path/data-class — one provider allowed, another
// denied for a REASON beyond the deny-list) remain FR-602's separate scope;
// what changed here is that the single allow/deny/local-only gate FR-601
// already built is no longer bypassable just by using multiple endpoints
// instead of one.
function resolveLlmInvokeWithDecision(opts = {}) {
  // An injected callback is a test/consumer-controlled escape hatch — it
  // bypasses egress the same way it already bypasses endpoint resolution,
  // because there is no real endpoint here for a policy to evaluate.
  if (opts.llmInvoke) return { invoke: opts.llmInvoke, decision: null };

  const multi = opts.endpoints || process.env[DEFAULT_CONSENSUS_ENV];
  if (multi) {
    const { invoke, decisions } = makeConsensusInvoke(multi, { timeoutMs: opts.timeoutMs, scanRoot: opts.scanRoot, purpose: opts.purpose });
    // A single aggregate `decision` for the pre-existing callers (hunter.js,
    // disprove.js), which only ever read `.reason` when `invoke` is null —
    // the all-denied case. The full per-endpoint detail is on `decisions`
    // for a caller that wants it.
    const decision = decisions.find(d => !d.allowed) || decisions[0] || null;
    return { invoke, decision, decisions };
  }

  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  if (!endpoint) return { invoke: null, decision: null };

  const decision = (0,policy/* evaluateEgress */.nn)({ scanRoot: opts.scanRoot, purpose: opts.purpose || 'discovery', endpoint });
  if (!decision.allowed) return { invoke: null, decision };

  return { invoke: (prompt) => defaultLlmInvoke(prompt, { timeoutMs: opts.timeoutMs }), decision };
}

function resolveLlmInvoke(opts = {}) {
  // Precedence, most explicit first: an injected callback beats configuration,
  // and a multi-endpoint list beats a single endpoint. A caller who supplied
  // their own function must always get exactly that function.
  return resolveLlmInvokeWithDecision(opts).invoke;
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
  const { invoke: llmInvoke, decision: egressDecision } = resolveLlmInvokeWithDecision({ ...opts, purpose: 'discovery-hunter' });

  if (typeof llmInvoke !== 'function') {
    // FR-601: distinguish "policy denied a configured endpoint" from "nothing
    // was configured at all" — the reason must reflect which actually happened.
    const reason = egressDecision
      ? `egress policy denied this call: ${egressDecision.reason}`
      : 'no llmInvoke supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set';
    appendEntry(transcript, { phase: 'init', reason, egressDecision: egressDecision || undefined });
    return { ...base, candidates: [], degraded: true, reason, egressDecision };
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
  // FR-601: an egress-policy denial resolves llmInvoke to null the same way a
  // missing endpoint always has, so it falls straight into this module's own
  // pre-existing rule — "silence never refutes" — with zero votes cast and no
  // prompt ever built for a denied endpoint.
  const { invoke: llmInvoke, decision: egressDecision } = resolveLlmInvokeWithDecision({ ...opts, purpose: 'discovery-disprove' });

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
  return { ...candidate, refutation: { votes, voterCount, refuteCount, refuted, undecided, egressDecision: egressDecision || undefined } };
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

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(1174);
;// CONCATENATED MODULE: ./src/discovery/memory.js
// Cross-run discovery memory — PRD Phase 3 / C4.
//
// WHAT WAS MISSING
// ----------------
// `judge.js` dedupes a hunt against `last-scan.json` and the triage ledger, so
// it knows what the RULE ENGINE found and what a human dismissed. It has never
// known what a PREVIOUS HUNT found. Two consequences, both bad:
//
//   1. Every run re-proposes, re-confirms and re-refutes the same candidates.
//      That is three LLM calls per candidate per run, spent to rediscover
//      something already judged — the exact waste the Phase 0 budget exists to
//      bound, being incurred deliberately.
//   2. A second run cannot be *additive*. Without a record of what was already
//      examined, "hunt again" means "hunt the same thing again" rather than
//      "hunt what we missed".
//
// This is that record. It turns a sequence of independent runs into a campaign.
//
// WHAT IS AND IS NOT REMEMBERED
// -----------------------------
// Remembered: every candidate ever JUDGED, with the verdict and the run that
// produced it. Also every focus area ever hunted, so coverage can become a plan
// instead of a report.
//
// NOT remembered: refuted candidates as if they were settled forever. A
// refutation is a majority opinion from three prompts on one day, not a proof.
// It suppresses re-reporting, and `--forget-refuted` exists precisely because a
// verdict made by a weaker model, or before a sanitiser was removed, must be
// re-openable. A memory you cannot clear is a memory that eventually lies.
//
// THE PRECEDENT THIS FOLLOWS
// --------------------------
// `judge.js` deliberately suppresses only `fp` triage verdicts and re-reports
// `tp` ones, because a prior true positive that is still in the code is still a
// bug. The same asymmetry holds here: a candidate previously judged FRESH is
// re-reported (it was never fixed), while one previously REFUTED is held back
// until something changes.





const MEMORY_SCHEMA = 'agentic-security/discovery-memory@1';
const MEMORY_FILE = external_node_path_.join('.agentic-security', 'discovery-memory.json');

function emptyMemory() {
  return { schema: MEMORY_SCHEMA, runs: 0, candidates: {}, areas: {} };
}

/** A stable identity for a candidate across runs. */
function memoryKey(candidate) {
  // Location + family, matching judge.js's PRIMARY duplicate key. Deliberately
  // NOT stableId: that is location-fuzzy by design and collides across distinct
  // findings in one file, which is tolerable for a single scan's dedupe and
  // corrosive when it accumulates across every run ever made.
  const file = candidate?.file ?? '?';
  const line = candidate?.line ?? '?';
  const family = candidate?.family ?? candidate?.lens ?? '?';
  return `${file}:${line}:${family}`;
}

/** Read the memory. Anything unreadable or unrecognised yields an empty one. */
function loadMemory(scanRoot) {
  try {
    const doc = JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(scanRoot, MEMORY_FILE), 'utf8'));
    if (doc?.schema !== MEMORY_SCHEMA) return emptyMemory();
    return { ...emptyMemory(), ...doc };
  } catch {
    // A corrupt memory must degrade to "remember nothing", never to a crash and
    // never to a partially-trusted record. Re-hunting is cheap next to acting on
    // a half-read ledger.
    return emptyMemory();
  }
}

/** Persist. Failure is non-fatal — the run still produced its report. */
function saveMemory(scanRoot, memory) {
  try {
    const p = external_node_path_.join(scanRoot, MEMORY_FILE);
    if (!(0,state_dir.stateWritesEnabled)()) return;
  external_node_fs_.mkdirSync(external_node_path_.dirname(p), { recursive: true });
    external_node_fs_.writeFileSync(p, JSON.stringify(memory, null, 2) + '\n');
    return true;
  } catch {
    return false;
  }
}

/**
 * Should this candidate be held back because a previous run already judged it?
 *
 * Only a REFUTED verdict suppresses. Everything else — fresh, duplicate,
 * suppressed-by-triage — is re-evaluated, because those states are about the
 * code and the code may have changed.
 */
function previouslyRefuted(memory, candidate) {
  const rec = memory?.candidates?.[memoryKey(candidate)];
  return Boolean(rec && rec.verdict === 'refuted');
}

/** Fold this run's outcome into the memory. Returns a NEW memory object. */
function rememberRun(memory, { fresh = [], refutedCandidates = [], areas = [], at }) {
  const next = {
    ...emptyMemory(),
    ...memory,
    candidates: { ...(memory?.candidates || {}) },
    areas: { ...(memory?.areas || {}) },
  };
  next.runs = (memory?.runs || 0) + 1;
  const stamp = at || new Date().toISOString();

  for (const f of fresh) {
    next.candidates[memoryKey(f)] = { verdict: 'fresh', run: next.runs, at: stamp };
  }
  for (const c of refutedCandidates) {
    next.candidates[memoryKey(c)] = { verdict: 'refuted', run: next.runs, at: stamp };
  }
  for (const a of areas) {
    const prev = next.areas[a.id] || { hunts: 0 };
    next.areas[a.id] = {
      label: a.label,
      hunts: prev.hunts + (a.hunted ? 1 : 0),
      lastRun: a.hunted ? next.runs : (prev.lastRun ?? null),
      files: a.files ?? prev.files ?? null,
    };
  }
  return next;
}

/**
 * Turn the memory into a PLAN: which areas have never been successfully hunted.
 *
 * This is the half that makes a second run additive rather than repetitive. A
 * coverage report says what happened; this says what to do next.
 */
function nextWavePlan(memory, areas) {
  const unhunted = [];
  const stale = [];
  for (const a of areas || []) {
    const rec = memory?.areas?.[a.id];
    if (!rec || rec.hunts === 0) unhunted.push(a.label || a.id);
    else if (rec.lastRun !== memory.runs) stale.push(a.label || a.id);
  }
  return {
    unhunted,
    stale,
    // Stated as a sentence because this lands in a report a human reads, and
    // "3 areas" without saying which ones is not actionable.
    summary: unhunted.length
      ? `${unhunted.length} focus area(s) have NEVER been successfully hunted: ${unhunted.slice(0, 5).join(', ')}` +
        (unhunted.length > 5 ? `, +${unhunted.length - 5} more` : '')
      : 'every focus area has been hunted at least once',
  };
}

/** Drop refuted verdicts so they can be re-examined. */
function forgetRefuted(memory) {
  const candidates = {};
  for (const [k, v] of Object.entries(memory?.candidates || {})) {
    if (v?.verdict !== 'refuted') candidates[k] = v;
  }
  return { ...emptyMemory(), ...memory, candidates };
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
    const { runDeepAnalysis } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 2555));
    return runDeepAnalysis(perFileIR, callGraph, {});
  } catch {
    return null;
  }
}

// ctx = { perFileIR, callGraph, fileContents, priorScan, triageFeedback }
// where { perFileIR, callGraph } come from buildProjectIR(fileContents),
// which returns { perFile, callGraph } — callers must pass perFile as
// perFileIR (see scanner/src/ir/index.js).
/**
 * PRD Phase 0 / C3 — the run budget.
 *
 * This pipeline is multiplicative and was, until now, unbounded. Eight focus
 * areas × seven lenses is 56 hunter calls before a single candidate exists, and
 * every surviving candidate then costs three more calls in the refutation
 * panel. Nothing capped any of it, so the cost of a run was a function of how
 * large the repository happened to be — which is not a property you want to
 * discover from an invoice.
 *
 * ENFORCED AT THE ONE SEAM EVERY CALL PASSES THROUGH. Rather than thread checks
 * through the hunter and the panel, the budget wraps `llmInvoke` itself. When
 * it is spent the wrapper throws, and both callers already treat a throwing
 * llmInvoke as ordinary degradation with a stated reason. So exhaustion arrives
 * through the same path as a rate limit or a dead endpoint, and lands in
 * `coverage.reasons` like any other coverage gap. No new failure mode.
 *
 * CALLS AND WALL CLOCK, NOT TOKENS. `llmInvoke` is an injected callback that
 * returns a string; it carries no usage metadata, so counting tokens here would
 * mean inventing a number. Calls are exactly countable and wall clock is
 * exactly observable. A caller who knows their per-call cost can pass
 * `costPerCallUsd` and get a `maxCostUsd` ceiling expressed in calls, which is
 * honest about being an estimate derived from their figure rather than ours.
 */
// Internal, not exported: the dead-module guard treats an export with no
// external call site as shipped dead code, and these are read only by
// makeBudget below. A consumer sets a ceiling by passing opts, not by importing
// a constant.
const DEFAULT_MAX_LLM_CALLS = 200;
const DEFAULT_MAX_WALL_MS = 15 * 60 * 1000;
const DEFAULT_MAX_CANDIDATES = 50;

function makeBudget(opts = {}, now = Date.now) {
  const startedAt = now();
  let maxCalls = Number.isInteger(opts.maxLlmCalls) && opts.maxLlmCalls >= 0
    ? opts.maxLlmCalls : DEFAULT_MAX_LLM_CALLS;
  // A dollar ceiling is only meaningful with a caller-supplied per-call cost.
  // Converting it to a call count keeps one enforcement mechanism rather than
  // two that can disagree.
  if (Number.isFinite(opts.maxCostUsd) && Number.isFinite(opts.costPerCallUsd) && opts.costPerCallUsd > 0) {
    maxCalls = Math.min(maxCalls, Math.floor(opts.maxCostUsd / opts.costPerCallUsd));
  }
  const maxWallMs = Number.isInteger(opts.maxWallMs) && opts.maxWallMs > 0
    ? opts.maxWallMs : DEFAULT_MAX_WALL_MS;

  let calls = 0;
  let exhaustedReason = null;

  const check = () => {
    if (exhaustedReason) return exhaustedReason;
    if (calls >= maxCalls) return (exhaustedReason = `LLM call budget spent (${calls}/${maxCalls} calls)`);
    if (now() - startedAt >= maxWallMs) {
      return (exhaustedReason = `wall-clock budget spent (${Math.round(maxWallMs / 1000)}s)`);
    }
    return null;
  };

  return {
    get calls() { return calls; },
    get maxCalls() { return maxCalls; },
    get exhaustedReason() { return exhaustedReason; },
    spent: () => check() !== null,
    /** Wrap an llmInvoke so every call is counted and the ceiling is enforced. */
    wrap(llmInvoke) {
      if (typeof llmInvoke !== 'function') return llmInvoke;
      return async (prompt) => {
        const stop = check();
        if (stop) throw new Error(`discovery budget exhausted: ${stop}`);
        calls += 1;
        return llmInvoke(prompt);
      };
    },
  };
}

async function runDiscovery(ctx = {}, opts = {}) {
  const areas = partitionCallGraph(ctx.callGraph, { maxAreas: opts.maxAreas ?? 8 });

  const reasons = [];
  const budget = makeBudget(opts);
  // PRD C4 — what previous runs already judged. scanRoot absent => no memory,
  // which is the correct default for a library call with nowhere to persist.
  const memory = opts.scanRoot ? loadMemory(opts.scanRoot) : null;
  // Every LLM call in this pipeline goes through this one wrapped callback.
  const llmInvoke = budget.wrap(opts.llmInvoke);

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
      const run = await runHunter(area, lens, { fileContents: ctx.fileContents || {} }, { llmInvoke, scanRoot: opts.scanRoot });
      runs.push({ focusAreaId: run.focusAreaId, lens: run.lens, degraded: run.degraded, reason: run.reason, candidateCount: run.candidates.length });
      if (run.degraded && run.reason) reasons.push(`${area.label} × ${lens.key}: ${run.reason}`);
      if (run.degraded) areaDegradedCount += 1;
      else hunted.add(area.id);
      candidates = candidates.concat(run.candidates);
    }
    if (lenses.length > 0 && areaDegradedCount === 0) fullyHunted.add(area.id);
  }

  // PRD Phase 0 / C3.2 — the candidate cap.
  //
  // Every candidate that reaches the panel costs three more LLM calls, so an
  // unusually productive hunt multiplies straight into spend. Cap it, and
  // REPORT the cap rather than applying it silently: a run that quietly
  // examined the first N candidates and said nothing would look identical to a
  // run that found only N. Same precedent as prove-findings.js's `capped`.
  // PRD C4 — drop what a previous run already refuted, BEFORE spending the
  // panel's three calls per candidate on it again. Only refutals suppress: a
  // candidate previously judged fresh is re-reported, because it was never
  // fixed, which is the same asymmetry judge.js applies to tp/fp triage.
  let rememberedRefutals = 0;
  if (memory) {
    const before = candidates.length;
    candidates = candidates.filter(c => !previouslyRefuted(memory, c));
    rememberedRefutals = before - candidates.length;
    if (rememberedRefutals > 0) {
      reasons.push(`${rememberedRefutals} candidate(s) were refuted by an earlier run and not re-examined ` +
        '(clear with --forget-refuted if a model, ruleset or the code has changed since)');
    }
  }

  const maxCandidates = Number.isInteger(opts.maxCandidates) && opts.maxCandidates >= 0
    ? opts.maxCandidates : DEFAULT_MAX_CANDIDATES;
  let candidatesCapped = 0;
  if (candidates.length > maxCandidates) {
    candidatesCapped = candidates.length - maxCandidates;
    // Deterministic: candidates arrive in a stable (area, lens) order, so the
    // cap keeps the same prefix on every run over the same inputs.
    candidates = candidates.slice(0, maxCandidates);
    reasons.push(`candidate cap: ${candidatesCapped} candidate(s) were NOT confirmed or refuted ` +
      `(cap ${maxCandidates}); they are neither findings nor cleared — they were not examined`);
  }

  // PRD D3 — the hybrid-loop uplift measurement.
  //
  // `confirm: false` runs the pipeline with the deterministic gate switched OFF,
  // so every candidate reaches the panel as `unconfirmed`. Running a population
  // both ways and diffing the result isolates what the taint engine contributes
  // on top of the model — a number no surveyed competitor can compute, because
  // none of them has a deterministic layer to switch off.
  //
  // It exists ONLY to be measured against. It is not a performance switch, and
  // a run with it disabled is strictly weaker: severity collapses to `low` for
  // everything, since the confirmation tier is what sets it.
  const confirmationEnabled = opts.confirm !== false;
  const taintProbe = confirmationEnabled ? makeTaintProbe(ctx.perFileIR, ctx.callGraph) : null;
  if (!confirmationEnabled) {
    reasons.push('deterministic confirmation was DISABLED for this run (uplift measurement); ' +
      'every candidate is reported unconfirmed and severity is not evidence-derived');
  }
  const confirmed = await confirmAll(candidates, { taintProbe });
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke, scanRoot: opts.scanRoot });
  const { fresh, duplicates, suppressed } = judgeCandidates(survivors, ctx.priorScan, ctx.triageFeedback);

  // A spent budget is a coverage gap, stated once at the top level rather than
  // left to be inferred from N identical per-run degradation reasons.
  if (budget.exhaustedReason) {
    reasons.push(`RUN INCOMPLETE — ${budget.exhaustedReason}. Work remained when the budget ran ` +
      'out, so absence of a finding below is not evidence of absence. Raise maxLlmCalls / ' +
      'maxWallMs, or narrow the scope with --root or --lens, and re-run.');
  }

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

  // PRD C4 — fold this run into the memory so the next one can be additive
  // rather than a repeat. Persistence failure is non-fatal: the report is still
  // valid, it just will not inform the next run.
  if (memory && opts.scanRoot) {
    saveMemory(opts.scanRoot, rememberRun(memory, {
      fresh, refutedCandidates: refuted,
      areas: areas.map(a => ({ id: a.id, label: a.label, files: a.files.length, hunted: hunted.has(a.id) })),
    }));
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
      // PRD Phase 0 / C3 — what the run cost and whether the budget stopped it.
      // `budgetExhausted` true means the report is INCOMPLETE by construction:
      // work remained and was not done. Reading it as a clean result is the
      // exact misreading the coverage block exists to prevent.
      // PRD C4 — what history contributed, and what to hunt next. A coverage
      // report says what happened; `nextWave` says what to do about it.
      rememberedRefutals,
      priorRuns: memory ? memory.runs : null,
      nextWave: memory ? nextWavePlan(memory, areas.map(a => ({ id: a.id, label: a.label }))) : null,
      llmCalls: budget.calls,
      maxLlmCalls: budget.maxCalls,
      // PRD N4 — the standing cost metric. C3 bounded the worst case and C4
      // moved the typical case by 4x, so cost is a property that drifts across
      // several workstreams rather than one that a phase finishes. A number
      // that only appears when somebody goes looking regresses silently, so it
      // is reported every run and carries its denominator like every other rate
      // in this engine. `null` when nothing was found — dividing by zero
      // findings would print Infinity and read as a catastrophe rather than as
      // "there is nothing to divide".
      callsPerFinding: fresh.length > 0 ? Number((budget.calls / fresh.length).toFixed(1)) : null,
      budgetExhausted: Boolean(budget.exhaustedReason),
      candidatesCapped,
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
