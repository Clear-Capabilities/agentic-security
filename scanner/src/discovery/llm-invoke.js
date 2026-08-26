//
// Shared LLM endpoint caller. Both the hunter and the refutation panel need
// the same default endpoint caller when tests don't inject a mock. Two copies
// of a network call is one copy too many — if one path gets fixed and the
// other does not, the bug stays buried in one direction.
//

import { evaluateEgress } from '../egress/policy.js';

const DEFAULT_TIMEOUT_MS = 60000;

export async function defaultLlmInvoke(prompt, opts = {}) {
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
export function parseEndpoints(raw) {
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
export function consensusOf(responses) {
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
  const decisions = list.map(url => evaluateEgress({ scanRoot, purpose: purpose || 'discovery-consensus', endpoint: url }));
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
export function resolveLlmInvokeWithDecision(opts = {}) {
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

  const decision = evaluateEgress({ scanRoot: opts.scanRoot, purpose: opts.purpose || 'discovery', endpoint });
  if (!decision.allowed) return { invoke: null, decision };

  return { invoke: (prompt) => defaultLlmInvoke(prompt, { timeoutMs: opts.timeoutMs }), decision };
}

export function resolveLlmInvoke(opts = {}) {
  // Precedence, most explicit first: an injected callback beats configuration,
  // and a multi-endpoint list beats a single endpoint. A caller who supplied
  // their own function must always get exactly that function.
  return resolveLlmInvokeWithDecision(opts).invoke;
}
