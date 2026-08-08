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
export const REFUTE_ANGLES = Object.freeze([...DEFAULT_ANGLES]);

const ANGLE_BRIEF = {
  reachability: 'Can attacker-controlled data actually reach this line at runtime? Name the caller chain or show there is none.',
  preconditions: 'What must the attacker already have — a session, a role, a tenant, a race window? If the prerequisites exceed the impact, it is refuted.',
  sanitization: 'Is the value validated, escaped, parameterised, or type-constrained anywhere on the path? A framework default counts.',
};

export function buildRefutePrompt(candidate, angle) {
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

async function defaultLlmInvoke(prompt) {
  const res = await fetch(process.env.AGENTIC_SECURITY_LLM_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

export async function disproveCandidate(candidate, opts = {}) {
  const angles = Array.isArray(opts.angles) && opts.angles.length ? opts.angles : DEFAULT_ANGLES;
  const llmInvoke = opts.llmInvoke
    || (process.env.AGENTIC_SECURITY_LLM_ENDPOINT ? defaultLlmInvoke : null);

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

export async function disprovePanel(candidates, opts = {}) {
  const survivors = [], refuted = [];
  for (const c of candidates || []) {
    const judged = await disproveCandidate(c, opts);
    (judged.refutation.refuted ? refuted : survivors).push(judged);
  }
  return { survivors, refuted };
}
