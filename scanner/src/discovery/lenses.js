//
// The seven hunting lenses. Each hunter run is one (focus area × lens) pair.
//
// WHY DIVERSE LENSES RATHER THAN N IDENTICAL HUNTERS: redundancy raises
// confidence in what was already found and adds nothing to coverage. A lens
// that is told to look only at authorization asks different questions of the
// same code than one told to look at crypto, so the union covers failure modes
// no single prompt reaches. `wildcard` exists because a fixed taxonomy is a
// ceiling, and the classes worth finding are the ones not on the list.
export const LENSES = Object.freeze([
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

export function lensByKey(key) {
  if (typeof key !== 'string') return null;
  return LENSES.find(l => l.key === key) || null;
}

const DEFAULT_MAX_CHARS = 60_000;

export function buildHunterPrompt(focusArea, lens, ctx = {}) {
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
