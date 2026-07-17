// Deterministic honesty gates on fix / finding output (#7).
//
// The project's verification discipline (scanner/CLAUDE.md) exists because
// several releases shipped broken or false because work was reported as done
// without confirming the artifact changed. Two of those failure modes are
// *textual* — they live in the prose an agent emits alongside a fix — and can
// be caught deterministically, with no LLM and no network:
//
//   1. Hand-wave residual-risk prose. "The input is adequately handled",
//      "future work", "tbd", "later" — vague assurances that claim safety
//      without naming a concrete remaining vector. A residual you can't name
//      is a residual you're guessing about; reject the guess.
//
//   2. An unbacked "this is a false positive / provably safe" verdict. Marking
//      a finding safe is a coverage *reduction* — it must cite a `file:line`
//      that shows why, exactly like the rules-override gate refuses to silently
//      shrink coverage.
//
// Plus a conservative fix-tier classifier so a partial remediation can never be
// labelled FULL: any workaround-only signal (rate-limit, docs, log-without-
// reject) is WORKAROUND; anything short of (sink signature changed + all callers
// routed + a discriminating test) is at most MITIGATION; only the full set with
// no partial-sanitization caveat earns FULL.
//
// Pure functions, no side effects, no throwing — safe to call from a command,
// a hook, or the MCP verify_fix path.

// Vague-assurance phrases that a real residual must never hide behind. Matched
// case-insensitively with word boundaries so "later" doesn't trip on
// "collateral" and "tbd" doesn't trip on a longer token.
const BANNED_RESIDUAL_PHRASES = Object.freeze([
  'adequately handled',
  'adequately handles',
  'properly validated',
  'properly handled',
  'handled properly',
  'handled safely',
  'future work',
  'more work needed',
  'to be done',
  'tbd',
  'later',
]);

// A citation shaped like `file:line` — one or more non-space, non-colon chars,
// a colon, then digits. Unanchored: it need only appear somewhere in the item.
const CITATION_RE = /[^\s:]+:\d+/;

// Verdicts that assert the finding is not real and therefore demand a citation.
// Compared after normalizing separators (`_`/space → `-`) and lowercasing, so
// FALSE_POSITIVE, false-positive, and "provably safe" all land here.
const FP_VERDICTS = Object.freeze(new Set(['false-positive', 'provably-safe', 'safe']));

function _escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Reject vague-assurance / hand-wave residual-risk prose.
 *
 * An empty or whitespace-only residual is ok — there is no residual to lie
 * about. A non-empty residual is rejected when it contains any banned phrase;
 * each match yields one violation naming the offending phrase.
 *
 * @param {string} residualText
 * @returns {{ ok: boolean, violations: string[] }}
 */
export function checkResidualHonesty(residualText) {
  const text = typeof residualText === 'string' ? residualText : '';
  if (text.trim() === '') return { ok: true, violations: [] };

  const violations = [];
  for (const phrase of BANNED_RESIDUAL_PHRASES) {
    const re = new RegExp(`\\b${_escapeRe(phrase)}\\b`, 'i');
    if (re.test(text)) {
      violations.push(`vague-assurance phrase: "${phrase}"`);
    }
  }
  return { ok: violations.length === 0, violations };
}

function _isCitation(item) {
  if (typeof item === 'string') return CITATION_RE.test(item);
  if (item && typeof item === 'object' && typeof item.location === 'string') {
    return CITATION_RE.test(item.location);
  }
  return false;
}

function _normalizeVerdict(verdict) {
  return String(verdict).trim().toLowerCase().replace(/[_\s]+/g, '-');
}

/**
 * Require a file:line citation behind a "this is not real" verdict.
 *
 * For a false-positive / provably-safe / safe verdict (case-insensitive; also
 * accepts FALSE_POSITIVE), at least one evidence item must be a `file:line`
 * citation — either a string matching /[^\s:]+:\d+/ or an object
 * `{ location: "file:line" }`. Any other verdict passes unconditionally.
 *
 * @param {string} verdict
 * @param {Array|string|object} evidence
 * @returns {{ ok: boolean, violations: string[] }}
 */
export function requireCitedEvidence(verdict, evidence) {
  if (typeof verdict !== 'string' || !FP_VERDICTS.has(_normalizeVerdict(verdict))) {
    return { ok: true, violations: [] };
  }
  const items = Array.isArray(evidence)
    ? evidence
    : evidence == null
      ? []
      : [evidence];
  if (items.some(_isCitation)) return { ok: true, violations: [] };
  return {
    ok: false,
    violations: ['false-positive/safe verdict requires a file:line citation'],
  };
}

/**
 * Classify a fix into FULL | MITIGATION | WORKAROUND, conservative-first.
 *
 * @param {object} signals
 * @param {boolean} signals.sinkSignatureChanged
 * @param {boolean} signals.allCallersRouted
 * @param {boolean} signals.testDiscriminates - a test that fails pre-fix, passes post-fix
 * @param {boolean} [signals.rateLimitOnly]
 * @param {boolean} [signals.docsOnly]
 * @param {boolean} [signals.logOnlyNoReject]
 * @param {boolean} [signals.partialSanitization]
 * @returns {'FULL'|'MITIGATION'|'WORKAROUND'}
 */
export function computeFixTier(signals) {
  const s = signals && typeof signals === 'object' ? signals : {};
  if (s.rateLimitOnly || s.docsOnly || s.logOnlyNoReject) return 'WORKAROUND';
  const complete = s.sinkSignatureChanged && s.allCallersRouted && s.testDiscriminates;
  if (s.partialSanitization || !complete) return 'MITIGATION';
  return 'FULL';
}

/**
 * Compose the three gates for a single fix's output.
 *
 * ok = residual-honesty ok AND evidence-citation ok, further constrained by the
 * tier/residual consistency invariant:
 *   - a FULL tier must NOT carry a residual (a full fix has nothing left);
 *   - a non-FULL tier MUST document a residual (say what's still open).
 *
 * @param {{ residual?: string, verdict?: string, evidence?: any, signals?: object }} input
 * @returns {{ ok: boolean, tier: string, violations: string[] }}
 */
export function gateFixOutput({ residual, verdict, evidence, signals } = {}) {
  const tier = computeFixTier(signals);
  const residualCheck = checkResidualHonesty(residual);
  const evidenceCheck = requireCitedEvidence(verdict, evidence);

  const violations = [...residualCheck.violations, ...evidenceCheck.violations];
  let ok = residualCheck.ok && evidenceCheck.ok;

  const residualEmpty = typeof residual !== 'string' || residual.trim() === '';
  if (tier === 'FULL' && !residualEmpty) {
    violations.push('FULL tier cannot carry a residual');
    ok = false;
  }
  if (tier !== 'FULL' && residualEmpty) {
    violations.push('non-FULL tier must document a residual');
    ok = false;
  }

  return { ok, tier, violations };
}

export const _internals = Object.freeze({ BANNED_RESIDUAL_PHRASES, CITATION_RE, FP_VERDICTS });
