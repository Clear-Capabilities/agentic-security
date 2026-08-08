// PRD Epic 6 — the business-logic tier's missing half.
//
// The deterministic side of business logic already exists and is wired:
// `sast/logic.js` carries the canonical anti-patterns, `posture/business-logic.js`
// builds the per-route authZ matrix, extracts state machines and finds
// negative-test gaps. What did NOT exist was any handling of the OTHER
// producer — the reviewing agent, which is the only party that can read intent
// and is therefore the only one that can find the flaws patterns cannot.
//
// THE PROBLEM WITH THAT PRODUCER. Everything else in this engine can be
// checked: a taint finding has a path, an execution-proven finding has a marker
// file, an SCA finding has a version range. A logic claim is prose. It arrives
// asserting that a handler lets one user act on another's resource, and there
// is nothing in the finding that a second party could disagree with. An
// unrefutable claim is the weakest thing this engine emits, and it was the only
// tier with no way to be wrong.
//
// WHAT THIS MODULE DOES. It takes claims from a reviewing agent and puts them
// through deterministic lenses that can REFUTE them — cheaply, offline, and
// without asking a model to grade its own homework:
//
//   citation   — the file exists and the cited line is inside it. A claim about
//                `routes/orders.js:214` in a 90-line file is refuted on the
//                spot; that is the signature of a fabricated location.
//   quotation  — the snippet the claim quotes actually appears at the cited
//                line (± a small window). A claim that misquotes the code it is
//                about was not written from the code.
//   corroboration — for the claim kinds that MAKE a checkable assertion about
//                the source ("this route has no authentication"), check it.
//                A route that plainly does authenticate refutes it.
//
// RECALL-PRESERVING, same precedent as `falsification.js` and `proof-gate.js`.
// A refuted claim is marked and kept, never deleted and never severity-touched.
// Refutation here means "no second party could corroborate this", which is a
// triage signal, not proof the reviewer was wrong.
//
// SEPARATION IS ENFORCED, NOT ASSUMED. The agent is stamped as producer and
// these lenses record under their own verifier ids, so `assertSeparation`
// refuses if anything ever tries to verify its own claim. That is why the
// lenses live here in deterministic code rather than in the agent's prompt: a
// reviewer asked to double-check itself is the same party voting twice.

import { recordProducer, recordVerdict, consensusOf } from './verification-separation.js';

export const PRODUCER = 'agent:logic-reviewer';

export const VERIFIER_CITATION = 'verifier:citation';
const VERIFIER_QUOTATION = 'verifier:quotation';
export const VERIFIER_CORROBORATION = 'verifier:logic-corroboration';

// Claim kinds that assert something checkable about the source. Anything else
// is accepted as unverifiable-but-recorded rather than silently upheld.
const CLAIM_KINDS = Object.freeze([
  'missing-authentication',
  'missing-authorization',
  'missing-ownership-check',
  'state-transition-bypass',
  'race-condition',
  'other',
]);

// Reused deliberately from the same vocabulary the authZ matrix uses, so a
// corroboration verdict and a matrix finding cannot disagree about what
// "authenticated" means in this codebase.
const AUTH_HINTS = [
  /\breq\.user\b/, /\breq\.auth\b/, /\brequest\.user\b/,
  /requireAuth|isAuthenticated|@login_required|@requires_auth|@jwt_required/,
  /authorize|authMiddleware|verifyJWT|jwt\.verify\b/, /\bpassport\b/,
  /\bgetSession\b|\bcurrentUser\b/,
];
const OWNERSHIP_HINTS = [
  /\bowner(?:Id)?\b/i, /\buser_?id\s*[=:]/i,
  /\.userId\s*===\s*req\.user/, /\.owner\s*===\s*req\.user/,
  /where\s*:\s*\{[^}]*user/i,
];

// How far from the cited line a quoted snippet may appear before the citation
// is treated as not corroborated. Small on purpose: an agent reading the file
// is off by a line or two, not by twenty.
const QUOTE_WINDOW = 3;

function _lines(content) { return String(content).split('\n'); }

function _normalize(s) {
  return String(s).replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * The enclosing handler body around a line, bounded by blank-line-separated
 * top-level blocks. Deliberately crude: a corroboration lens that guessed at
 * scope precisely would be a parser, and a wrong guess here REFUTES a real
 * finding. So the window is generous — it errs toward finding the auth check
 * and therefore toward refusing to refute.
 */
function _enclosingBlock(content, line) {
  const ls = _lines(content);
  const idx = Math.max(0, Math.min(ls.length - 1, line - 1));
  let start = idx, end = idx;
  while (start > 0 && !/^\s*$/.test(ls[start - 1])) start--;
  while (end < ls.length - 1 && !/^\s*$/.test(ls[end + 1])) end++;
  // Widen by a few lines either side: middleware often sits on the route line
  // above the block the flaw is in.
  start = Math.max(0, start - 5);
  end = Math.min(ls.length - 1, end + 5);
  return ls.slice(start, end + 1).join('\n');
}

/**
 * Put one claim through the deterministic lenses.
 *
 * @param {object} claim  {file, line, vuln, kind, description, snippet?, severity?}
 * @param {object|Map} fileContents  file -> source
 * @returns {object} the claim as a finding, carrying `verification`
 */
export function verifyLogicClaim(claim, fileContents) {
  const finding = {
    ...claim,
    parser: 'LOGIC-AGENT',
    family: claim.family || 'business-logic',
    kind: CLAIM_KINDS.includes(claim.kind) ? claim.kind : 'other',
  };
  recordProducer(finding, claim.producer || PRODUCER);

  const read = (f) => {
    if (!fileContents) return null;
    if (typeof fileContents.get === 'function') return fileContents.get(f) ?? null;
    return fileContents[f] ?? null;
  };
  const content = claim.file ? read(claim.file) : null;

  // ── citation ──────────────────────────────────────────────────────────────
  if (content === null) {
    recordVerdict(finding, {
      verifierId: VERIFIER_CITATION, lens: 'citation', verdict: 'refuted',
      reason: `no file '${claim.file}' was scanned, so the cited location does not exist`,
    });
    finding.consensus = consensusOf(finding);
    finding.quarantined = true;
    return finding;
  }
  const total = _lines(content).length;
  const line = Number(claim.line);
  if (!Number.isInteger(line) || line < 1 || line > total) {
    recordVerdict(finding, {
      verifierId: VERIFIER_CITATION, lens: 'citation', verdict: 'refuted',
      reason: `cited line ${claim.line} is outside ${claim.file} (${total} lines)`,
    });
  } else {
    recordVerdict(finding, {
      verifierId: VERIFIER_CITATION, lens: 'citation', verdict: 'upheld',
      reason: `${claim.file}:${line} exists`,
    });
  }

  // ── quotation ─────────────────────────────────────────────────────────────
  // Only a lens when the claim actually quotes something. A claim with no
  // snippet is UNDECIDED here, not upheld — silence is not corroboration.
  if (!claim.snippet || !String(claim.snippet).trim()) {
    recordVerdict(finding, {
      verifierId: VERIFIER_QUOTATION, lens: 'quotation', verdict: 'undecided',
      reason: 'the claim quotes no source, so there is nothing to check it against',
    });
  } else {
    const want = _normalize(claim.snippet);
    const ls = _lines(content);
    const lo = Math.max(0, (line || 1) - 1 - QUOTE_WINDOW);
    const hi = Math.min(ls.length, (line || 1) + QUOTE_WINDOW);
    const window = _normalize(ls.slice(lo, hi).join(' '));
    const anywhere = _normalize(content);
    if (window.includes(want)) {
      recordVerdict(finding, {
        verifierId: VERIFIER_QUOTATION, lens: 'quotation', verdict: 'upheld',
        reason: 'the quoted source appears at the cited line',
      });
    } else if (anywhere.includes(want)) {
      // Right file, wrong line. Not a fabrication, but the location is not
      // usable as-is, so it is not corroboration either.
      recordVerdict(finding, {
        verifierId: VERIFIER_QUOTATION, lens: 'quotation', verdict: 'undecided',
        reason: 'the quoted source is in the file but not at the cited line',
      });
    } else {
      recordVerdict(finding, {
        verifierId: VERIFIER_QUOTATION, lens: 'quotation', verdict: 'refuted',
        reason: 'the quoted source does not appear in the cited file',
      });
    }
  }

  // ── corroboration ─────────────────────────────────────────────────────────
  const block = _enclosingBlock(content, line || 1);
  if (finding.kind === 'missing-authentication') {
    const hit = AUTH_HINTS.find((re) => re.test(block));
    recordVerdict(finding, hit
      ? { verifierId: VERIFIER_CORROBORATION, lens: 'authz', verdict: 'refuted',
        reason: `the handler around this line does authenticate (${hit.source})` }
      : { verifierId: VERIFIER_CORROBORATION, lens: 'authz', verdict: 'upheld',
        reason: 'no authentication marker anywhere in the enclosing handler' });
  } else if (finding.kind === 'missing-authorization' || finding.kind === 'missing-ownership-check') {
    const hit = OWNERSHIP_HINTS.find((re) => re.test(block));
    recordVerdict(finding, hit
      ? { verifierId: VERIFIER_CORROBORATION, lens: 'authz', verdict: 'refuted',
        reason: `the handler around this line does scope the record to a user (${hit.source})` }
      : { verifierId: VERIFIER_CORROBORATION, lens: 'authz', verdict: 'upheld',
        reason: 'no ownership scoping in the enclosing handler' });
  } else {
    // No deterministic lens exists for this kind. Said out loud rather than
    // counted as agreement — an unchecked claim and a corroborated one must
    // not read the same in the consensus.
    recordVerdict(finding, {
      verifierId: VERIFIER_CORROBORATION, lens: 'authz', verdict: 'undecided',
      reason: `no deterministic lens covers claim kind '${finding.kind}'`,
    });
  }

  finding.consensus = consensusOf(finding);
  // Quarantine, not deletion — the same contract falsification uses.
  finding.quarantined = finding.consensus.verdict === 'refuted';
  return finding;
}

/**
 * Verify a batch. Nothing is dropped: the returned list is the same length as
 * the input, in the same order.
 */
export function ingestLogicClaims(claims, { fileContents = null } = {}) {
  const list = Array.isArray(claims) ? claims : [];
  const out = list.map((c) => {
    try { return verifyLogicClaim(c, fileContents); }
    catch (e) {
      // A lens that throws must not swallow the claim.
      const f = { ...c, parser: 'LOGIC-AGENT', family: 'business-logic', quarantined: false };
      f.consensus = { verdict: 'undecided', upheld: 0, refuted: 0, undecided: 0, lenses: [] };
      f.verificationError = String(e?.message || e);
      return f;
    }
  });
  return { claims: out, summary: summarizeLogicClaims(out) };
}

function summarizeLogicClaims(claims) {
  const s = { total: claims.length, corroborated: 0, refuted: 0, unverifiable: 0 };
  for (const c of claims) {
    const v = c.consensus?.verdict;
    if (v === 'upheld') s.corroborated++;
    else if (v === 'refuted') s.refuted++;
    else s.unverifiable++;
  }
  return s;
}

/** One line. Leads with what could not be corroborated. */
export function renderLogicClaimSummary(s) {
  if (!s || !s.total) return null;
  const bits = [`${s.total} business-logic claim(s)`];
  if (s.refuted) bits.push(`${s.refuted} REFUTED by a deterministic lens (quarantined, not deleted)`);
  if (s.unverifiable) bits.push(`${s.unverifiable} unverifiable — no lens could agree or disagree`);
  if (s.corroborated) bits.push(`${s.corroborated} corroborated`);
  return bits.join('; ') + '.';
}

// Not exported: the quotation verifier id, the claim-kind vocabulary and the
// batch summariser have no consumer outside this module. Kept internal rather
// than exported-and-unused — an export with no call site is how dead code gets
// shipped and then trusted.
export const _internals = { AUTH_HINTS, OWNERSHIP_HINTS, _enclosingBlock, QUOTE_WINDOW, CLAIM_KINDS, VERIFIER_QUOTATION, summarizeLogicClaims };
