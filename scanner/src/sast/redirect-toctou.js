// PRD T4.4 + T4.5 — redirect/header-forwarding semantics, and validate-then-
// resolve TOCTOU. 11 of the 96 root-caused real-world misses between them.
//
// WHY THESE ARE NOT ALREADY COVERED. Every existing "redirect" rule in this
// codebase is CWE-601 open-redirect — the app sends an attacker-controlled
// Location header. These are the OPPOSITE direction: the app is the CLIENT,
// and the danger is what its own outbound request does when the SERVER
// redirects it.
//
//   T4.4a (CWE-200) — credential headers survive an origin-changing redirect.
//       `httpx.get(url, headers=auth_headers, follow_redirects=True)` replays
//       Authorization to whatever host the first server names.
//       (GHSA-r5vv-ff45-prp2, GHSA-4jc5-g844-4x33)
//   T4.4b (CWE-918) — a validated URL is followed into redirect space with no
//       per-hop re-validation, so the allow-list is checked once and bypassed
//       on hop 2. (GHSA-c9hr-64h3-gxpc)
//   T4.5  (CWE-367) — the value CHECKED and the value USED are resolved
//       separately, so they can differ: DNS rebinding between an IP check and
//       the connect, or a re-resolved path after a containment check.
//       (GHSA-ch52-px8q-f22j, GHSA-vx7x-vcc2-c44g)
//
// Precision comes from requiring the mitigation to be ABSENT: each rule names
// the specific control the real fix added, and stays silent when it is present.
import { blankComments } from './_comment-strip.js';

const SRC_RE = /\.(?:py|js|jsx|ts|tsx|mjs|cjs)$/i;

/** An outbound HTTP call that can be told to follow redirects. */
const CLIENT_CALL_RE =
  /\b(?:requests|httpx|session|client|axios|got|fetch|urlopen|request)\b[\w.]{0,40}\s{0,4}\(([^;]{0,400})/gi;

/** Redirect-following turned on (explicitly, or by a library that defaults to it). */
const FOLLOWS_REDIRECTS_RE = /\b(?:follow_redirects\s{0,4}=\s{0,4}True|allow_redirects\s{0,4}=\s{0,4}True|maxRedirects\s{0,4}:\s{0,4}[1-9]|redirect\s{0,4}:\s{0,4}['"]follow['"])/;

/** Credential-bearing headers handed to that call. */
const CREDENTIAL_HEADER_RE = /\b(?:headers|auth|Authorization|Cookie|api_?key|bearer|token)\b/i;

/** The T4.4a mitigation: headers stripped or rescoped across the hop. */
const HEADER_STRIP_RE =
  /\b(?:_?redirect_headers|strip_?(?:auth|headers)|rebuild_auth|same_?origin|origin\s{0,4}[!=]==?|del\s+headers|headers\.pop|headers\.delete|drop_?headers)\b/i;

/** The T4.4b mitigation: the target is re-checked per hop, not once up front. */
const PER_HOP_CHECK_RE =
  /\b(?:on_?redirect|beforeRedirect|redirect_?hook|validate_?redirect|check_?redirect|per_?hop|for\s+hop\b)/i;

/** A one-time URL/host validation — the thing that gets bypassed. */
const URL_VALIDATION_RE =
  /\b(?:validate_?url|check_?url|is_?allowed|allow_?list|allowlist|deny_?list|is_?private|is_?internal|ssrf|_validate_url_for_fetch)\w{0,20}\s{0,4}\(/i;

/** T4.5: a resolution whose result is checked. */
const RESOLVE_RE = /\b(?:getaddrinfo|gethostbyname|resolve|\w*[dD]ns\w*\.lookup|socket\.getaddrinfo|realpath|os\.path\.realpath|resolve\(\))\b/i;

/** T4.5 mitigation: the checked result is PINNED and reused, not re-resolved. */
const PIN_RE = /\b(?:pin|pinned|resolved_?ip|cached_?ip|use_?resolved|connect_?to_?ip|sock\.connect\(\s*\(?\s*resolved)/i;

/**
 * T4.5's OTHER mitigation shape, found via GHSA-ch52-px8q-f22j: instead of
 * pinning the checked value, the fix installs a custom resolver/lookup hook so
 * the SAME resolution used to connect is the one that gets validated — a
 * connect-time revalidation gate rather than a cache. Window-scoped like PIN_RE
 * would miss this: the hook is typically a sibling function, not adjacent to
 * the original resolve-and-check call it supersedes. File-scoped is safe here
 * because assignment to `.lookup`/`.resolveLookup`/an http(s) agent's `lookup`
 * option is a specific code shape, not a word that appears in prose or pattern
 * tables the way "resolve" or "getaddrinfo" do.
 */
const CONNECT_TIME_REVALIDATION_RE = /\.\s{0,2}(?:lookup|resolveLookup)\s{0,4}=\s{0,4}(?:async\s{1,4})?\(/;

const _lineOf = (raw, i) => raw.slice(0, i).split('\n').length;
const _win = (raw, line, half = 14) => {
  const l = raw.split('\n');
  return l.slice(Math.max(0, line - 1 - half), Math.min(l.length, line - 1 + half)).join('\n');
};

function mk(file, line, sub, severity, cwe, vuln, description, remediation, checkedFor) {
  return {
    id: `redirect-toctou:${sub}:${file}:${line}`,
    file, line, vuln, severity, cwe,
    family: sub === 'toctou-resolve' ? 'toctou' : 'redirect-forwarding',
    parser: 'REDIRECT-TOCTOU',
    subfamily: sub,
    confidence: 0.5,
    description, remediation, checkedFor,
  };
}

export function scanRedirectToctou(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 500_000) return [];
  if (!SRC_RE.test(file)) return [];
  if (!/redirect|getaddrinfo|gethostbyname|realpath|resolve/i.test(raw)) return [];
  const code = blankComments(raw, /\.py$/i.test(file) ? 'py' : null);
  const out = [];
  const seen = new Set();
  const push = (f) => { const k = `${f.subfamily}:${f.line}`; if (!seen.has(k)) { seen.add(k); out.push(f); } };

  CLIENT_CALL_RE.lastIndex = 0;
  let m;
  while ((m = CLIENT_CALL_RE.exec(code))) {
    const argsText = m[1] || '';
    const line = _lineOf(code, m.index);
    const win = _win(raw, line);
    if (!FOLLOWS_REDIRECTS_RE.test(argsText) && !FOLLOWS_REDIRECTS_RE.test(win)) continue;

    // T4.4a — credentials handed to a redirect-following request, with no
    // evidence anywhere nearby that headers are dropped when the origin changes.
    if (CREDENTIAL_HEADER_RE.test(argsText) && !HEADER_STRIP_RE.test(win)) {
      push(mk(file, line, 'credential-across-redirect', 'medium', 'CWE-200',
        'Credential headers forwarded across an origin-changing redirect',
        'This request carries credential headers AND follows redirects, and nothing in the surrounding code drops '
        + 'those headers when the redirect changes origin. Most HTTP clients only strip Authorization and Cookie by '
        + 'default, so a custom header (X-Api-Key, X-Auth-Token) is replayed verbatim to whatever host the first '
        + 'server names — handing the caller\'s credentials to a third party that merely had to answer with a 302.',
        'Drop every credential header when the redirect target\'s origin differs from the original request\'s, or '
        + 'disable redirect-following and handle each hop explicitly.',
        'a header-stripping / same-origin check within 14 lines'));
    }

    // T4.4b — the URL was validated once, then followed wherever it leads.
    if (URL_VALIDATION_RE.test(win) && !PER_HOP_CHECK_RE.test(win)) {
      push(mk(file, line, 'unvalidated-redirect-hop', 'medium', 'CWE-918',
        'URL allow-list checked once, then redirects followed without re-validation',
        'The target URL is validated before the request, but redirects are followed and nothing re-validates the '
        + 'destination of each hop. An allowed host can answer with a 302 to an internal address, so the check '
        + 'protects only the first hop — the classic SSRF allow-list bypass.',
        'Re-run the same host validation on every redirect hop (a redirect hook / per-hop callback), or follow '
        + 'redirects manually so each Location can be checked before it is fetched.',
        'a per-hop redirect hook or re-validation within 14 lines'));
    }
  }

  // T4.5 — resolve, check the result, then let the consumer resolve again.
  //
  // LOCALITY IS REQUIRED. The first draft asked whether the file ANYWHERE
  // contained a resolve, a validation, and no pin — and immediately fired on
  // two of this project's own detector modules, whose rule tables mention
  // getaddrinfo/is_allowed as pattern DATA rather than performing either. A
  // real TOCTOU has the resolve and the check in the same handful of lines,
  // so the window is the unit, not the file.
  // The resolved value must be BOUND to a name and that same name checked —
  // window co-occurrence alone was still too loose (it fired on catalog.js and
  // two structural detectors, whose rule tables merely mention these APIs).
  const RESOLVE_BIND_RE = /\b(\w{1,60})\s{0,4}=\s{0,4}[^\n]{0,120}\b(?:getaddrinfo|gethostbyname|\w*[dD]ns\w*\.lookup|realpath)\b/g;
  let rmm;
  while ((rmm = RESOLVE_BIND_RE.exec(code))) {
    const bound = rmm[1];
    const line = _lineOf(code, rmm.index);
    const win = _win(raw, line, 10);
    // That exact name must be what the validation looks at.
    const checked = new RegExp(`${URL_VALIDATION_RE.source.replace(/^\\b/, '\\b')}[^)]{0,80}\\b${bound}\\b`, 'i');
    if (!checked.test(win)) continue;             // the resolved value is not what is checked
    if (PIN_RE.test(win)) continue;               // the checked value is reused — the fix
    if (CONNECT_TIME_REVALIDATION_RE.test(code)) continue; // a custom lookup hook revalidates at connect time — the other fix
    push(mk(file, line, 'toctou-resolve', 'medium', 'CWE-367',
      'Validated address is re-resolved before use (TOCTOU / DNS rebinding)',
      'A name is resolved and the result is validated, but the resolved value is not pinned — the connection (or '
      + 'file open) resolves the name a second time. Between the two resolutions the answer can change, so the '
      + 'address that was checked is not the address that is used. For DNS this is rebinding: the attacker answers '
      + 'once with a public IP to pass the check and once with an internal one to be connected to.',
      'Pin the validated result and use it directly (connect to the checked IP, open the checked realpath) instead '
      + 'of re-resolving the original name.',
      'evidence that the validated result is pinned and reused rather than re-resolved'));
    break;   // one finding per file is enough to act on
  }
  return out;
}

export const _internals = { FOLLOWS_REDIRECTS_RE, HEADER_STRIP_RE, PER_HOP_CHECK_RE, URL_VALIDATION_RE, PIN_RE, CONNECT_TIME_REVALIDATION_RE };
