// A handler that answers "does an account exist for this email?": CWE-200 (account enumeration, the CWE-204 observable-response kind).
//
// THE SHAPE. A request handler looks up an account by an email taken from the request and returns whether it was found:
//
//     public function __invoke(Request $request) {
//         $user = User::findByEmail($request->email);
//         return ['exists' => (bool) $user];
//     }
//
// Whoever can reach the handler learns which addresses have accounts, which feeds credential stuffing, targeted phishing and password
// reset abuse. Such endpoints are sometimes wanted (an administrator's "invite user" form), and then they must be restricted to the
// callers allowed to know: the fix adds the authorization check.
//
// WHAT MUST BE TRUE TO REPORT.
//   1. An account lookup keyed on `email` whose value is read from the request object of the framework (Laravel's request property
//      or input accessor, Express's body, query or params, Django or Flask request data, Rails params): see REQ_EMAIL.
//   2. Within the next few lines the handler returns or responds with a key named `exists`, `available`, `taken`, `registered`,
//      `in_use`/`inUse` or `found`, whose value is the lookup's result (the variable it was assigned to, or the lookup itself).
//   3. No authorization call (`authorize`, `can`, `permission`, `isGranted`, `@login_required`/`permission_required` decorators...) in
//      the lines of the handler before it.
// The finding is reported at the lookup.

const FILE_RE = /\.(?:php|py|js|jsx|ts|tsx|mjs|cjs|rb)$/i;
const isTest = (f) => /(?:^|\/)(?:tests?|specs?|__tests__)\//i.test(f) || /\.(?:test|spec)\.\w+$/.test(f) || /(?:Test|_test|_spec)\.\w+$/.test(f) || /(?:^|\/)test_[^/]*\.py$/.test(f);

const REQ_EMAIL = /(?:\$request\s*->\s*(?:email\b|(?:input|get|query|post)\s*\(\s*['"]email['"])|\brequest\s*\(\s*['"]email['"]|\breq\s*\.\s*(?:body|query|params)\s*(?:\.\s*email\b|\[\s*['"]email['"]\s*\])|\brequest\s*\.\s*(?:data|POST|GET|args|form|json|query_params)\s*(?:\[\s*['"]email['"]\s*\]|\.\s*get\s*\(\s*['"]email['"])|\bparams\s*\[\s*:email\s*\]|\bctx\s*\.\s*request\s*\.\s*body\s*\.\s*email\b|\$_(?:GET|POST|REQUEST)\s*\[\s*['"]email['"]\s*\])/;
const LOOKUP = /\b(?:findByEmail|find_by_email|getUserByEmail|get_user_by_email|getByEmail|get_by_email|findOneByEmail|findUserByEmail)\s*\(|\bwhere\s*\(\s*['"]email['"]\s*,|\bfind_by\s*\(?\s*email:|\bexists\?\s*\(\s*email:|\b(?:objects\s*\.\s*(?:get|filter)|filter_by|get_or_none)\s*\(\s*email\s*=|\b(?:findOne|findFirst|findUnique|exists|count)\s*\(\s*\{\s*(?:where\s*:\s*\{\s*)?email\s*:/;
const ANSWER_KEY = /(?:['"](?:exists|available|taken|registered|in_use|inUse|found|isRegistered|is_registered)['"]\s*(?:=>|:)|\b(?:exists|available|taken|registered|inUse|found)\s*:)/;
const AUTHZ = /\b(?:authori[sz]e\w*|can|cannot|Gate\s*::\s*\w+|isGranted|denyAccessUnlessGranted|has_?[Pp]ermission\w*|permission_required|login_required|user_passes_test|staff_member_required|requireAuth\w*|require_?admin\w*|ensureAdmin\w*|abort_unless|authenticate\w*)\s*\(|@(?:login_required|permission_required|staff_member_required)\b|before_action\s+:authenticate/;

export function scanAccountExistenceOracle(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || code.length > 1_000_000 || isTest(file)) return [];
  if (!/email/.test(code) || !ANSWER_KEY.test(code)) return [];
  const lines = code.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    const lk = l.match(LOOKUP);
    if (!lk || !REQ_EMAIL.test(l.slice(lk.index))) continue;
    const assigned = (l.slice(0, lk.index).match(/(\$?[A-Za-z_]\w{0,40})\s*=(?![=>])[^=]*$/) || [])[1];
    let answer = -1;
    for (let k = i; k < Math.min(lines.length, i + 6); k++) {
      const t = lines[k];
      const key = t.match(ANSWER_KEY);
      if (!key) continue;
      const after = t.slice(key.index);
      const usesResult = k === i || (assigned && new RegExp(`(?<![\\w$])${assigned.replace(/\$/g, '\\$')}(?!\\w)`).test(after));
      if (usesResult) { answer = k; break; }
    }
    if (answer < 0) continue;
    // The handler's lines before the lookup: from the nearest function header above.
    let start = i;
    while (start > 0 && i - start < 40 && !/\b(?:function|def)\s|=>\s*\{|\)\s*\{\s*$/.test(lines[start])) start--;
    const pre = lines.slice(Math.max(0, start - 4), i + 1).join('\n');
    if (AUTHZ.test(pre)) continue;
    out.push({
      id: `account-existence-oracle:${file}:${i + 1}`,
      file, line: i + 1,
      vuln: 'Handler reveals whether an account exists for a request-supplied email',
      severity: 'medium',
      cwe: 'CWE-200',
      family: 'information-disclosure',
      stride: 'Information Disclosure',
      description: `The handler looks up an account by an email read from the request and answers with whether it exists (line ${answer + 1}). Anyone who can call it learns which addresses are registered (account enumeration, the CWE-204 observable-response kind), which feeds credential stuffing, phishing and password-reset abuse. No authorization check precedes it in the handler.`,
      remediation: 'Restrict the endpoint to callers who are allowed to know (an authorization check before the lookup), or answer the same way whether or not the account exists.',
      snippet: l.trim().slice(0, 200),
      parser: 'ACCOUNT-ORACLE',
      confidence: 0.5,
    });
  }
  return out;
}
