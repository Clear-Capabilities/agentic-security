// Social / OAuth sign-in that adopts a local account by the provider's email: CWE-287.
//
// THE SHAPE. The sign-in callback receives an identity from an external provider and, when no account is linked to that provider id,
// looks up a LOCAL account by the email the provider reported and signs the caller in as it:
//
//     $user = User::findByOAuthId($provider, $remote->getId())
//          ?: User::findByEmail($remote->getEmail());              // any provider that lets users type an email takes over the account
//
// An email from a provider is only an identity claim if the provider verified it. Many providers (self-hosted identity servers,
// generic OpenID Connect, providers that allow changing the email without re-verification) do not, so an attacker registers the
// victim's address there and signs in as the victim. The fix requires a verified-email claim (`email_verified`), or trusts the email
// only for an allow-list of providers known to verify it, or links accounts only after the user proves ownership while signed in.
//
// WHAT MUST BE TRUE TO REPORT.
//   1. The file is sign-in code for an external provider (it names OAuth, OpenID, Socialite, OmniAuth, Passport, SSO or a provider).
//   2. An account lookup by email (`findByEmail`, `find_by(email:)`, `objects.get(email=)`, `findOne({ email })`, `getUserByEmail`...)
//      whose argument is an email read from a provider-identity object (`$socialUser->getEmail()`, `profile.emails[0].value`,
//      `userinfo['email']`, `auth.info.email`), directly or through a local assigned from it.
//   3. The lookup's result becomes the account: assigned or returned, not negated (a `! findByEmail(...)` refusal is the fix's shape).
//   4. Nothing near it mentions a verified-email claim or a trusted-provider decision.
// Reported at the lookup.

const FILE_RE = /\.(?:php|py|js|jsx|ts|tsx|mjs|cjs|rb)$/i;
const SIGNIN_FILE = /oauth|socialite|omniauth|openid|oidc|passport|\bsso\b|social[_-]?(?:auth|login|user)|identity[_ -]?provider|\bprovider\b/i;
const isTest = (f) => /(?:^|\/)(?:tests?|specs?|__tests__)\//i.test(f) || /\.(?:test|spec)\.\w+$/.test(f) || /(?:Test|_test|_spec)\.\w+$/.test(f) || /(?:^|\/)test_[^/]*\.py$/.test(f);

// A provider-identity object: the thing the external provider handed back.
const IDENTITY_OBJ = '(?:\\$?(?:social\\w*|oauth\\w*|provider_?[Uu]ser\\w*|providerUser\\w*|remote_?[Uu]ser\\w*|remoteUser\\w*|external_?[Uu]ser\\w*|externalUser\\w*|sso_?\\w*|idp\\w*|user_?info|userInfo|userinfo|id_?info|idInfo|claims|id_?token_?claims|profile|auth\\.info|auth\\[[\'"]info[\'"]\\]|omniauth\\w*|socialite\\w*))';
const PROVIDER_EMAIL = new RegExp(
  `${IDENTITY_OBJ}\\s*(?:->\\s*getEmail\\s*\\(\\s*\\)|->\\s*email\\b|\\.\\s*emails\\s*\\[\\s*0\\s*\\]\\s*\\.\\s*value|\\.\\s*email\\b(?!_verified|Verified)|\\[\\s*['"]email['"]\\s*\\]|\\.\\s*get\\s*\\(\\s*['"]email['"])`, 'i');
const LOOKUP = /\b(?:findByEmail|find_by_email|findOneByEmail|getUserByEmail|get_user_by_email|getByEmail|get_by_email|user_by_email|userByEmail|loadUserByEmail|findUserByEmail|find_user_by_email)\s*\(|\bfind_by\s*\(?\s*email:|\bwhere\s*\(\s*['"]email['"]\s*,|\b(?:objects\s*\.\s*get|objects\s*\.\s*filter|filter_by|get_or_none)\s*\(\s*email\s*=|\b(?:findOne|findFirst|findUnique)\s*\(\s*\{\s*(?:where\s*:\s*\{\s*)?email\s*:/;
const VERIFIED = /email_?verified|emailVerified|verified_?email|isEmailVerified|is_email_verified|hasVerifiedEmail|email_confirmed|emailConfirmed|trusts?Emails?|trusted_?providers?|trustedProviders?|trust_email/i;

export function scanOAuthEmailAccountLink(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || code.length > 1_000_000 || isTest(file)) return [];
  if (!SIGNIN_FILE.test(code) || !LOOKUP.test(code)) return [];
  const lines = code.split('\n');
  const out = [];
  // Locals holding a provider email: `$email = $socialUser->getEmail();`, `email = userinfo["email"]`.
  const emailLocals = new Set();
  for (const l of lines) {
    const m = l.match(/^\s*(?:const\s+|let\s+|var\s+)?(\$?[A-Za-z_]\w{0,40})\s*=(?!=)\s*(.*)$/);
    // The right-hand side must BE the email (optionally normalised: `strtolower(...)`, `.lower()`), not a call that merely reads it.
    const pm = m && m[2].match(PROVIDER_EMAIL);
    const lead = pm ? m[2].slice(0, pm.index).replace(/\s/g, '') : '';
    if (pm && /^[\w.(]{0,90}$/.test(lead) && (lead.match(/\(/g) || []).length <= 2 && !LOOKUP.test(m[2])) emailLocals.add(m[1]);
  }
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    const lk = l.match(LOOKUP);
    if (!lk) continue;
    // The lookup's argument: the rest of the line plus the next two, enough for a wrapped call.
    const tail = (l.slice(lk.index) + ' ' + (lines[i + 1] || '') + ' ' + (lines[i + 2] || '')).slice(0, 400);
    const fromProvider = PROVIDER_EMAIL.test(tail) ||
      [...emailLocals].some((v) => new RegExp(`(?<![\\w$])${v.replace(/\$/g, '\\$')}(?!\\w)`).test(tail.slice(0, 160)));
    if (!fromProvider) continue;
    // Adopted as the account: assigned or returned, never negated.
    const head = l.slice(0, lk.index);
    // Peel the receiver chain (`User::`, `$this->repo->`, `models.User.`) one segment at a time, then look for a negation.
    let bare = head.trimEnd();
    for (let k = 0; k < 8; k++) {
      const q = bare.match(/[\w$\\]{1,80}\s{0,4}(?:::|->|\.)\s{0,4}$/);
      if (!q) break;
      bare = bare.slice(0, q.index);
    }
    if (/(?:!|\bnot\s|\bunless\s)[\s(]{0,8}$/.test(bare)) continue;
    if (!/(?:\$?\w+\s*=(?![=>])|\breturn\b|\|\||\?:|\bor\b|\?\?)/.test(head + ' ' + (lines[i - 1] || '').slice(-60))) continue;
    const lo = Math.max(0, i - 25), hi = Math.min(lines.length, i + 15);
    if (VERIFIED.test(lines.slice(lo, hi).join('\n'))) continue;
    out.push({
      id: `oauth-email-account-link:${file}:${i + 1}`,
      file, line: i + 1,
      vuln: 'External sign-in adopts a local account by the provider-reported email without a verified-email check',
      severity: 'high',
      cwe: 'CWE-287',
      family: 'auth',
      stride: 'Spoofing',
      description: 'This sign-in path looks up a local account by the email address the external identity provider returned and treats the caller as that account. An email from a provider proves nothing unless the provider verified it: an attacker who registers the victim\'s address with a provider that does not verify (or lets the address be changed) signs in as the victim.',
      remediation: 'Link by the provider\'s stable subject id only. Adopt an existing account by email only when the provider asserts a verified email (`email_verified`), only for an allow-list of providers known to verify it, or after the user proves ownership of the account while signed in.',
      snippet: l.trim().slice(0, 200),
      parser: 'AUTH-OAUTH-LINK',
      confidence: 0.55,
    });
  }
  return out;
}
