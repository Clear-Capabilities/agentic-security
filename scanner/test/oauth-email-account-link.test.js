// External sign-in that adopts a local account by the provider email (CWE-287), src/sast/oauth-email-account-link.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanOAuthEmailAccountLink as scan } from '../src/sast/oauth-email-account-link.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'oauth-email-account-link');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'SocialLogin.php'), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

test('a lookup by the provider-reported email, adopted as the account, is reported at the lookup', () => {
  const code = read('vulnerable');
  const out = scan('SocialLogin.php', code);
  assert.deepEqual(out.map((f) => f.line), [lineOf(code, 'findByEmail')]);
  assert.equal(out[0].cwe, 'CWE-287');
});

test('the fixed version, which requires a verified-email claim, is silent', () => {
  assert.deepEqual(scan('SocialLogin.php', read('clean')), []);
});

test('a negated lookup (refusing to create a duplicate) and an email from the request are not this shape', () => {
  const negated = 'class OAuthController {\n  function cb($providerUser) {\n    if (! User::findByEmail($providerUser->getEmail())) { $u = create($providerUser); }\n  }\n}\n';
  assert.deepEqual(scan('OAuthController.php', negated), []);
  const fromRequest = read('vulnerable').replace('$socialUser->getEmail()', '$request->email');
  assert.deepEqual(scan('SocialLogin.php', fromRequest), []);
});

test('the same shape in Python and JavaScript sign-in code is reported', () => {
  const py = 'def oauth_callback(token):\n    userinfo = token["userinfo"]\n    user = User.objects.get(email=userinfo["email"])\n    login(user)\n';
  assert.equal(scan('auth/views.py', py).length, 1);
  const js = 'passport.use(new Strategy(opts, async (at, rt, profile, done) => {\n  const user = await User.findOne({ email: profile.emails[0].value });\n  done(null, user);\n}));\n';
  assert.equal(scan('auth/passport.js', js).length, 1);
  assert.deepEqual(scan('auth/passport.js', js.replace('const user', 'if (!profile._json.email_verified) return done(null, false);\n  const user')), []);
});
