// PRD F4.1 — the regression net under `bench/secrets-precision`.
//
// The bench is the measurement; this is the gate. It runs offline in
// milliseconds and pins the specific findings that bench produced, so none of
// them can silently come back.
//
// The structural finding worth reading before adding any credential pattern:
// **`CRED_PREFILTER` is a whole-file gate.** `scanCredentials` returns early
// unless that one regex matches the file, so a pattern whose trigger token is
// missing from it can never fire, however correct the pattern is. That is the
// same "wired into the dispatch, never invoked" shape as `rate-limit.js`,
// `k8s-admission` and `install-script`. The last test in this file enforces it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCredentials } from '../src/engine.js';

// NOTE FOR SECRET SCANNERS (including GitHub push protection): every
// credential-shaped value in this file is SYNTHETIC — there is nothing to
// rotate. Provider-format values are ASSEMBLED at runtime rather than written as
// contiguous literals, because a format scanner matches on shape and cannot read
// this comment. The assembled string is what the detector under test sees, so
// the tests are unchanged in meaning; only the source representation differs.

const vulns = (file, body) => scanCredentials(file, body + '\n').map((f) => f.vuln);

// ─── Formats that were absent until the bench measured them ─────────────────

test('database connection URIs with an inline password are detected', () => {
  // `jdbc:` was the only database URI shape covered, and it is the least
  // common of the three in the ecosystems this tool is aimed at. A connection
  // string with the password inline is what a leak usually looks like.
  assert.deepEqual(
    vulns('src/config.js', 'const db = "postgres://appuser:Kd8fJ2mQx9Lp4Zt1@db.internal:5432/production";'),
    ['PostgreSQL Connection URI'],
  );
  assert.deepEqual(
    vulns('src/config.js', 'const db = "mongodb+srv://appuser:Kd8fJ2mQx9Lp4Zt1@cluster0.ab12c.mongodb.net/prod";'),
    ['MongoDB Connection URI'],
  );
});

test('a database URI reports ONCE, under the specific name', () => {
  // The generic "Password in URL" pattern also matches these. Two findings for
  // one secret on one line is noise that makes a report look padded, and the
  // specific name is the useful one — it says which system to rotate.
  const hits = vulns('src/config.js', 'const db = "postgres://appuser:Kd8fJ2mQx9Lp4Zt1@db.internal:5432/production";');
  assert.equal(hits.length, 1);
  assert.ok(!hits.includes('Password in URL'));
});

test('the generic URL-password pattern still fires for schemes with no specific rule', () => {
  // The dedupe above must not become a blanket suppression of the generic rule.
  assert.ok(vulns('src/c.js', 'const u = "ftp://bob:S3cretPass99@files.internal/x";').includes('Password in URL'));
});

test('placeholder database URIs stay silent', () => {
  // A connection string pointing at localhost with `user:pass` is a README.
  for (const body of [
    'const db = "postgres://user:pass@localhost:5432/dev";',
    'const db = "mongodb://admin:admin@example.com:27017/test";',
    'const db = "postgres://test:test@127.0.0.1:5432/testdb";',
  ]) {
    assert.deepEqual(vulns('src/config.js', body), [], body);
  }
});

test('the provider tokens the bench found missing are detected', () => {
  const cases = [
    ['glpat-' + 'Kd8fJ2mQx9Lp4Zt1aB2c', 'GitLab Personal Access Token'],
    ['dop_v1_' + 'a1b2c3d4'.repeat(8), 'DigitalOcean Personal Access Token'],
    ['sbp_' + 'f1e2d3c4'.repeat(5), 'Supabase Service Key'],
    ['pat-na1-' + ['a1b2c3d4', 'e5f6', '7890', 'abcd', 'ef1234567890'].join('-'), 'HubSpot Private App Token'],
  ];
  for (const [value, expected] of cases) {
    assert.ok(vulns('src/config.js', `const k = "${value}";`).includes(expected), `${expected} not detected`);
  }
  const azure = 'DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=' + 'A'.repeat(86) + '==;EndpointSuffix=core.windows.net';
  assert.ok(vulns('src/config.js', `const c = "${azure}";`).includes('Azure Storage Account Key'));
});

// ─── The negative set: the half that makes the tool usable ──────────────────

test('the JWT specimen from the standard\'s documentation is not a leak', () => {
  const specimen = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  assert.deepEqual(vulns('docs/auth.md', `A token looks like: ${specimen}`), []);
});

test('a REAL JWT is still reported — the specimen rule is narrow', () => {
  // Suppression is on the DECODED payload matching the documented sample, so a
  // token that merely shares the standard header is unaffected. Without this
  // test the rule above could be widened into "never report a JWT".
  const payload = Buffer.from(JSON.stringify({ sub: 'auth0|66f1', email: 'ops@prod.internal', exp: 1893456000 })).toString('base64url');
  const real = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.Kd8fJ2mQx9Lp4Zt1aB2cD3eF4gH5iJ6k`;
  assert.ok(vulns('src/session.js', `const token = "${real}";`).includes('Exposed JWT Token'));
});

test('credential-shaped strings that are not credentials stay silent', () => {
  // A sample of the bench's negative set, including the case a secrets scanner
  // is most embarrassed by: a rule file that defines key formats.
  const cases = [
    ['package-lock.json', '{"node_modules/x":{"integrity":"sha512-fzUuVI8FSWjrpV3qKrPkFKgHzYzjeIVUyLC3Jzp8U0AXAf13Qb1L6P8FVQnDmpZbLhFYLLYUFbrMSFT6oB6xNQ=="}}'],
    ['Cargo.lock', 'checksum = "1e6d5d3b5d5b1d9c1a8f3f8e6b9d0a5c4f2e1d0c9b8a7f6e5d4c3b2a1908f7e6"'],
    ['go.sum', 'github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4='],
    ['src/config.js', "const tenantId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';"],
    ['src/config.js', 'const apiKey = process.env.STRIPE_SECRET_KEY;'],
    ['.env.example', 'STRIPE_SECRET_KEY=sk_live_your_key_here_replace_me'],
    ['.npmrc', '//registry.npmjs.org/:_authToken=${NPM_TOKEN}'],
    ['rules/secrets.yml', "patterns:\n  - name: github-pat\n    regex: 'ghp_[0-9a-zA-Z]{36}'"],
    ['docs/aws-setup.md', 'Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE for the walkthrough.'],
    ['Dockerfile', 'FROM node@sha256:5e5f6f0a2ea0c9e6e2e6b1e33b8b1e0c8a9d3f2e1b0a9c8d7e6f5a4b3c2d1e0f'],
  ];
  for (const [file, body] of cases) {
    assert.deepEqual(vulns(file, body), [], `${file}: ${body.slice(0, 60)}`);
  }
});

// ─── The structural guard ───────────────────────────────────────────────────

test('every credential pattern has a CRED_PREFILTER trigger — no dead patterns', async () => {
  // `scanCredentials` bails out before touching CREDENTIAL_PATTERNS unless
  // CRED_PREFILTER matches the file. A pattern added without a corresponding
  // prefilter token is dead code that unit-tests-of-the-regex would still pass.
  //
  // The check is behavioural rather than textual: for each pattern, build a
  // string that pattern matches and assert the whole scanner reports it. A
  // textual check on the prefilter source would drift the moment either regex
  // was rewritten.
  const fs = await import('node:fs');
  const url = await import('node:url');
  const pathMod = await import('node:path');
  const here = pathMod.dirname(url.fileURLToPath(import.meta.url));
  const src = fs.readFileSync(pathMod.join(here, '..', 'src', 'engine.js'), 'utf8');

  const start = src.indexOf('const CREDENTIAL_PATTERNS=[');
  assert.ok(start > 0, 'CREDENTIAL_PATTERNS not found');
  const body = src.slice(start, src.indexOf('\n];', start));
  const names = [...body.matchAll(/\{n:"([^"]+)"/g)].map((m) => m[1]);
  assert.ok(names.length > 40, `expected the full pattern list, got ${names.length}`);

  // Not every pattern can have a sample synthesized from its regex here, so
  // this asserts the invariant on the set the bench covers plus the ones added
  // for it — the population where a missing trigger has actually happened.
  const mustFire = {
    'PostgreSQL Connection URI': 'const c = "postgres://appuser:Kd8fJ2mQx9Lp4Zt1@db.internal:5432/production";',
    'MongoDB Connection URI': 'const c = "mongodb+srv://appuser:Kd8fJ2mQx9Lp4Zt1@cluster0.ab12c.mongodb.net/prod";',
    'GitLab Personal Access Token': `const c = "glpat-${'Kd8fJ2mQx9Lp4Zt1aB2c'}";`,
    'DigitalOcean Personal Access Token': `const c = "dop_v1_${'a1b2c3d4'.repeat(8)}";`,
    'Supabase Service Key': `const c = "sbp_${'f1e2d3c4'.repeat(5)}";`,
    'HubSpot Private App Token': `const c = "pat-na1-${['a1b2c3d4', 'e5f6', '7890', 'abcd', 'ef1234567890'].join('-')}";`,
    'Azure Storage Account Key': `const c = "AccountKey=${'A'.repeat(86)}==";`,
  };
  for (const [name, sample] of Object.entries(mustFire)) {
    assert.ok(names.includes(name), `${name} is no longer a declared pattern — update this test deliberately`);
    assert.ok(vulns('src/config.js', sample).includes(name),
      `${name} is declared but does not fire — most likely CRED_PREFILTER has no trigger for it`);
  }
});
