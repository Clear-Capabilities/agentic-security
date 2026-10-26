import { HASKELL_CASES } from './cases-haskell.mjs';

// Cases for the metamorphic + adversarial mutation gate (bench/mutation/runner.mjs).
// Moved out of the runner so the cases can be inspected and tested without running a scan.

// ── Case shape ───────────────────────────────────────────────────────────────
// Every case declares which DIMENSION of the verdict it is measuring, because
// the two bug classes this harness has had to catch are different kinds of
// wrong:
//
//   dimension: 'sanitization'  (default) — the finding must FIRE in every case
//              and the question is whether the engine calls it `sanitized`.
//              `expectSanitized` is the answer. This is the original family
//              (family-aware sanitizer gating); its CWE is XSS.
//
//   dimension: 'detection'     — the question is whether the finding fires AT
//              ALL. `expectDetected` is the answer. Needed for the receiver-
//              type gate (PRD R6), which can only ever be wrong by suppressing
//              or by failing to suppress — there is no sanitizer in the flow to
//              have an opinion about.
//
// `cwe` selects which findings the case looks at (default: XSS).
export const DEFAULT_CWE = /CWE-79/;

// ── The base program. Tainted input, one sanitizer, one XSS sink. ────────────
// Each case rewrites it; `expectSanitized` is what the engine must conclude.
export const CASES = [
  {
    id: 'baseline',
    class: 'baseline',
    expectSanitized: true,
    why: 'xss sanitizer guarding an xss sink',
    code: `app.get('/i', (req, res) => {
  const name = escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'metamorphic-rename',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'renaming the variable changes nothing about the flow',
    code: `app.get('/i', (req, res) => {
  const cleanedUserValue = escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', cleanedUserValue);
});`,
  },
  {
    id: 'metamorphic-indirection',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'an extra clean copy step does not unsanitize the value',
    code: `app.get('/i', (req, res) => {
  const first = escapeHtml(req.query.name);
  const second = first;
  el.insertAdjacentHTML('beforeend', second);
});`,
  },
  {
    id: 'metamorphic-inline',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'applying the sanitizer inline at the sink is the same program',
    code: `app.get('/i', (req, res) => {
  el.insertAdjacentHTML('beforeend', escapeHtml(req.query.name));
});`,
  },
  {
    id: 'adversarial-sanitizer-removed',
    class: 'adversarial',
    expectSanitized: false,
    why: 'no sanitizer at all — the flow is genuinely unsanitized',
    code: `app.get('/i', (req, res) => {
  const name = req.query.name;
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'adversarial-wrong-family',
    class: 'adversarial',
    expectSanitized: false,
    why: 'shellEscape neutralizes command injection, not XSS',
    code: `app.get('/i', (req, res) => {
  const name = shellEscape(req.query.name);
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'adversarial-sanitizer-not-on-path',
    class: 'adversarial',
    expectSanitized: false,
    why: 'the sanitizer is called but its result is discarded — the sink gets raw input',
    code: `app.get('/i', (req, res) => {
  escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', req.query.name);
});`,
  },

  // ── PRD R6: the CHA-inferred receiver-type gate on catalog sink matching ───
  // This gate decides whether a bare `.query()` is a SQL sink by consulting the
  // receiver's resolved class. It shipped three times with the same defect: a
  // NAME or SHAPE guess ("the field is called `dbConn`, so its class must be
  // `DbConn`"; "the chain root is `svc`, so ask about `svc`") being trusted as
  // a confident type resolution, which then SUPPRESSED real SQL injections
  // whose receiver name happened to fall outside a fixed vocabulary. A corpus
  // fixture cannot catch that class of bug — the fixtures were themselves
  // named to match the vocabulary. A metamorphic rename can, and does: every
  // case below FAILS on the pre-fix engine.
  {
    id: 'r6-baseline-local',
    class: 'baseline',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'tainted input reaching .query() on a local DB object is SQL injection',
    code: `class Db {
  query(sql) { return sql; }
}
app.get('/s', (req, res) => {
  const d = new Db();
  d.query(req.query.q);
});`,
  },
  {
    id: 'metamorphic-receiver-class-rename',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'renaming `class Db` to `class DatabaseConnection` is the same program — a receiver-type allow-list that only matches the short name is keyed on spelling, not on meaning',
    code: `class DatabaseConnection {
  query(sql) { return sql; }
}
app.get('/s', (req, res) => {
  const d = new DatabaseConnection();
  d.query(req.query.q);
});`,
  },
  {
    id: 'r6-baseline-field',
    class: 'baseline',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'the same SQL injection reached through a `this.<field>` receiver',
    code: `class Repo {
  constructor() { this.db = makeConn(); }
  find(req) { return this.db.query(req.query.q); }
}
app.get('/s', (req, res) => { new Repo().find(req); });`,
  },
  {
    id: 'metamorphic-receiver-field-rename',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'renaming the field `this.db` to `this.dbConn` is the same program — a gate that guesses the receiver type from the field name loses the finding on any name outside its vocabulary',
    code: `class Repo {
  constructor() { this.dbConn = makeConn(); }
  find(req) { return this.dbConn.query(req.query.q); }
}
app.get('/s', (req, res) => { new Repo().find(req); });`,
  },
  {
    id: 'adversarial-non-db-receiver',
    class: 'adversarial',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: false,
    why: 'a `.query()` on a confidently-typed cache is not a SQL sink — this is the false positive the receiver-type gate exists to remove, and it is what stops "delete the gate" from passing the two metamorphic cases above',
    code: `class Cache {
  query(key) { return key; }
}
app.get('/s', (req, res) => {
  const c = new Cache();
  c.query(req.query.q);
});`,
  },
  // ── Go concurrency guard (PRD F12.5) ──────────────────────────────────────
  //
  // Encodes the defect fixed in a5ecb3b: the lock guard matched a BARE receiver
  // (`defer mu.Unlock()`) but not a QUALIFIED one (`defer s.mu.Unlock()`), which
  // is how a mutex held as a struct field is always written. 62% of this
  // detector's findings on real Go were false positives against correct code.
  //
  // These belong in the mutation gate rather than only in a unit test because
  // the failure was a NEAR-MISS discrimination failure — exactly what this gate
  // scores. A rule that starts flagging correct code again fails here even if
  // its unit tests are edited to match the new behaviour.
  {
    id: 'go-concurrency-bare-defer',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'svc.go',
    parser: /^CONCURRENCY$/,
    cwe: /CWE-667/,
    expectDetected: false,
    why: 'a bare `defer mu.Unlock()` releases on every path — no finding',
    code: `func Get(k string) string {
	mu.Lock()
	defer mu.Unlock()
	return d[k]
}`,
  },
  {
    id: 'go-concurrency-qualified-defer',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'svc.go',
    parser: /^CONCURRENCY$/,
    cwe: /CWE-667/,
    expectDetected: false,
    why: 'moving the mutex onto a struct field is the same program — still guarded',
    code: `func (s *Store) Get(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[k]
}`,
  },
  {
    id: 'go-concurrency-adversarial-other-lock',
    class: 'adversarial',
    dimension: 'detection',
    file: 'svc.go',
    parser: /^CONCURRENCY$/,
    cwe: /CWE-667/,
    expectDetected: true,
    why: 'the defer releases a DIFFERENT lock, so this one can leak — verdict must flip',
    code: `func (s *Store) Move(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.other.Lock()
	if k == "" {
		return errEmpty
	}
	s.other.Unlock()
	return nil
}`,
  },

  // ── PRD F12.5 — the families 0.141.0 added ────────────────────────────────
  //
  // Every detector family shipped in that release owed a metamorphic pair and
  // an adversarial near-miss, and none had one: the gate stood at 12 cases
  // while five new families landed. A rule that fires on both variants of a
  // control is not detecting the control, it is detecting the resource, and
  // that failure is invisible to any recall-only measurement.
  //
  // These are `detection`-dimension by construction. There is no sanitizer in
  // an infrastructure template to have an opinion about — the question is only
  // whether the misconfiguration is recognised and its hardened twin is not.

  // CloudFormation — unrestricted ingress.
  {
    id: 'cfn-baseline-open-admin-port',
    class: 'baseline',
    dimension: 'detection',
    file: 'infra/stack.yaml',
    parser: /^IAC$/,
    cwe: /CWE-284/,
    expectDetected: true,
    why: 'SSH open to 0.0.0.0/0 is the control',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
`,
  },
  {
    id: 'cfn-metamorphic-property-order',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'infra/stack.yaml',
    parser: /^IAC$/,
    cwe: /CWE-284/,
    expectDetected: true,
    why: 'YAML mappings are unordered — reordering the ingress keys is the same template',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          ToPort: 22
          FromPort: 22
          IpProtocol: tcp
`,
  },
  {
    id: 'cfn-metamorphic-quoted-scalars',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'infra/stack.yaml',
    parser: /^IAC$/,
    cwe: /CWE-284/,
    expectDetected: true,
    why: 'quoting a YAML scalar does not change its value',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: "tcp"
          FromPort: "22"
          ToPort: "22"
          CidrIp: "0.0.0.0/0"
`,
  },
  {
    id: 'cfn-adversarial-public-web-port',
    class: 'adversarial',
    dimension: 'detection',
    file: 'infra/stack.yaml',
    parser: /^IAC$/,
    cwe: /CWE-284/,
    expectDetected: false,
    why: '443 open to the world is a public web listener, not a finding — the verdict must flip on the PORT alone',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
`,
  },
  {
    id: 'cfn-adversarial-restricted-cidr',
    class: 'adversarial',
    dimension: 'detection',
    file: 'infra/stack.yaml',
    parser: /^IAC$/,
    cwe: /CWE-284/,
    expectDetected: false,
    why: 'the same port scoped to a private range is the hardened form',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 10.0.0.0/8
`,
  },

  // CloudFormation — public object storage.
  {
    id: 'cfn-baseline-public-bucket',
    class: 'baseline',
    dimension: 'detection',
    file: 'infra/storage.yaml',
    parser: /^IAC$/,
    cwe: /CWE-732/,
    expectDetected: true,
    why: 'a PublicRead canned ACL is the control',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Assets:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
`,
  },
  {
    id: 'cfn-adversarial-private-bucket',
    class: 'adversarial',
    dimension: 'detection',
    file: 'infra/storage.yaml',
    parser: /^IAC$/,
    cwe: /CWE-732/,
    expectDetected: false,
    why: 'one word changes the meaning entirely',
    code: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Assets:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
`,
  },

  // Bicep.
  {
    id: 'bicep-baseline-public-blob',
    class: 'baseline',
    dimension: 'detection',
    file: 'infra/main.bicep',
    parser: /^IAC$/,
    cwe: /CWE-732/,
    expectDetected: true,
    why: 'anonymous public blob access is the control',
    code: `resource assets 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'companyassets'
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: true
  }
}
`,
  },
  {
    id: 'bicep-metamorphic-property-order',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'infra/main.bicep',
    parser: /^IAC$/,
    cwe: /CWE-732/,
    expectDetected: true,
    why: 'object property order carries no meaning in Bicep',
    code: `resource assets 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  properties: {
    allowBlobPublicAccess: true
    supportsHttpsTrafficOnly: true
  }
  location: 'westeurope'
  name: 'companyassets'
}
`,
  },
  {
    id: 'bicep-adversarial-private-blob',
    class: 'adversarial',
    dimension: 'detection',
    file: 'infra/main.bicep',
    parser: /^IAC$/,
    cwe: /CWE-732/,
    expectDetected: false,
    why: 'false is the hardened form and must not report',
    code: `resource assets 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'companyassets'
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: false
  }
}
`,
  },

  // Helm chart values.
  {
    id: 'helm-baseline-privileged-default',
    class: 'baseline',
    dimension: 'detection',
    file: 'charts/app/values.yaml',
    parser: /^IAC$/,
    cwe: /CWE-250/,
    expectDetected: true,
    why: 'a chart that defaults to privileged runs privileged on every install that does not override it',
    code: `image:
  repository: registry.example.com/app
  tag: "1.0.0"
securityContext:
  privileged: true
`,
  },
  {
    id: 'helm-metamorphic-key-order',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'charts/app/values.yaml',
    parser: /^IAC$/,
    cwe: /CWE-250/,
    expectDetected: true,
    why: 'moving the block above the image stanza changes nothing',
    code: `securityContext:
  privileged: true
image:
  repository: registry.example.com/app
  tag: "1.0.0"
`,
  },
  {
    id: 'helm-adversarial-not-privileged',
    class: 'adversarial',
    dimension: 'detection',
    file: 'charts/app/values.yaml',
    parser: /^IAC$/,
    cwe: /CWE-250/,
    expectDetected: false,
    why: 'the hardened default must be silent',
    code: `image:
  repository: registry.example.com/app
  tag: "1.0.0"
securityContext:
  privileged: false
  runAsNonRoot: true
`,
  },
  {
    id: 'helm-adversarial-template-not-values',
    class: 'adversarial',
    dimension: 'detection',
    file: 'charts/app/templates/deployment.yaml',
    parser: /^IAC$/,
    cwe: /CWE-250/,
    expectDetected: false,
    why: 'templates/ is Go template source, not YAML — reading text inside {{ }} would report the template rather than the configuration. A DELIBERATE scope limit, pinned so it cannot drift into coverage by accident.',
    code: `securityContext:
  privileged: true
`,
  },

  // Dockerfile base-image pinning.
  {
    id: 'docker-baseline-floating-tag',
    class: 'baseline',
    dimension: 'detection',
    file: 'Dockerfile',
    parser: /^IAC$/,
    cwe: /CWE-1104/,
    expectDetected: true,
    why: 'a mutable tag makes the build non-reproducible',
    code: `FROM ubuntu:latest
USER app
CMD ["/bin/sh"]
`,
  },
  {
    id: 'docker-metamorphic-implicit-latest',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'Dockerfile',
    parser: /^IAC$/,
    cwe: /CWE-1104/,
    expectDetected: true,
    why: 'omitting the tag IS :latest — the same program, written differently',
    code: `FROM ubuntu
USER app
CMD ["/bin/sh"]
`,
  },
  {
    id: 'docker-adversarial-digest-pinned',
    class: 'adversarial',
    dimension: 'detection',
    file: 'Dockerfile',
    parser: /^IAC$/,
    cwe: /CWE-1104/,
    expectDetected: false,
    why: 'a digest is the MOST pinned form there is; reporting it inverts the advice. This case is the regression pin for a real false positive on the hardened configuration.',
    code: `FROM ubuntu@sha256:5e5f6f0a2ea0c9e6e2e6b1e33b8b1e0c8a9d3f2e1b0a9c8d7e6f5a4b3c2d1e0f
USER app
CMD ["/bin/sh"]
`,
  },
  {
    id: 'docker-adversarial-build-stage-ref',
    class: 'adversarial',
    dimension: 'detection',
    file: 'Dockerfile',
    parser: /^IAC$/,
    cwe: /CWE-1104/,
    expectDetected: false,
    why: 'FROM builder references a named stage in this same file, not a registry pull',
    code: `FROM node:20-alpine AS builder
RUN echo build
FROM builder
USER app
`,
  },

  // Ruby File.join path traversal.
  {
    id: 'ruby-baseline-pathjoin',
    class: 'baseline',
    dimension: 'detection',
    file: 'lib/cache.rb',
    parser: /^RUBY$/,
    cwe: /CWE-22/,
    expectDetected: true,
    why: 'a request-derived component joined to a root and opened, with no traversal check',
    code: `def serve(request)
  cache_path = File.join(document_root, request.path)
  File.read(cache_path)
end
`,
  },
  {
    id: 'ruby-metamorphic-rename',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'lib/cache.rb',
    parser: /^RUBY$/,
    cwe: /CWE-22/,
    expectDetected: true,
    why: 'renaming the local changes nothing about the flow',
    code: `def serve(request)
  resolved_target = File.join(document_root, request.path)
  File.read(resolved_target)
end
`,
  },
  {
    id: 'ruby-metamorphic-predicate-sink',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'lib/cache.rb',
    parser: /^RUBY$/,
    cwe: /CWE-22/,
    expectDetected: true,
    why: 'File.exist? is as much a filesystem operation as File.read — this is the shape a trailing \\b silently excluded, so it is pinned',
    code: `def serve(request)
  cache_path = File.join(document_root, request.path)
  return nil unless File.exist?(cache_path)
  cache_path
end
`,
  },
  {
    id: 'ruby-adversarial-guard-added',
    class: 'adversarial',
    dimension: 'detection',
    file: 'lib/cache.rb',
    parser: /^RUBY$/,
    cwe: /CWE-22/,
    expectDetected: false,
    why: 'rejecting traversal segments is exactly the fix the real advisories shipped — the verdict must flip',
    code: `def serve(request)
  return nil if request.path.split("/").intersect?(%w[. ..])
  cache_path = File.join(document_root, request.path)
  File.read(cache_path)
end
`,
  },
  {
    id: 'ruby-adversarial-constant-root',
    class: 'adversarial',
    dimension: 'detection',
    file: 'lib/cache.rb',
    parser: /^RUBY$/,
    cwe: /CWE-22/,
    expectDetected: false,
    why: 'a path assembled from the project layout is not attacker-reachable — the false positive that got an earlier Ruby rule reverted',
    code: `def load_fixture(name)
  File.read(File.join(__dir__, "fixtures", name))
end
`,
  },
  {
    id: 'ruby-adversarial-literal-leaf',
    class: 'adversarial',
    dimension: 'detection',
    file: 'lib/cache.rb',
    parser: /^RUBY$/,
    cwe: /CWE-22/,
    expectDetected: false,
    why: 'a constant filename cannot traverse',
    code: `def index
  File.read(File.join(document_root, "index.html"))
end
`,
  },

  // ── Sanitization dimension, kept in proportion ────────────────────────────
  // The additions above are all `detection`, because an infrastructure template
  // has no sanitizer. Left alone, that would tilt the gate almost entirely to
  // one dimension and quietly retire the property it was built for — whether
  // the taint engine tracks SANITIZATION through a rewrite.
  {
    id: 'metamorphic-template-literal',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'template-literal interpolation and concatenation are the same operation',
    code: `app.get('/i', (req, res) => {
  const name = escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', \`<p>\${name}</p>\`);
});`,
  },
  // NOT A CASE, deliberately: hoisting the sanitizer into a helper
  //
  //     function clean(v) { return escapeHtml(v); }
  //     const name = clean(req.query.name);
  //
  // is a semantics-preserving rewrite that the engine DOES get wrong — it
  // reports the flow as unsanitized, because `_sanitizersByVar` records callees
  // seen in this function and sanitizer effect is not propagated through a
  // summarised return. Adding it as a case would make this gate permanently
  // red, and a gate nobody can pass is a gate that gets deleted.
  //
  // It is recorded instead: in `dataflow/CLAUDE.md` under what the engine does
  // not model, and in the PRD. The error direction is precision, not safety —
  // a correctly sanitized flow is reported at full confidence — which is why it
  // is a documented limitation rather than a release blocker.
  {
    id: 'adversarial-sanitizer-on-other-var',
    class: 'adversarial',
    expectSanitized: false,
    why: 'the sanitizer is applied to a DIFFERENT request field; the one reaching the sink is raw',
    code: `app.get('/i', (req, res) => {
  const other = escapeHtml(req.query.other);
  el.insertAdjacentHTML('beforeend', req.query.name);
});`,
  },
  {
    id: 'adversarial-html-decoded-after-escape',
    class: 'adversarial',
    expectSanitized: false,
    why: 'he.decode puts back exactly what escapeHtml removed — the value reaching the sink is raw again. This case FAILED when written: the engine reported it SANITIZED, a missed XSS, because nothing modelled a sanitizer being undone.',
    code: `app.get('/i', (req, res) => {
  const escaped = escapeHtml(req.query.name);
  const name = he.decode(escaped);
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'metamorphic-url-decode-is-not-an-html-reversal',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'decodeURIComponent undoes percent-encoding and does NOTHING to HTML entities, so it must not void an xss sanitization claim. The reversal list is family-keyed for exactly this reason; a flat list would fail here.',
    code: `app.get('/i', (req, res) => {
  const raw = decodeURIComponent(req.query.name);
  const name = escapeHtml(raw);
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  // Rust: sqlx::query(&format!(...)) vs the parameterized .bind() form —
  // the exact contrast the engine must draw to be more than a taint-blind
  // sink-name matcher. `format!` splices the value into the SQL text itself;
  // `.bind()` keeps the SQL a literal and passes the value out-of-band.
  {
    id: 'rs-sqli-format-baseline',
    class: 'baseline',
    dimension: 'detection',
    file: 'main.rs',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'sqlx::query(&format!("...{}...", input)) splices the request value into the SQL text — SQL injection',
    code: `use axum::extract::Query;
use std::collections::HashMap;

async fn f(Query(params): Query<HashMap<String, String>>, pool: &sqlx::PgPool) {
    let q = params.get("q").unwrap().to_string();
    sqlx::query(&format!("SELECT * FROM t WHERE q = '{}'", q)).fetch_all(pool).await.unwrap();
}`,
  },
  {
    id: 'rs-sqli-bind-adversarial',
    class: 'adversarial',
    dimension: 'detection',
    file: 'main.rs',
    cwe: /CWE-89/,
    expectDetected: false,
    why: 'the `.bind()` form keeps the SQL text a compile-time literal and passes the value as a parameter — genuinely safe, and the verdict must flip from the baseline above, not just always fire on any sqlx::query call',
    code: `use axum::extract::Query;
use std::collections::HashMap;

async fn f(Query(params): Query<HashMap<String, String>>, pool: &sqlx::PgPool) {
    let q = params.get("q").unwrap().to_string();
    sqlx::query("SELECT * FROM t WHERE q = $1").bind(q).fetch_all(pool).await.unwrap();
}`,
  },

  // ── RegExp.exec is not child_process.exec ─────────────────────────────────
  // The callee `exec` is a command sink in the catalog, matched by bare method
  // name. A regex's own `.exec()` shares that name and is by far the more
  // common call on request data, so the sink must be gated on the receiver's
  // type: a receiver that is provably a RegExp is not a sink; a real
  // child_process exec, however it is spelled, still is; and a receiver the
  // engine cannot resolve keeps the conservative (fires) behaviour.
  {
    id: 'rx-exec-baseline-child-process',
    class: 'baseline',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: true,
    why: 'exec imported from child_process with a request value in the command is command injection',
    code: `const { exec } = require('child_process');
app.get('/v', (req, res) => {
  exec('ls ' + req.query.d);
  res.send('ok');
});`,
  },
  {
    id: 'rx-exec-metamorphic-member-form',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: true,
    why: 'cp.exec(...) through the module object is the same call as the destructured exec',
    code: `const cp = require('child_process');
app.get('/v', (req, res) => {
  cp.exec('ls ' + req.query.d);
  res.send('ok');
});`,
  },
  {
    id: 'rx-exec-metamorphic-unresolved-receiver',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: true,
    why: 'a receiver the engine cannot resolve to a RegExp must keep firing: only a PROVEN regex is exempt',
    code: `const runner = makeRunner();
app.get('/v', (req, res) => {
  runner.exec('ls ' + req.query.d);
  res.send('ok');
});`,
  },
  {
    id: 'rx-exec-metamorphic-rebound-name',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: true,
    why: 'the same name is a regex in another scope of the file: the engine cannot tell the scopes apart, so a name ever bound to anything but a regex is not a proven RegExp and keeps firing',
    code: `app.get('/a', (req, res) => {
  const runner = require('child_process');
  runner.exec('ls ' + req.query.d);
  res.send('ok');
});
app.get('/b', (req, res) => {
  const runner = /^a/;
  res.send(String(runner.test('a')));
});`,
  },
  {
    id: 'rx-exec-adversarial-module-const',
    class: 'adversarial',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: false,
    why: 'a module-scope const initialised from a regex literal: its .exec() runs a match, not a shell',
    code: `const SEMVER = /^(\\d+)\\.(\\d+)$/;
app.get('/v', (req, res) => {
  const m = SEMVER.exec(req.query.v);
  res.send(String(m && m[1]));
});`,
  },
  {
    id: 'rx-exec-adversarial-inline-literal',
    class: 'adversarial',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: false,
    why: 'a regex literal as the receiver: /re/.exec(value) runs a match, not a shell',
    code: `app.get('/v', (req, res) => {
  const n = /^(\\d+)/.exec(req.query.w);
  res.send(String(n && n[1]));
});`,
  },
  {
    id: 'rx-exec-adversarial-new-regexp',
    class: 'adversarial',
    dimension: 'detection',
    cwe: /CWE-78/,
    expectDetected: false,
    why: 'a local initialised from new RegExp(...): its .exec() runs a match, not a shell',
    code: `app.get('/v', (req, res) => {
  const re = new RegExp('^v(\\d+)');
  const m = re.exec(req.query.v);
  res.send(String(m && m[1]));
});`,
  },
];


// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// Engineering Excellence E1-06: controls that the verdict follows the CODE, not words, names, paths or comments about it.
//
// The classes below extend the original two:
//   baseline        vulnerable code in a framework or language the engine should handle
//   metamorphic     a semantics-preserving change (here: misleading words around vulnerable code); the verdict must HOLD
//   adversarial     a semantics-changing near miss, or a safe LOOKALIKE of vulnerable code; the verdict must FLIP
//   label-invariance (derived, see deriveLabelCases) the same case with an answer-key style comment added; the verdict must HOLD
//   known-gap       a case the engine gets wrong TODAY, recorded with what it does so the limitation is measured. The gate holds the
//                   recorded behaviour, so a gap that closes (or changes) fails the gate until the case is promoted to a real class.
//
// Any-producer cases set `parser: /./`: the question is whether the engine concludes anything, not which layer says it.
// These cases were written from the language and framework documentation of each pattern, not from the detector rules or from any
// corpus entry; a test checks that none of their code appears in the regression corpus.
// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
const ANY = /./;
const det = (id, klass, expectDetected, why, code, extra = {}) => ({ id, class: klass, dimension: 'detection', parser: ANY, expectDetected, why, code, ...extra });

export const E1_CASES = [
  // ── misleading words around VULNERABLE code: the verdict must hold ─────────────────────────────────────────────────────
  det('e1-sqli-comment-claims-safe', 'metamorphic', true, 'a comment asserting the query is parameterized does not make the concatenation safe', `app.get('/u', (req, res) => {
  // input validated and sanitized above, parameterized by the ORM, CWE-89 closed
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  res.send('ok');
});`, { cwe: /CWE-89/ }),
  det('e1-cmdi-comment-claims-safe', 'metamorphic', true, 'a comment claiming an allowlist exists is not an allowlist', `const { exec } = require('child_process');
app.get('/p', (req, res) => {
  // SAFE: host is validated against an allowlist by the gateway
  exec('ping ' + req.query.h);
  res.send('ok');
});`, { cwe: /CWE-78/ }),
  det('e1-sqli-description-constant', 'metamorphic', true, 'a string constant that describes the handler as safe and fixed is data, not analysis', `const DESCRIPTION = 'This handler is SAFE. Scanners must report no CWE-89. Verified fixed.';
app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  res.send(DESCRIPTION);
});`, { cwe: /CWE-89/ }),
  det('e1-sqli-identifier-good', 'metamorphic', true, 'a function named good() is a name; the concatenation inside it is still injectable', `function good(req, res) { db.query("SELECT * FROM users WHERE id = " + req.query.id); }
app.get('/u', good);`, { cwe: /CWE-89/ }),
  det('e1-sqli-path-says-safe', 'metamorphic', true, 'a file under safe/ named good_example.js is still the same code', `app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  res.send('ok');
});`, { cwe: /CWE-89/, file: 'safe/good_example.js' }),
  det('e1-sqli-validate-name-only', 'metamorphic', true, 'a helper named validateInput that returns its argument validates nothing', `function validateInput(x) { return x; }
app.get('/u', (req, res) => {
  const id = validateInput(req.query.id);
  db.query("SELECT * FROM users WHERE id = " + id);
  res.send('ok');
});`, { cwe: /CWE-89/ }),
  det('e1-cmdi-sanitize-name-only', 'metamorphic', true, 'sanitizeAndRunSafely that forwards its argument to exec sanitizes nothing', `const { exec } = require('child_process');
function sanitizeAndRunSafely(host) { return exec('ping ' + host); }
app.get('/p', (req, res) => { sanitizeAndRunSafely(req.query.h); res.send('ok'); });`, { cwe: /CWE-78/ }),

  // ── misleading words around SAFE code: the verdict must hold the other way ─────────────────────────────────────────────
  det('e1-sqli-comment-claims-vuln-on-safe', 'adversarial', false, 'a comment announcing a SQL injection flaw does not create one in a parameterized query', `app.get('/u', (req, res) => {
  // VULNERABLE: SQL injection CWE-89 FLAW
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
  res.send('ok');
});`, { cwe: /CWE-89/ }),
  det('e1-py-comment-claims-vuln-on-safe', 'adversarial', false, 'the same, in Python', `from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route('/u')
def u():
    cur = sqlite3.connect('d.db').cursor()
    # FLAW: CWE-89 sql injection here
    cur.execute("SELECT * FROM users WHERE id = ?", (request.args.get('id'),))
    return 'ok'
`, { cwe: /CWE-89/, file: 'app.py' }),

  // ── the same defect across frameworks and languages ───────────────────────────────────────────────────────────────────
  det('e1-sqli-koa', 'baseline', true, 'Koa: ctx.query reaches a concatenated query', `router.get('/u', async (ctx) => { await db.query('SELECT * FROM users WHERE id = ' + ctx.query.id); ctx.body = 'ok'; });`, { cwe: /CWE-89/ }),
  det('e1-sqli-fastify', 'baseline', true, 'Fastify: request.query reaches a concatenated query', `fastify.get('/u', async (request, reply) => { await db.query('SELECT * FROM users WHERE id = ' + request.query.id); return 'ok'; });`, { cwe: /CWE-89/ }),
  det('e1-sqli-hapi', 'baseline', true, 'Hapi route handler', `server.route({ method: 'GET', path: '/u', handler: async (request, h) => { await db.query('SELECT * FROM users WHERE id = ' + request.query.id); return 'ok'; } });`, { cwe: /CWE-89/ }),
  det('e1-sqli-nest', 'baseline', true, 'NestJS: @Query parameter into a raw query', `@Controller('u') export class U { @Get() async get(@Query('id') id: string) { return this.repo.query('SELECT * FROM users WHERE id = ' + id); } }`, { cwe: /CWE-89/, file: 'u.controller.ts' }),
  det('e1-sqli-flask', 'baseline', true, 'Flask: request.args into cursor.execute', `from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route('/u')
def u():
    cur = sqlite3.connect('d.db').cursor()
    cur.execute("SELECT * FROM users WHERE id = " + request.args.get('id'))
    return 'ok'
`, { cwe: /CWE-89/, file: 'app.py' }),
  det('e1-sqli-django', 'baseline', true, 'Django view: request.GET into cursor.execute', `from django.db import connection
def u(request):
    cur = connection.cursor()
    cur.execute("SELECT * FROM t WHERE id = " + request.GET['id'])
`, { cwe: /CWE-89/, file: 'views.py' }),
  det('e1-sqli-fastapi', 'baseline', true, 'FastAPI: a path function parameter into execute', `from fastapi import FastAPI
import sqlite3
app = FastAPI()
@app.get('/u')
def u(id: str):
    return sqlite3.connect('d').execute("SELECT * FROM t WHERE id = " + id).fetchall()
`, { cwe: /CWE-89/, file: 'app.py' }),
  det('e1-sqli-java-servlet', 'baseline', true, 'Servlet: getParameter into Statement.executeQuery', `import javax.servlet.http.*; import java.sql.*;
public class Q extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
  Statement st = DriverManager.getConnection("jdbc:x").createStatement();
  st.executeQuery("SELECT * FROM t WHERE id = " + req.getParameter("id")); } }
`, { cwe: /CWE-89/, file: 'Q.java' }),
  det('e1-sqli-go-http', 'baseline', true, 'net/http: URL query into database/sql Query', `package main
import ("database/sql"; "net/http")
func h(w http.ResponseWriter, r *http.Request) { db, _ := sql.Open("x", "y"); db.Query("SELECT * FROM t WHERE id = " + r.URL.Query().Get("id")) }
func main() { http.HandleFunc("/", h) }
`, { cwe: /CWE-89/, file: 'main.go' }),
  det('e1-sqli-gin', 'baseline', true, 'Gin: c.Query into database/sql Query', `package main
import ("database/sql"; "github.com/gin-gonic/gin")
func h(c *gin.Context) { db, _ := sql.Open("x", "y"); db.Query("SELECT * FROM t WHERE id = " + c.Query("id")) }
`, { cwe: /CWE-89/, file: 'main.go' }),
  det('e1-sqli-php', 'baseline', true, 'PHP: $_GET into mysqli_query', `<?php
$id = $_GET['id'];
$r = mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);
`, { cwe: /CWE-89/, file: 'a.php' }),
  det('e1-sqli-laravel', 'baseline', true, 'Laravel: request input into DB::select', `<?php
class C extends Controller { public function u(Request $request) { return DB::select("SELECT * FROM t WHERE id = " . $request->input('id')); } }
`, { cwe: /CWE-89/, file: 'C.php' }),
  det('e1-sqli-rails', 'baseline', true, 'Rails: params interpolated into where()', `class UsersController < ApplicationController
  def show
    User.where("id = #{params[:id]}")
  end
end
`, { cwe: /CWE-89/, file: 'a.rb' }),
  det('e1-sqli-sinatra', 'baseline', true, 'Sinatra: params interpolated into execute', `require 'sinatra'
get '/u' do
  DB.execute("SELECT * FROM t WHERE id = #{params[:id]}")
end
`, { cwe: /CWE-89/, file: 'a.rb' }),
  det('e1-cmdi-py-os-system', 'baseline', true, 'Python: request.args into os.system', `import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/p')
def p():
    os.system('ping ' + request.args.get('h'))
    return 'ok'
`, { cwe: /CWE-78/, file: 'app.py' }),
  det('e1-ssrf-fetch', 'baseline', true, 'fetch of a request-supplied URL', `app.get('/g', async (req, res) => { const r = await fetch(req.query.url); res.send(await r.text()); });`, { cwe: /CWE-918/ }),
  det('e1-path-sendfile', 'baseline', true, 'sendFile of a request-supplied name', `app.get('/f', (req, res) => { res.sendFile('/srv/data/' + req.query.name); });`, { cwe: /CWE-22/ }),
  det('e1-path-readfile-async', 'baseline', true, 'fs.readFile of a request-supplied name', `const fs = require('fs');
app.get('/f', (req, res) => { fs.readFile('/srv/data/' + req.query.name, (e, d) => res.send(d)); });`, { cwe: /CWE-22/ }),
  det('e1-path-py-open', 'baseline', true, 'open() of a request-supplied name', `from flask import Flask, request
app = Flask(__name__)
@app.route('/f')
def f():
    return open('/srv/data/' + request.args.get('name')).read()
`, { cwe: /CWE-22/, file: 'app.py' }),
  det('e1-xss-send', 'baseline', true, 'request value concatenated into an HTML response', `app.get('/h', (req, res) => { res.send('<h1>' + req.query.name + '</h1>'); });`, { cwe: /CWE-79/ }),
  det('e1-redirect-open', 'baseline', true, 'redirect to a request-supplied location', `app.get('/r', (req, res) => { res.redirect(req.query.next); });`, { cwe: /CWE-601/ }),

  // ── safe LOOKALIKES: they read like the vulnerable shape and are not ──────────────────────────────────────────────────
  det('e1-lookalike-py-parameterized', 'adversarial', false, 'a bound parameter, not concatenation', `from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route('/u')
def u():
    cur = sqlite3.connect('d.db').cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (request.args.get('id'),))
    return 'ok'
`, { cwe: /CWE-89/, file: 'app.py' }),
  det('e1-lookalike-java-prepared', 'adversarial', false, 'PreparedStatement with a bound value', `import javax.servlet.http.*; import java.sql.*;
public class Q extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
  PreparedStatement st = DriverManager.getConnection("jdbc:x").prepareStatement("SELECT * FROM t WHERE id = ?");
  st.setString(1, req.getParameter("id")); st.executeQuery(); } }
`, { cwe: /CWE-89/, file: 'Q.java' }),
  det('e1-lookalike-go-bound', 'adversarial', false, 'a $1 placeholder with the value passed separately', `package main
import ("database/sql"; "net/http")
func h(w http.ResponseWriter, r *http.Request) { db, _ := sql.Open("x", "y"); db.Query("SELECT * FROM t WHERE id = $1", r.URL.Query().Get("id")) }
func main() { http.HandleFunc("/", h) }
`, { cwe: /CWE-89/, file: 'main.go' }),
  det('e1-lookalike-php-int-cast', 'adversarial', false, 'an (int) cast makes the value a number', `<?php
$id = (int)$_GET['id'];
$r = mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);
`, { cwe: /CWE-89/, file: 'a.php' }),
  det('e1-lookalike-py-subprocess-list', 'adversarial', false, 'an argument list is not parsed by a shell', `import subprocess
from flask import Flask, request
app = Flask(__name__)
@app.route('/p')
def p():
    subprocess.run(['ping', '-c', '1', request.args.get('h')])
    return 'ok'
`, { cwe: /CWE-78/, file: 'app.py' }),
  det('e1-lookalike-js-spawn-array', 'adversarial', false, 'spawn with an argument array', `const { spawn } = require('child_process');
app.get('/p', (req, res) => { spawn('ping', ['-c', '1', req.query.h]); res.send('ok'); });`, { cwe: /CWE-78/ }),
  det('e1-lookalike-js-basename', 'adversarial', false, 'path.basename strips directories', `const fs = require('fs'); const path = require('path');
app.get('/f', (req, res) => { res.send(fs.readFileSync('/srv/data/' + path.basename(req.query.name))); });`, { cwe: /CWE-22/ }),
  det('e1-lookalike-ssrf-allowlist', 'adversarial', false, 'the URL is checked against a fixed allowlist before it is fetched', `const ALLOWED = new Set(['https://api.example.com']);
app.get('/g', async (req, res) => { if (!ALLOWED.has(req.query.url)) return res.sendStatus(400); const r = await fetch(req.query.url); res.send(await r.text()); });`, { cwe: /CWE-918/ }),
  det('e1-lookalike-xss-escaped', 'adversarial', false, 'the value is HTML-escaped', `const escapeHtml = require('escape-html');
app.get('/h', (req, res) => { res.send('<h1>' + escapeHtml(req.query.name) + '</h1>'); });`, { cwe: /CWE-79/ }),
  det('e1-lookalike-xss-json', 'adversarial', false, 'a JSON response is not interpreted as markup', `app.get('/h', (req, res) => { res.json({ name: req.query.name }); });`, { cwe: /CWE-79/ }),
  det('e1-lookalike-redirect-constant', 'adversarial', false, 'a constant location', `app.get('/r', (req, res) => { res.redirect('/home'); });`, { cwe: /CWE-601/ }),
  {
    id: 'e1-sanitized-int-cast', class: 'metamorphic', parser: ANY, cwe: /CWE-89/, expectSanitized: true,
    why: 'parseInt(..., 10) yields a number; the flow is reported and labelled sanitized',
    code: `app.get('/u', (req, res) => { const id = parseInt(req.query.id, 10); db.query('SELECT * FROM users WHERE id = ' + id); res.send('ok'); });`,
    parser: /^IR-TAINT$/,
  },
  {
    id: 'e1-sanitized-py-basename', class: 'metamorphic', cwe: /CWE-22/, expectSanitized: true, parser: /^IR-TAINT$/, file: 'app.py',
    why: 'os.path.basename removes directory components; the flow is reported and labelled sanitized',
    code: `import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/f')
def f():
    return open('/srv/data/' + os.path.basename(request.args.get('name'))).read()
`,
  },

  // ── KNOWN GAPS: measured today, held by the gate until they are fixed and promoted ─────────────────────────────────────
  det('gap-fp-js-constant-concat', 'known-gap', false, 'concatenating a constant table name into a query involves no request value; the structural JS layer still reports it', `const TABLE = 'users';
app.get('/u', (req, res) => { db.query('SELECT * FROM ' + TABLE + ' WHERE active = 1'); res.send('ok'); });`, { cwe: /CWE-89/, gap: { observedDetected: true, kind: 'false positive' } }),
  det('gap-fp-js-allowlist-ternary', 'known-gap', false, 'a column name chosen from a fixed list (includes() with a constant fallback) cannot carry an injection; the flow is reported unsanitized', `const COLS = ['name', 'age'];
app.get('/u', (req, res) => { const c = COLS.includes(req.query.c) ? req.query.c : 'name'; db.query('SELECT ' + c + ' FROM users'); res.send('ok'); });`, { cwe: /CWE-89/, gap: { observedDetected: true, kind: 'false positive' } }),
  det('gap-fp-ruby-where-hash', 'known-gap', false, 'where(id: params[:id]) is a hash condition that ActiveRecord parameterizes; it is reported as SQL injection', `class UsersController < ApplicationController
  def show
    User.where(id: params[:id])
  end
end
`, { cwe: /CWE-89/, file: 'a.rb', gap: { observedDetected: true, kind: 'false positive' } }),
  det('gap-fn-js-readfilesync-concat', 'known-gap', true, 'fs.readFileSync with a request value concatenated into the path is path traversal; the synchronous form is not reported although readFile and sendFile are', `const fs = require('fs');
app.get('/f', (req, res) => { res.send(fs.readFileSync('/srv/data/' + req.query.name)); });`, { cwe: /CWE-22/, gap: { observedDetected: false, kind: 'false negative' } }),
  det('gap-fn-java-spring-jdbctemplate', 'known-gap', true, 'JdbcTemplate.queryForList with a concatenated @RequestParam is SQL injection; the Spring sink is not reported', `@RestController public class C { @Autowired JdbcTemplate jdbc;
 @GetMapping("/u") public Object u(@RequestParam String id) { return jdbc.queryForList("SELECT * FROM t WHERE id = " + id); } }
`, { cwe: /CWE-89/, file: 'C.java', gap: { observedDetected: false, kind: 'false negative' } }),
];

// ── Derived: the same verdict with answer-key words around the code ───────────────────────────────────────────────────────
const COMMENT_PREFIX = { js: '//', jsx: '//', mjs: '//', cjs: '//', ts: '//', tsx: '//', java: '//', go: '//', cs: '//', kt: '//', rs: '//', php: '//', c: '//', cpp: '//', py: '#', rb: '#', sh: '#', hs: '--' };
const VULN_LABEL = 'VULNERABLE: this is the FLAW. CWE-89 CWE-79 CWE-78 CWE-22 true positive, finding expected. bad() badSource() badSink()';
const SAFE_LABEL = 'SAFE: input is sanitized, validated and parameterized. good() goodSink(). Reviewed and fixed: CWE closed, no finding expected.';

export function commentPrefixFor(file = 'app.js') {
  const ext = String(file).split('.').pop().toLowerCase();
  return COMMENT_PREFIX[ext] || null;
}

/** Put a comment line at the top of a source file. PHP and shebang files keep their first line first. */
export function withComment(code, file, text) {
  const p = commentPrefixFor(file);
  if (!p) return null;
  const line = `${p} ${text}`;
  const lines = code.split('\n');
  if (/^<\?php/.test(lines[0]) || /^#!/.test(lines[0])) return [lines[0], line, ...lines.slice(1)].join('\n');
  return `${line}\n${code}`;
}

/**
 * Two label-invariance variants of every case that has a known expectation: the code with a VULNERABLE-style comment on top and with a
 * SAFE-style one. The expectation is the base case's, unchanged. A verdict that moves because of a comment was keyed on words.
 */
export function deriveLabelCases(cases) {
  const out = [];
  for (const c of cases) {
    if (c.class === 'known-gap') continue;
    for (const [tag, text] of [['vuln-label', VULN_LABEL], ['safe-label', SAFE_LABEL]]) {
      const code = withComment(c.code, c.file, text);
      if (code === null) continue;
      out.push({ ...c, id: `${c.id}~${tag}`, class: 'label-invariance', derivedFrom: c.id, why: `${c.why} (with an answer-key style comment: ${tag})`, code });
    }
  }
  return out;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// DAG precision cases (docs/implementation-status/dag-improvements.md): each rule is a statement about what a construct CAN do,
// so every case pairs a semantics-preserving rewrite (verdict must hold) with a semantics-changing near-miss (verdict must flip).
//   open redirect  a literal that fixes the ORIGIN ('/user/' + id) cannot be steered off-origin; '/' + x, '//' + x, a host
//                  without a closing slash and a bare value can
//   reflection     only the properties of `req` that carry the client's input are request input; session/user/app state and
//                  a value wrapped in an HTML escaper are not reflected raw
//   blocking I/O   a synchronous call at module level delays startup once; the same call in a handler stalls every request
//   file serving   sendFile/download with an inline `root` option confines the path; without `root` the caller owns containment
//   logging        the `address` a listen callback receives is the bound socket address; the same name bound from a request is not
// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
const STRUCT = /^STRUCTURAL$/;
export const DAG_PRECISION_CASES = [
  // ── open redirect ───────────────────────────────────────────────────────────────────────────────────────────────────────
  det('dag-redirect-baseline', 'baseline', true, 'a redirect whose whole target is request input is an open redirect', `app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-pinned-path', 'metamorphic', false, 'a target that begins with a path-absolute literal stays on this origin whatever follows it', `app.get('/go', (req, res) => {
  res.redirect('/user/' + req.query.id);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-pinned-path-template', 'metamorphic', false, 'a template literal with the same fixed prefix is the same program', `app.get('/go', (req, res) => {
  res.redirect(\`/user/\${req.query.id}\`);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-pinned-path-via-variable', 'metamorphic', false, 'binding the request value to a name first does not change where the redirect can land', `app.get('/go', (req, res) => {
  const id = req.query.id;
  res.redirect('/user/' + id);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-pinned-with-status', 'metamorphic', false, 'a status code before the target does not change the target', `app.get('/go', (req, res) => {
  res.redirect(302, '/user/' + req.query.id);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-pinned-absolute', 'metamorphic', false, 'a complete authority followed by a slash fixes the host', `app.get('/go', (req, res) => {
  res.redirect('https://app.example.com/' + req.query.p);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-bare-slash', 'adversarial', true, "'/' + x is '//host' when x starts with a slash: a protocol-relative redirect", `app.get('/go', (req, res) => {
  res.redirect('/' + req.query.next);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-double-slash', 'adversarial', true, "'//' + x names the host outright", `app.get('/go', (req, res) => {
  res.redirect('//' + req.query.next);
});`, { cwe: /CWE-601/ }),
  det('dag-redirect-host-without-slash', 'adversarial', true, "'https://app.example.com' + x lets x extend the host ('.evil.test') or add userinfo ('@evil.test')", `app.get('/go', (req, res) => {
  res.redirect('https://app.example.com' + req.query.next);
});`, { cwe: /CWE-601/ }),

  // ── reflected input ─────────────────────────────────────────────────────────────────────────────────────────────────────
  det('dag-reflect-baseline', 'baseline', true, 'raw query input written to the response', `app.get('/h', (req, res) => {
  res.send('hi ' + req.query.name);
});`, { cwe: /CWE-79/, parser: STRUCT }),
  det('dag-reflect-renamed-property', 'metamorphic', true, 'another request-input property is the same program', `app.post('/h', (req, res) => {
  res.send('hi ' + req.body.who);
});`, { cwe: /CWE-79/, parser: STRUCT }),
  det('dag-reflect-escaped', 'adversarial', false, 'the same value inside an HTML escaper is encoded before it is written', `app.get('/h', (req, res) => {
  res.send('hi ' + escapeHtml(req.query.name));
});`, { cwe: /CWE-79/, parser: STRUCT }),
  det('dag-reflect-session-state', 'adversarial', false, 'req.session holds server-side state, not what this request sent', `app.get('/h', (req, res) => {
  res.send('visits ' + req.session.count);
});`, { cwe: /CWE-79/, parser: STRUCT }),
  det('dag-reflect-user-object', 'adversarial', false, 'req.user is loaded by authentication middleware, not typed by this request', `app.get('/h', (req, res) => {
  res.send('hi ' + req.user.name);
});`, { cwe: /CWE-79/, parser: STRUCT }),
  det('dag-reflect-escaped-plus-raw', 'metamorphic', true, 'one escaped value does not protect a second, raw one in the same call', `app.get('/h', (req, res) => {
  res.send('hi ' + escapeHtml(req.query.a) + req.query.b);
});`, { cwe: /CWE-79/, parser: STRUCT }),

  // ── blocking I/O ────────────────────────────────────────────────────────────────────────────────────────────────────────
  det('dag-sync-io-in-handler', 'baseline', true, 'a blocking read inside a request handler stalls every connection', `const express = require('express');
const fs = require('fs');
const app = express();
app.get('/f', (req, res) => {
  const body = fs.readFileSync('page.html', 'utf8');
  res.send(body);
});
app.listen(3000);`, { cwe: /CWE-400/, parser: STRUCT }),
  det('dag-sync-io-in-handler-function-form', 'metamorphic', true, 'a function expression instead of an arrow is the same handler', `const express = require('express');
const fs = require('fs');
const app = express();
app.get('/f', function (req, res) {
  const body = fs.readFileSync('page.html', 'utf8');
  res.send(body);
});
app.listen(3000);`, { cwe: /CWE-400/, parser: STRUCT }),
  det('dag-sync-io-in-expression-arrow', 'metamorphic', true, 'an expression-bodied arrow handler is a handler: the read runs per request', `const express = require('express');
const fs = require('fs');
const app = express();
app.get('/f', (req, res) => res.send(fs.readFileSync('page.html', 'utf8')));
app.listen(3000);`, { cwe: /CWE-400/, parser: STRUCT }),
  det('dag-sync-io-in-module-helper', 'metamorphic', true, 'a read inside a helper function runs whenever the helper is called, not at load', `const express = require('express');
const fs = require('fs');
const app = express();
const load = (p) => fs.readFileSync(p, 'utf8');
app.get('/f', (req, res) => res.send(load('page.html')));
app.listen(3000);`, { cwe: /CWE-400/, parser: STRUCT }),
  det('dag-sync-io-at-startup', 'adversarial', false, 'the same read once at module load delays startup once and blocks nobody', `const express = require('express');
const fs = require('fs');
const app = express();
const page = fs.readFileSync('page.html', 'utf8');
app.get('/f', (req, res) => {
  res.send(page);
});
app.listen(3000);`, { cwe: /CWE-400/, parser: STRUCT }),
  det('dag-sync-io-in-options-object-at-startup', 'adversarial', false, 'a read inside an options object evaluated at module load is still startup', `const express = require('express');
const fs = require('fs');
const server = require('https').createServer({ key: fs.readFileSync('k.pem'), cert: fs.readFileSync('c.pem') }, express());
server.listen(3000);`, { cwe: /CWE-400/, parser: STRUCT }),

  // ── file serving ────────────────────────────────────────────────────────────────────────────────────────────────────────
  det('dag-sendfile-unrooted', 'baseline', true, 'a client-chosen path handed to sendFile with no root is path traversal', `const path = require('path');
app.get('/d', (req, res) => {
  res.sendFile(req.query.f);
});`, { cwe: /CWE-22/ }),
  det('dag-sendfile-rooted', 'adversarial', false, 'with an inline root the sender resolves inside it and refuses a path that climbs out', `app.get('/d', (req, res) => {
  res.sendFile(req.query.f, { root: '/srv/files' });
});`, { cwe: /CWE-22/ }),
  det('dag-sendfile-rooted-download', 'metamorphic', false, 'download takes the same options', `app.get('/d', (req, res) => {
  res.download(req.query.f, 'out.bin', { root: '/srv/files' });
});`, { cwe: /CWE-22/ }),
  det('dag-sendfile-options-without-root', 'adversarial', true, 'an options object that does not set root confines nothing', `app.get('/d', (req, res) => {
  res.sendFile(req.query.f, { dotfiles: 'deny' });
});`, { cwe: /CWE-22/ }),

  // ── logging a value because of its name ─────────────────────────────────────────────────────────────────────────────────
  det('dag-log-listen-address', 'baseline', false, 'the address a listen callback receives is the bound socket address', `const app = require('express')();
app.listen(3000, (err, address) => {
  console.log(\`listening on \${address}\`);
});`, { cwe: /CWE-(359|532)/ }),
  det('dag-log-listen-address-function-form', 'metamorphic', false, 'a function expression callback is the same program', `const app = require('express')();
app.listen(3000, function (err, address) {
  console.log(\`listening on \${address}\`);
});`, { cwe: /CWE-(359|532)/ }),
  det('dag-log-request-address', 'adversarial', true, 'the same name taken from the request body is a postal address', `app.post('/ship', (req, res) => {
  const address = req.body.address;
  console.log(\`shipping to \${address}\`);
  res.end();
});`, { cwe: /CWE-(359|532)/ }),
  det('dag-log-prose-only', 'adversarial', false, 'a PII word that appears only in the text of a message is not a logged value', `app.post('/s', (req, res) => {
  console.log('please enter your email to continue');
  res.end();
});`, { cwe: /CWE-(359|532)/ }),
  det('dag-log-variable', 'adversarial', true, 'logging the variable itself is the finding', `app.post('/s', (req, res) => {
  const email = req.body.email;
  console.log(email);
  res.end();
});`, { cwe: /CWE-(359|532)/ }),
];

export function allCases() {
  const hand = [...CASES, ...E1_CASES, ...DAG_PRECISION_CASES, ...HASKELL_CASES];
  return [...hand, ...deriveLabelCases(hand)];
}

/**
 * The verdict of one case given what the engine did (`v` = { detected, sanitized }).
 *   known-gap     passes only while the engine still behaves as recorded; reports whether the gap has closed
 *   detection     passes when `detected` equals `expectDetected`
 *   sanitization  needs the finding to fire at all (a blind engine must not pass), then `sanitized` must equal `expectSanitized`
 */
export function judge(c, v) {
  if (c.class === 'known-gap') {
    return { expected: c.gap.observedDetected, detectOk: true, verdictOk: v.detected === c.gap.observedDetected, gapClosed: v.detected === c.expectDetected };
  }
  if (c.dimension === 'detection') return { expected: c.expectDetected, detectOk: true, verdictOk: v.detected === c.expectDetected };
  return { expected: c.expectSanitized, detectOk: v.detected, verdictOk: v.detected && v.sanitized === c.expectSanitized };
}
