// Metamorphic + adversarial mutation harness.
//
// WHY THIS EXISTS. A detector can score well on a fixed corpus by memorising
// its shapes. This harness measures the opposite property: whether the verdict
// tracks the SEMANTICS of the code. Two mutation classes, and the engine must
// behave differently on each:
//
//   METAMORPHIC  — a semantics-preserving rewrite (rename a variable, swap
//                  string concatenation for a template literal, hoist the sink
//                  into a helper). The verdict MUST NOT move. A verdict that
//                  moves here was keyed on syntax, not meaning.
//
//   ADVERSARIAL  — a semantics-CHANGING near-miss (delete the sanitizer, or
//                  replace it with one from the wrong family). The verdict MUST
//                  move. A verdict that holds here is not analysing the flow.
//
// The score is verdict-flip correctness, not detection count. That is the whole
// point: accumulating patterns cannot raise it, and over-fitting lowers it.
//
// Both directions are gated. A harness that only checks "still detected" would
// pass an engine that labels everything sanitized, and a harness that only
// checks the mutants would pass one that labels nothing.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';
import { runScan } from '../../scanner/src/runScan.js';

// A benchmark must not mutate what it measures. Every mutant is scanned, and a
// scan writes `.agentic-security/` unless told not to — which would leave state
// behind in the temp trees and, worse, normalise the habit. Verified inside,
// not assumed.
await disableStateWrites();

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
const DEFAULT_CWE = /CWE-79/;

// ── The base program. Tainted input, one sanitizer, one XSS sink. ────────────
// Each case rewrites it; `expectSanitized` is what the engine must conclude.
const CASES = [
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
];

async function verdictFor(c, tmpRoot) {
  const dir = path.join(tmpRoot, c.id);
  fs.mkdirSync(dir, { recursive: true });
  // The filename was hardcoded to app.js, so this gate — the anti-overfitting
  // control — could only ever cover JavaScript. Measured on the CVE corpus, 204
  // of 280 findings are NOT JavaScript, so the check with the broadest mandate
  // had the narrowest reach. A case may now name its own file; JS stays the
  // default so every existing case is unchanged.
  // A case may name a NESTED path, and several must: IaC admission is
  // path-sensitive (`charts/app/values.yaml` is a chart's values file,
  // `charts/app/templates/…` is Go template source and deliberately out of
  // scope), so writing every case at the tree root would test a different
  // program than the one the case describes.
  const target = path.join(dir, c.file || 'app.js');
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, c.code);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const cweRe = c.cwe || DEFAULT_CWE;
    // Default stays IR-TAINT: the original cases are all about whether the taint
    // engine labels a flow sanitized. A case can opt into a different producer
    // (`parser`) when it is testing a structural detector instead — without
    // this, a non-taint case silently matches nothing and every verdict reads
    // "not detected", which would look like a passing adversarial case.
    const parserRe = c.parser || /^IR-TAINT$/;
    const hits = (scan.findings || []).filter(
      f => parserRe.test(f.parser || '') && cweRe.test(f.cwe || ''));
    return { detected: hits.length > 0, sanitized: hits.some(f => f.sanitized === true) };
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  }
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-mutation-'));
const rows = [];
let failures = 0;

for (const c of CASES) {
  const v = await verdictFor(c, tmpRoot);
  let detectOk, verdictOk, expected;
  if (c.dimension === 'detection') {
    // The detection dimension IS the verdict here — a case may legitimately
    // expect no finding (the adversarial non-DB receiver), so "did it fire"
    // cannot also serve as a precondition.
    expected = c.expectDetected;
    detectOk = true;
    verdictOk = v.detected === c.expectDetected;
  } else {
    // Precondition: the finding must fire in every case. A mutation that stops
    // detection entirely is not evidence about sanitization — it is a hole, and
    // silently scoring it as "not sanitized" would let a blind engine pass.
    expected = c.expectSanitized;
    detectOk = v.detected;
    verdictOk = detectOk && v.sanitized === c.expectSanitized;
  }
  if (!verdictOk) failures++;
  rows.push({ ...c, ...v, expected, detectOk, verdictOk });
}

const w = (s, n) => String(s).padEnd(n);
console.log('\nMetamorphic + adversarial mutation gate\n');
console.log(w('case', 38), w('class', 13), w('dimension', 14), w('detected', 10), w('sanitized', 11), w('expected', 10), 'ok');
console.log('-'.repeat(108));
for (const r of rows) {
  console.log(
    w(r.id, 38), w(r.class, 13), w(r.dimension || 'sanitization', 14), w(r.detected, 10),
    w(r.sanitized, 11), w(r.expected, 10), r.verdictOk ? 'PASS' : 'FAIL');
  if (!r.verdictOk) {
    console.log(`   ${r.detectOk ? 'verdict' : 'DETECTION'} wrong — ${r.why}`);
  }
}

const metamorphic = rows.filter(r => r.class === 'metamorphic');
const adversarial = rows.filter(r => r.class === 'adversarial');
const pct = (list) => list.length
  ? `${list.filter(r => r.verdictOk).length}/${list.length}` : '0/0';
console.log('-'.repeat(108));
console.log(`metamorphic (verdict must HOLD): ${pct(metamorphic)}`);
console.log(`adversarial (verdict must FLIP): ${pct(adversarial)}`);
// Deliberately excludes the untagged 'baseline' sanity-check case: this line
// reports verdict-FLIP correctness specifically, and baseline is neither a
// metamorphic nor an adversarial mutant. Computing it over `rows` (all cases,
// including baseline) made the printed total disagree with metamorphic+
// adversarial's own sum (3+3=6 vs. a reported denominator of 7) — any
// baseline-only regression showed up as an unexplained "missing" case in this
// summary line with no attribution. `failures` below still covers every row,
// baseline included, so this is a reporting fix, not a gate-strength change.
console.log(`verdict-flip correctness       : ${pct([...metamorphic, ...adversarial])}`);

fs.rmSync(tmpRoot, { recursive: true, force: true });

if (failures) {
  console.error(`\n✖ ${failures} case(s) wrong. The engine is keying on syntax, not semantics.`);
  process.exit(1);
}
console.log('\n✓ every mutant verdict correct');
