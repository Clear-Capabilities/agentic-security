// PRD F4.3 — CloudFormation, Bicep, Helm values and Dockerfile base pinning.
//
// `bench/iac-coverage` is the measurement; this is the gate. It runs offline
// and pins two properties the bench discovered the hard way:
//
//   1. ADMISSION. A CloudFormation template is a `.yaml` that no path
//      predicate recognises, exactly like a Kubernetes manifest, and the
//      walker has TWO gates — `readTree` admits a file, then `runFullScan`
//      re-filters the same list. Opening one and not the other leaves the
//      detector as dark as never writing it. That is what happened to
//      `k8s-admission`, and it is why the first test here scans a directory
//      instead of calling a function.
//
//   2. VERDICT FLIP. Every rule is checked against the HARDENED variant as
//      well as the misconfigured one. A rule that fires on both is not
//      detecting the control, it is detecting the resource — invisible to any
//      recall-only test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { scanCloudTemplates, isCloudFormationTemplate } from '../src/sast/iac-cloud-templates.js';
import { scanContainer } from '../src/sca/container.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures', 'iac-cloud-templates');

const vulns = (file, body) => scanCloudTemplates(file, body).map((f) => f.vuln);

// ─── Admission, end to end ──────────────────────────────────────────────────

test('the fixture pair: vulnerable fires through a real scan, clean does not', async () => {
  for (const [variant, expectFindings] of [['vulnerable', true], ['clean', false]]) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `iac-fx-${variant}-`));
    await fsp.cp(path.join(FIXTURES, variant), dir, { recursive: true });
    await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"fx","version":"1.0.0"}');
    const { scan } = await runScan(dir, { noNetwork: true });
    const iac = (scan.findings || []).filter((f) => /cfn-|bicep-/.test(String(f.id || '')));
    if (expectFindings) {
      assert.ok(iac.length > 0, 'vulnerable fixture must produce CloudFormation/Bicep findings through a scan');
      const ids = iac.map((f) => String(f.id).split(':')[0]);
      assert.ok(ids.includes('cfn-open-ingress'), `expected cfn-open-ingress, got ${ids.join(',')}`);
      assert.ok(ids.includes('cfn-public-bucket'), `expected cfn-public-bucket, got ${ids.join(',')}`);
      assert.ok(ids.includes('bicep-public-blob'), `expected bicep-public-blob, got ${ids.join(',')}`);
    } else {
      assert.deepEqual(iac.map((f) => f.vuln), [], 'clean fixture must be silent');
    }
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('a CloudFormation template is recognised by content, not by path', () => {
  const withVersion = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n";
  const withoutVersion = 'Resources:\n  B:\n    Type: AWS::S3::Bucket\n';
  assert.ok(isCloudFormationTemplate('infra/stack.yaml', withVersion));
  assert.ok(isCloudFormationTemplate('anywhere/at/all.yml', withoutVersion));
  // Both signals are required, so an ordinary config file that happens to use
  // the word "Resources" is not swept in.
  assert.ok(!isCloudFormationTemplate('config/app.yaml', 'Resources:\n  - name: docs\n    url: /docs\n'));
  assert.ok(!isCloudFormationTemplate('infra/stack.txt', withVersion), 'extension still gates');
});

// ─── Verdict flip, per rule ─────────────────────────────────────────────────

test('CloudFormation: only ADMINISTRATIVE ports opened to the world fire', () => {
  const tmpl = (port, cidr) => `AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n      GroupDescription: web\n      SecurityGroupIngress:\n        - IpProtocol: tcp\n          FromPort: ${port}\n          ToPort: ${port}\n          CidrIp: ${cidr}\n`;
  assert.equal(vulns('infra/s.yaml', tmpl(22, '0.0.0.0/0')).length, 1);
  assert.equal(vulns('infra/s.yaml', tmpl(5432, '0.0.0.0/0')).length, 1);
  // A public web listener is the normal case and must stay silent, or nobody
  // will leave this rule on.
  assert.deepEqual(vulns('infra/s.yaml', tmpl(443, '0.0.0.0/0')), []);
  assert.deepEqual(vulns('infra/s.yaml', tmpl(22, '10.0.0.0/8')), []);
});

test('CloudFormation: public bucket ACL flips, private does not', () => {
  const t = (acl) => `AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: ${acl}\n`;
  assert.equal(vulns('infra/s.yaml', t('PublicRead')).length, 1);
  assert.equal(vulns('infra/s.yaml', t('PublicReadWrite')).length, 1);
  assert.deepEqual(vulns('infra/s.yaml', t('Private')), []);
});

test('CloudFormation: wildcard IAM needs BOTH Action * and Resource *', () => {
  const stmt = (action, resource) => `AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  P:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n      PolicyDocument:\n        Version: '2012-10-17'\n        Statement:\n          - Effect: Allow\n            Action: ${action}\n            Resource: ${resource}\n`;
  assert.equal(vulns('infra/iam.yaml', stmt("'*'", "'*'")).length, 1);
  // A wildcard action scoped to one bucket, or a scoped action on everything,
  // is a different and much smaller problem. Neither is this control.
  assert.deepEqual(vulns('infra/iam.yaml', stmt("'*'", "'arn:aws:s3:::assets/*'")), []);
  assert.deepEqual(vulns('infra/iam.yaml', stmt("['s3:GetObject']", "'*'")), []);
});

test('Bicep: public blob and plaintext transit flip', () => {
  const body = (pub, https) => `resource a 'Microsoft.Storage/storageAccounts@2022-09-01' = {\n  properties: {\n    allowBlobPublicAccess: ${pub}\n    supportsHttpsTrafficOnly: ${https}\n  }\n}\n`;
  assert.equal(vulns('infra/main.bicep', body('true', 'false')).length, 2);
  assert.deepEqual(vulns('infra/main.bicep', body('false', 'true')), []);
});

test('Helm values: privileged and hostNetwork defaults flip', () => {
  const body = (v) => `image:\n  repository: r/app\n  tag: "1.0.0"\nhostNetwork: ${v}\nsecurityContext:\n  privileged: ${v}\n`;
  assert.equal(vulns('charts/app/values.yaml', body('true')).length, 2);
  assert.deepEqual(vulns('charts/app/values.yaml', body('false')), []);
  // Only values files. A Go template under templates/ is not YAML and matching
  // text inside {{ }} would report the template rather than the configuration.
  assert.deepEqual(vulns('charts/app/templates/deployment.yaml', body('true')), []);
});

test('Kubernetes: a literal credential in env flips, secretKeyRef does not', () => {
  const literal = 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      env:\n        - name: DB_PASSWORD\n          value: "Kd8fJ2mQx9Lp4Zt1"\n';
  const ref = 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      env:\n        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n              name: s\n              key: k\n';
  assert.equal(vulns('deploy/app.yaml', literal).length, 1);
  assert.deepEqual(vulns('deploy/app.yaml', ref), []);
  // A non-secret env var is not a finding however long its value.
  const benign = 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      env:\n        - name: LOG_LEVEL\n          value: "debug"\n';
  assert.deepEqual(vulns('deploy/app.yaml', benign), []);
});

test('Dockerfile: unpinned base flips, digest-pinned does not', () => {
  const digest = 'sha256:' + '5e5f6f0a2ea0c9e6e2e6b1e33b8b1e0c8a9d3f2e1b0a9c8d7e6f5a4b3c2d1e0f';
  assert.equal(vulns('Dockerfile', 'FROM ubuntu:latest\nUSER app\n').length, 1);
  assert.equal(vulns('Dockerfile', 'FROM ubuntu\nUSER app\n').length, 1);
  assert.deepEqual(vulns('Dockerfile', `FROM ubuntu@${digest}\nUSER app\n`), []);
  assert.deepEqual(vulns('Dockerfile', 'FROM ubuntu:24.04\nUSER app\n'), []);
  // A named build stage is an internal reference, not a registry pull.
  assert.deepEqual(vulns('Dockerfile', 'FROM node:20-alpine AS builder\nFROM builder\nUSER app\n'), []);
});

// ─── The false positive verdict-flip scoring exposed ────────────────────────

test('a digest-pinned base image is not reported as a floating tag', () => {
  // `_ALL_FROM_RE` matched the digest without capturing it, so
  // `FROM ubuntu@sha256:…` parsed as image=ubuntu with no tag, and a missing
  // tag is treated as `latest`. The most tightly pinned form a Dockerfile can
  // use was therefore reported as "ubuntu:latest (floating tag)".
  //
  // A false positive on the HARDENED configuration is worse than a miss: it
  // tells the people who did the right thing that they did the wrong one.
  const digest = 'sha256:' + 'a'.repeat(64);
  assert.deepEqual(scanContainer('Dockerfile', `FROM ubuntu@${digest}\nUSER app\n`).map((f) => f.vuln), []);
  assert.deepEqual(scanContainer('Dockerfile', `FROM ubuntu:22.04@${digest}\nUSER app\n`).map((f) => f.vuln), []);
  // The genuinely floating forms must still fire, or the fix above is just a
  // way of switching the rule off.
  assert.ok(scanContainer('Dockerfile', 'FROM ubuntu:latest\nUSER app\n').length > 0);
  assert.ok(scanContainer('Dockerfile', 'FROM ubuntu\nUSER app\n').length > 0);
});
