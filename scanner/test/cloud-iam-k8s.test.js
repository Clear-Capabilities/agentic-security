// Tests for cloud-iam.js (AWS/GCP/Azure) and k8s-admission.js (RBAC/PodSec/webhooks).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanCloudIam } from '../src/sast/cloud-iam.js';
import { scanK8sAdmission } from '../src/sast/k8s-admission.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const IAM = path.join(__dirname, 'fixtures', 'cloud-iam');
const K8S = path.join(__dirname, 'fixtures', 'k8s-admission');

function read(p) { return fs.readFileSync(p, 'utf8'); }

// ── Cloud IAM ──────────────────────────────────────────────────────────────

test('cloud-iam: AWS Principal:* on s3 flagged as public-bucket', () => {
  const src = read(path.join(IAM, 'vulnerable/aws-public-bucket.json'));
  const out = scanCloudIam('aws-public-bucket.json', src);
  assert.ok(out.some(f => f.family === 'aws-public-s3'),
    `expected aws-public-s3; got ${out.map(f => f.family).join(',')}`);
});

// iam:PassRole + Resource:* is detected by posture/iam-policy.js — not
// duplicated in cloud-iam.

test('cloud-iam: GCP allUsers + roles/owner flagged', () => {
  const src = read(path.join(IAM, 'vulnerable/gcp-public-binding.yaml'));
  const out = scanCloudIam('gcp-public-binding.yaml', src);
  assert.ok(out.some(f => f.family === 'gcp-public-binding'));
  assert.ok(out.some(f => f.family === 'gcp-owner-overuse'));
});

test('cloud-iam: Azure Microsoft.Authorization/* in custom role flagged', () => {
  const src = read(path.join(IAM, 'vulnerable/azure-role.bicep'));
  const out = scanCloudIam('azure-role.bicep', src);
  assert.ok(out.some(f => f.family === 'azure-auth-wildcard'),
    `expected azure-auth-wildcard; got ${out.map(f => f.family).join(',')}`);
});

test('cloud-iam: narrow AWS policy with MFA condition is silent', () => {
  const src = read(path.join(IAM, 'clean/aws-narrow.json'));
  const out = scanCloudIam('aws-narrow.json', src);
  // The clean policy gates s3:GetObject behind MFA. Should not fire
  // aws-public-s3 (no Principal:*) or aws-no-mfa-condition (has the Bool MFA check).
  assert.equal(out.filter(f => f.family === 'aws-public-s3').length, 0);
  assert.equal(out.filter(f => f.family === 'aws-no-mfa').length, 0);
});

// Stage 4 correctness audit: cloud-iam.js's _line(raw, idx) expects idx to be
// a numeric string offset (like every GCP call site correctly passes
// mm.index/m.index) — but 4 AWS call sites pass a string literal instead
// (`"Principal"`, 'AssumeRole', `"${a}"`, m[0]). raw.slice(0, <string>)
// coerces the string to NaN, and slice(0, NaN) always returns '', so
// these findings are always stamped line:1 regardless of where the
// actual statement sits in the file. Because the finding id is
// `${ruleId}:${file}:${line}`, two textually distinct offending
// statements in the same file collapse onto the identical id, and the
// seen.has(id) dedup silently drops the second one — a false negative,
// not merely a wrong line number.
test('cloud-iam: two distinct over-permissive S3 statements in one file both fire (not silently deduped by a shared broken line number)', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Principal: '*', Action: ['s3:GetObject'] },
      { Effect: 'Allow', Principal: '*', Action: ['s3:PutObject'] },
    ],
  };
  const src = JSON.stringify(policy, null, 2);
  const out = scanCloudIam('policy.json', src).filter(f => f.family === 'aws-public-s3');
  assert.equal(out.length, 2, `expected 2 distinct aws-public-s3-policy findings (one per statement); got ${out.length}: ${JSON.stringify(out.map(f => f.id))}`);
  // Real bonus: the line numbers should actually differ, and neither should
  // be the always-wrong fallback of 1.
  const lines = out.map(f => f.line);
  assert.notEqual(lines[0], lines[1], `both findings reported the same line ${lines[0]} — the second statement's true position was never located`);
});

test('cloud-iam: AGENTIC_SECURITY_NO_CLOUD_IAM disables', () => {
  process.env.AGENTIC_SECURITY_NO_CLOUD_IAM = '1';
  try {
    const out = scanCloudIam('aws-public-bucket.json',
      read(path.join(IAM, 'vulnerable/aws-public-bucket.json')));
    assert.equal(out.length, 0);
  } finally { delete process.env.AGENTIC_SECURITY_NO_CLOUD_IAM; }
});

// ── Kubernetes ─────────────────────────────────────────────────────────────

test('k8s-adm: ClusterRoleBinding to cluster-admin via system:authenticated flagged', () => {
  const src = read(path.join(K8S, 'vulnerable/cluster-admin-binding.yaml'));
  const out = scanK8sAdmission('cluster-admin-binding.yaml', src);
  assert.ok(out.some(f => f.family === 'k8s-rbac-cluster-admin'),
    `expected cluster-admin; got ${out.map(f => f.family).join(',')}`);
  assert.ok(out.some(f => f.family === 'k8s-rbac-overbroad-binding'));
});

test('k8s-adm: wildcard verbs/resources/apiGroups all fire', () => {
  const src = read(path.join(K8S, 'vulnerable/wildcard-role.yaml'));
  const out = scanK8sAdmission('wildcard-role.yaml', src);
  const fams = new Set(out.map(f => f.family));
  assert.ok(fams.has('k8s-rbac-wildcard'),
    `expected k8s-rbac-wildcard; got ${[...fams].join(',')}`);
  // All three wildcard checks should fire on the same rule block.
  assert.ok(out.length >= 3, `expected ≥3 wildcard findings, got ${out.length}`);
});

test('k8s-adm: privileged pod fires multiple PodSecurity findings', () => {
  const src = read(path.join(K8S, 'vulnerable/privileged-pod.yaml'));
  const out = scanK8sAdmission('privileged-pod.yaml', src);
  const rules = new Set(out.map(f => f.id.split(':')[0]));
  assert.ok(rules.has('k8s-pod-privileged'));
  assert.ok(rules.has('k8s-pod-hostnetwork'));
  assert.ok(rules.has('k8s-pod-hostpid'));
  assert.ok(rules.has('k8s-pod-allow-privesc'));
  assert.ok(rules.has('k8s-pod-hostpath'));
  assert.ok(rules.has('k8s-pod-capabilities-broad'));
});

test('k8s-adm: ValidatingWebhookConfiguration with failurePolicy: Ignore flagged high', () => {
  const src = read(path.join(K8S, 'vulnerable/webhook-ignore.yaml'));
  const out = scanK8sAdmission('webhook-ignore.yaml', src);
  const fp = out.find(f => f.family === 'k8s-webhook-bypass');
  assert.ok(fp, `expected k8s-webhook-bypass; got ${out.map(f => f.family).join(',')}`);
  assert.equal(fp.severity, 'high');
});

test('k8s-adm: clean Deployment is silent on PodSecurity', () => {
  const src = read(path.join(K8S, 'clean/safe-deployment.yaml'));
  const out = scanK8sAdmission('safe-deployment.yaml', src);
  // No privileged / hostnetwork / hostpath findings.
  const bad = ['k8s-pod-privileged', 'k8s-pod-hostnetwork', 'k8s-pod-hostpath', 'k8s-pod-allow-privesc'];
  for (const id of bad) {
    assert.equal(out.filter(f => f.id.startsWith(id + ':')).length, 0,
      `unexpected ${id} on clean fixture`);
  }
});

test('k8s-adm: AGENTIC_SECURITY_NO_K8S_ADM disables', () => {
  process.env.AGENTIC_SECURITY_NO_K8S_ADM = '1';
  try {
    const out = scanK8sAdmission('privileged-pod.yaml',
      read(path.join(K8S, 'vulnerable/privileged-pod.yaml')));
    assert.equal(out.length, 0);
  } finally { delete process.env.AGENTIC_SECURITY_NO_K8S_ADM; }
});

test('k8s-adm: non-k8s yaml file is silent', () => {
  const out = scanK8sAdmission('docker-compose.yml',
    'version: "3"\nservices:\n  web:\n    image: nginx');
  assert.equal(out.length, 0);
});
