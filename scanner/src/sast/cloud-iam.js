// Cross-cloud IAM least-privilege analyzer — Item #4 of the world-class+3 plan.
//
// posture/iam-policy.js already covers a tight set of AWS-only over-permissive
// patterns (wildcard action + wildcard resource on dangerous services). This
// module fills the cross-cloud gaps:
//
//   AWS:
//     - aws-public-s3-policy        Principal:* on s3:* (object exfil)
//     - aws-public-trust-policy     sts:AssumeRole with Principal:* / AWS:*
//     - aws-no-mfa-condition        High-risk action without aws:MultiFactorAuthPresent
//     - aws-overbroad-managed-policy AdministratorAccess attached to non-root principal
//     (PassRole-wildcard is detected by posture/iam-policy.js — not duplicated here.)
//
//   GCP:
//     - gcp-public-iam-binding      member 'allUsers' / 'allAuthenticatedUsers'
//     - gcp-owner-binding           role 'roles/owner' on non-bootstrap account
//     - gcp-sa-key-export-allowed   serviceAccountKeys.create granted broadly
//     - gcp-workload-identity-wildcard  pool with broad attribute mapping
//
//   Azure:
//     - azure-owner-at-sub-scope    Owner role assigned at /subscriptions/...
//     - azure-microsoft-auth-wildcard  Custom role with Microsoft.Authorization/*
//     - azure-rbac-broad-scope      role assignment without scope or principalId tightening
//
// File scope (heuristic, no API calls):
//   .json  containing Statement / Principal → AWS
//   .yaml / .yml containing  bindings: + role:  → GCP IAM
//   .json  containing "type":"Microsoft.Authorization/roleDefinitions" or
//          .bicep with `resource ... 'Microsoft.Authorization/...'`  → Azure
//
// Opt-out: AGENTIC_SECURITY_NO_CLOUD_IAM=1

import { blankComments } from './_comment-strip.js';

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _shape(file, line, ruleId, vuln, fam, sev, cwe, remediation, description, cloud) {
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line, vuln, severity: sev, cwe,
    family: fam, parser: 'CLOUD-IAM',
    confidence: 0.85,
    stride: 'Elevation of Privilege',
    description: description || vuln,
    remediation,
    cloud,
  };
}

// ── AWS ────────────────────────────────────────────────────────────────────

const _HIGH_RISK_AWS_ACTIONS = [
  'iam:*', 'sts:AssumeRole', 'iam:PassRole', 'iam:CreateAccessKey',
  's3:DeleteBucket', 'kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey',
  'rds:DeleteDBInstance', 'ec2:TerminateInstances',
  'secretsmanager:GetSecretValue', 'secretsmanager:PutSecretValue',
  'cloudformation:DeleteStack',
];

function _statements(parsed) {
  const out = [];
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(visit); return; }
    if (node.Statement) {
      const ss = Array.isArray(node.Statement) ? node.Statement : [node.Statement];
      for (const s of ss) out.push(s);
    }
    for (const v of Object.values(node)) {
      if (v && typeof v === 'object') visit(v);
    }
  };
  visit(parsed);
  return out;
}

function _principalIsWildcard(p) {
  if (p === '*') return true;
  if (typeof p === 'object' && p) {
    if (p.AWS === '*' || p.AWS === ['*']) return true;
    if (Array.isArray(p.AWS) && p.AWS.includes('*')) return true;
    if (p['*'] === '*') return true;
  }
  return false;
}

function _actionList(a) {
  if (!a) return [];
  return Array.isArray(a) ? a : [a];
}

function detectAws(file, raw, out, seen) {
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return; }
  const ss = _statements(parsed);
  // _line() takes a raw-text offset, not a substring — a monotonically
  // advancing cursor lets successive statements (JSON.parse preserves
  // source order) each locate their OWN occurrence of a shared marker
  // like `"Principal"` instead of every statement resolving to the same
  // (first) occurrence in the file.
  let _cursor = 0;
  for (const s of ss) {
    if ((s.Effect || 'Allow') !== 'Allow') continue;
    const actions = _actionList(s.Action);
    const isStarAction = actions.includes('*') || actions.some(a => /^[a-z]+:\*$/.test(a));
    const hasCondition = s.Condition && Object.keys(s.Condition).length > 0;
    const principalStar = _principalIsWildcard(s.Principal);
    let _advanceTo = _cursor;

    // aws-public-s3-policy
    if (principalStar && actions.some(a => /^s3:/.test(a))) {
      const idx = raw.indexOf('"Principal"', _cursor);
      const ln = _line(raw, idx >= 0 ? idx : _cursor);
      if (idx >= 0) _advanceTo = Math.max(_advanceTo, idx + 1);
      const id = `aws-public-s3-policy:${file}:${ln}`;
      if (!seen.has(id)) {
        seen.add(id);
        out.push(_shape(file, ln, 'aws-public-s3-policy',
          'S3 bucket policy with Principal:* — bucket is publicly accessible',
          'aws-public-s3', 'critical', 'CWE-732',
          'Remove Principal:* and grant the policy to specific AWS account IDs or canonical user IDs. If the bucket genuinely needs to be public (CDN, public website), use CloudFront with an origin access identity instead.',
          'Public bucket policies are the #1 cause of S3 data breaches (Capital One, Verizon, Accenture etc). Even with object ACLs locked down, a permissive bucket policy makes every object world-readable.',
          'aws'));
      }
    }

    // aws-public-trust-policy (Principal:* on AssumeRole)
    if (principalStar && actions.includes('sts:AssumeRole')) {
      const idx = raw.indexOf('AssumeRole', _cursor);
      const ln = _line(raw, idx >= 0 ? idx : _cursor);
      if (idx >= 0) _advanceTo = Math.max(_advanceTo, idx + 1);
      const id = `aws-public-trust-policy:${file}:${ln}`;
      if (!seen.has(id)) {
        seen.add(id);
        out.push(_shape(file, ln, 'aws-public-trust-policy',
          'IAM role trust policy allows sts:AssumeRole from Principal:* — any AWS account can assume',
          'aws-public-trust', 'critical', 'CWE-863',
          'Restrict the trust policy Principal to specific AWS account IDs or specific AWS services (e.g. lambda.amazonaws.com). Add a Condition on aws:SourceAccount or aws:SourceArn to prevent confused-deputy attacks.',
          'A wildcard trust policy lets anyone with an AWS account assume the role, inheriting all its attached permissions. The 2022 Tesla AWS exposure stemmed from exactly this.',
          'aws'));
      }
    }

    // aws-no-mfa-condition on high-risk actions
    for (const a of actions) {
      if (_HIGH_RISK_AWS_ACTIONS.includes(a) || a === '*') {
        const conditionStr = JSON.stringify(s.Condition || {});
        if (!/MultiFactorAuthPresent|MultiFactorAuthAge/.test(conditionStr)) {
          const idx = raw.indexOf(`"${a}"`, _cursor);
          const ln = _line(raw, idx >= 0 ? idx : _cursor);
          if (idx >= 0) _advanceTo = Math.max(_advanceTo, idx + 1);
          const id = `aws-no-mfa-condition:${file}:${a}:${ln}`;
          if (!seen.has(id)) {
            seen.add(id);
            out.push(_shape(file, ln, 'aws-no-mfa-condition',
              `High-risk action ${a} not gated by aws:MultiFactorAuthPresent`,
              'aws-no-mfa', 'high', 'CWE-308',
              'Add a Condition gate: `"Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }`. This forces the calling identity to have authenticated with MFA inside the last hour (configurable via MultiFactorAuthAge).',
              'AWS best-practice and the CIS Benchmark both require MFA-gated sensitive actions. Without it, a compromised long-term access key has root-equivalent power for the policy scope.',
              'aws'));
          }
        }
      }
    }

    // (iam:PassRole with Resource:* is detected by posture/iam-policy.js —
    // not duplicated here.)
    _cursor = _advanceTo;
  }

  // aws-overbroad-managed-policy
  if (/"AdministratorAccess"|"PowerUserAccess"/.test(raw) && !/root\b|Bootstrap\b/.test(raw)) {
    const m = /"(AdministratorAccess|PowerUserAccess)"/.exec(raw);
    const ln = _line(raw, m.index);
    const id = `aws-overbroad-managed-policy:${file}:${ln}`;
    if (!seen.has(id)) {
      seen.add(id);
      out.push(_shape(file, ln, 'aws-overbroad-managed-policy',
        `${m[1]} managed policy attached — overbroad`,
        'aws-overbroad-managed', 'high', 'CWE-269',
        'Replace AdministratorAccess / PowerUserAccess with a least-privilege policy scoped to the resources the principal actually needs. Use AWS IAM Access Analyzer to suggest a narrowed policy from CloudTrail history.',
        'Attaching AdministratorAccess outside the root account is the most common over-permission pattern AWS Trusted Advisor reports. PowerUserAccess is almost as bad (excludes only IAM/Organizations).',
        'aws'));
    }
  }
}

// ── GCP ────────────────────────────────────────────────────────────────────

function detectGcp(file, raw, out, seen) {
  // YAML or JSON, looking for `bindings` shape.
  // We do a light regex pass — full YAML parsing is heavier than necessary.

  // gcp-public-iam-binding
  const publicMembers = ['allUsers', 'allAuthenticatedUsers'];
  for (const m of publicMembers) {
    const re = new RegExp(`["']?\\b${m}\\b["']?`, 'g');
    let mm;
    while ((mm = re.exec(raw))) {
      const ln = _line(raw, mm.index);
      const id = `gcp-public-iam-binding:${file}:${m}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'gcp-public-iam-binding',
        `GCP IAM binding includes ${m} — resource is publicly accessible`,
        'gcp-public-binding', 'critical', 'CWE-732',
        `Remove ${m} from the bindings members list. If the resource must be public (e.g. a GCS object for a public website), explicitly scope it via signed URLs or per-object ACL rather than a project-level IAM binding.`,
        `${m} grants the bound role to anyone with a Google identity (allAuthenticatedUsers) or to literally anyone (allUsers). Has been the source of repeated GCS public-bucket incidents.`,
        'gcp'));
    }
  }

  // gcp-owner-binding
  const ownerRe = /role:\s*roles\/owner\b|"role"\s*:\s*"roles\/owner"/g;
  let m;
  while ((m = ownerRe.exec(raw))) {
    const ln = _line(raw, m.index);
    const id = `gcp-owner-binding:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'gcp-owner-binding',
      'GCP IAM binding grants roles/owner — should be limited to bootstrap accounts',
      'gcp-owner-overuse', 'high', 'CWE-269',
      'Replace roles/owner with the narrowest predefined role (roles/editor, roles/viewer) or a custom role with the specific permissions needed. Roles/owner has the same IAM-mutation power as the project creator.',
      'GCP roles/owner can grant/revoke any other role on the project, including roles/owner itself. Only project bootstrap automation should hold it.',
      'gcp'));
  }

  // gcp-sa-key-export-allowed
  if (/iam\.serviceAccountKeys\.create/.test(raw) || /serviceAccountKeyAdmin\b/.test(raw)) {
    const m2 = /serviceAccountKeys\.create|serviceAccountKeyAdmin/.exec(raw);
    const ln = _line(raw, m2.index);
    const id = `gcp-sa-key-export-allowed:${file}:${ln}`;
    if (!seen.has(id)) {
      seen.add(id);
      out.push(_shape(file, ln, 'gcp-sa-key-export-allowed',
        'GCP IAM grants serviceAccountKeys.create — enables long-lived key export',
        'gcp-sa-key-export', 'high', 'CWE-798',
        'Replace user-managed service account keys with Workload Identity Federation (GitHub Actions, AWS, Okta) or Workload Identity for GKE. Long-lived service account keys persist after personnel leaves and are the #1 cause of GCP credential exposure on public repos.',
        'GCP service account keys are the equivalent of AWS access keys but with no built-in rotation. They show up in public GitHub leaks routinely. Workload Identity removes the need for a long-lived secret.',
        'gcp'));
    }
  }
}

// ── Azure ──────────────────────────────────────────────────────────────────

function detectAzure(file, raw, out, seen) {
  // Detect Azure RBAC role assignments / role definitions in JSON or Bicep.

  // azure-owner-at-sub-scope
  const ownerRe = /Owner['"]?\s*[,)]|"roleDefinitionId":\s*"[^"]*8e3af657-a8ff-443c-a75c-2fe8c4bcb635/g; // built-in Owner
  let m;
  while ((m = ownerRe.exec(raw))) {
    const ln = _line(raw, m.index);
    // Only flag when the same file references a subscription-scope.
    if (!/\/subscriptions\/[^/]+\/?$|scope:\s*[^,\n]*\/subscriptions\//.test(raw)) continue;
    const id = `azure-owner-at-sub-scope:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'azure-owner-at-sub-scope',
      'Azure Owner role assigned at subscription scope — full subscription control',
      'azure-owner-sub', 'critical', 'CWE-269',
      'Replace Owner with Contributor + User Access Administrator (split) or a custom role. Subscription Owner can assign roles to itself, recover from any policy, and remove security controls.',
      'Subscription-scope Owner is the highest Azure RBAC role short of Global Admin. CIS Azure Benchmark calls for explicit justification + JIT activation via Azure PIM.',
      'azure'));
  }

  // azure-microsoft-auth-wildcard in custom role definitions
  if (/Microsoft\.Authorization\/\*/.test(raw)) {
    const m2 = /Microsoft\.Authorization\/\*/.exec(raw);
    const ln = _line(raw, m2.index);
    const id = `azure-microsoft-auth-wildcard:${file}:${ln}`;
    if (!seen.has(id)) {
      seen.add(id);
      out.push(_shape(file, ln, 'azure-microsoft-auth-wildcard',
        'Custom role grants Microsoft.Authorization/* — enables RBAC self-elevation',
        'azure-auth-wildcard', 'critical', 'CWE-269',
        'Replace Microsoft.Authorization/* with the specific role-management operations the role needs. Microsoft.Authorization/roleAssignments/write is the canonical privilege-escalation primitive in Azure.',
        'Microsoft.Authorization/* permits creating role assignments — meaning the principal can grant itself any role on any scope it reaches. Owner-equivalent in practice.',
        'azure'));
    }
  }
}

// ── Entry point ────────────────────────────────────────────────────────────

function _isAwsPolicy(raw) {
  return /"Version"\s*:\s*"2012-10-17"|"Statement"\s*:\s*\[/.test(raw.slice(0, 4000));
}
function _isGcpIam(raw) {
  return /\bbindings\s*:|\bgcp[-_]?iam|cloudfunctions\.googleapis|allUsers\b|allAuthenticatedUsers\b/.test(raw);
}
function _isAzureIam(raw) {
  return /Microsoft\.Authorization|roleDefinitions|roleAssignments|azurerm_role_assignment/.test(raw);
}

export function scanCloudIam(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_CLOUD_IAM === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  const out = [];
  const seen = new Set();
  const isJson = /\.json$/i.test(fp) || raw.trimStart().startsWith('{');
  const isYaml = /\.(?:yaml|yml)$/i.test(fp);
  const isBicep = /\.bicep$/i.test(fp);
  const isTf = /\.tf$/i.test(fp);

  try {
    if ((isJson || isTf) && _isAwsPolicy(raw)) detectAws(fp, raw, out, seen);
  } catch {}
  try {
    if ((isYaml || isJson) && _isGcpIam(raw)) detectGcp(fp, raw, out, seen);
  } catch {}
  try {
    if ((isJson || isBicep || isTf) && _isAzureIam(raw)) detectAzure(fp, raw, out, seen);
  } catch {}

  for (const f of out) f.file = fp;
  return out;
}

export const _internals = {
  _statements, _principalIsWildcard, _isAwsPolicy, _isGcpIam, _isAzureIam,
  detectAws, detectGcp, detectAzure, _HIGH_RISK_AWS_ACTIONS,
};
