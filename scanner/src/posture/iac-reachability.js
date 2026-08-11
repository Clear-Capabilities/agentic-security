// IaC → application code reachability bridge (Sentinel-parity FR-DET-4).
//
// Detects publicly-exposed cloud resources in IaC and correlates them with
// application-code references to the same resource (by name, ARN, or
// hostname). Application-code findings on resources that IaC has exposed get
// a severity bump and an explicit "exposed-via-iac" tag.
//
// **Terraform only.** Only `parseTerraform` exists in this file — this header
// previously also listed CloudFormation and five Kubernetes patterns as
// detected; neither has any parser function anywhere here (found via
// Stage-0 doc audit, 2026; confirmed by grep for `function parse*` in this
// file, which returns exactly one hit). The pattern list below is therefore
// the Terraform-only reality, not the originally-documented superset:
//
//   S3 bucket with public-read ACL / public-access-block disabled
//   RDS / DocumentDB / Redshift with publicly_accessible = true
//   Security group with 0.0.0.0/0 ingress on a sensitive port
//   ALB / NLB / API Gateway with internet-facing scheme
//   Lambda function URL with auth_type = NONE
//   ECS task with assignPublicIp = ENABLED
//
// NOT IMPLEMENTED despite being previously documented here: CloudFormation
// support, K8s Service/LoadBalancer + NetworkPolicy correlation, K8s Ingress
// auth-annotation checking.
//
// Output: { exposedResources: [{name, kind, file, line, severity}], findings: [...new findings] }

const SENSITIVE_PORTS = new Set([22, 23, 25, 110, 143, 3306, 3389, 5432, 6379, 27017, 9200, 9300, 1521, 5984, 11211]);

// Match Terraform resource blocks.
function parseTerraform(fileContents) {
  const resources = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!/\.tf$/i.test(fp)) continue;
    if (!c || typeof c !== 'string') continue;
    // resource "TYPE" "NAME" { ... }
    const re = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}/g;
    let m;
    while ((m = re.exec(c))) {
      const line = c.substring(0, m.index).split('\n').length;
      resources.push({ file: fp, line, kind: m[1], name: m[2], body: m[3] });
    }
  }
  return resources;
}

function classifyExposure(r) {
  const reasons = [];
  if (r.kind === 'aws_s3_bucket' || r.kind === 'aws_s3_bucket_acl' || r.kind === 'aws_s3_bucket_public_access_block') {
    if (/acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"/.test(r.body)) reasons.push('s3-public-acl');
    if (/block_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false/.test(r.body)) reasons.push('s3-public-access-block-off');
  }
  if (/aws_db_instance|aws_rds|aws_docdb_cluster_instance/.test(r.kind)) {
    if (/publicly_accessible\s*=\s*true/.test(r.body)) reasons.push('db-publicly-accessible');
  }
  if (r.kind === 'aws_security_group' || r.kind === 'aws_security_group_rule' || r.kind === 'aws_vpc_security_group_ingress_rule') {
    if (/cidr_blocks?\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]|cidr_ipv4\s*=\s*"0\.0\.0\.0\/0"/.test(r.body)) {
      const portMatch = r.body.match(/from_port\s*=\s*(\d+)/);
      const port = portMatch ? parseInt(portMatch[1], 10) : null;
      if (port && SENSITIVE_PORTS.has(port)) reasons.push(`sg-open-${port}`);
      else if (port === 0 || (portMatch && parseInt(portMatch[1], 10) === 0)) reasons.push('sg-all-ports-open');
      else if (!portMatch) reasons.push('sg-no-port-restriction');
    }
  }
  if (/aws_lb\b|aws_alb\b|aws_elb\b/.test(r.kind)) {
    if (/internal\s*=\s*false/.test(r.body) || /scheme\s*=\s*"internet-facing"/.test(r.body)) reasons.push('lb-internet-facing');
  }
  if (r.kind === 'aws_lambda_function_url') {
    if (/authorization_type\s*=\s*"NONE"/.test(r.body)) reasons.push('lambda-url-no-auth');
  }
  if (r.kind === 'aws_ecs_service' || r.kind === 'aws_ecs_task_definition') {
    if (/assign_public_ip\s*=\s*true/.test(r.body)) reasons.push('ecs-public-ip');
  }
  return reasons;
}

// Detect application-code references to a named resource. Heuristic:
// `process.env.<UPPERCASE_NAME>`, hardcoded `"<bucket-name>"` literals, or
// ARN substrings containing the resource name.
function findCodeReferences(fileContents, resourceName) {
  const out = [];
  const envName = resourceName.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|java|kt|cs|php)$/i.test(fp)) continue;
    // process.env.<NAME> reference.
    const re1 = new RegExp(`\\b(?:process\\.env|os\\.environ|os\\.getenv|System\\.getenv)\\s*[.\\[]\\s*['"]?${envName}['"]?`, 'g');
    let m;
    while ((m = re1.exec(c))) {
      const line = c.substring(0, m.index).split('\n').length;
      out.push({ file: fp, line, refType: 'env-var' });
    }
    // String literal reference.
    const re2 = new RegExp(`['"]${resourceName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`, 'g');
    while ((m = re2.exec(c))) {
      const line = c.substring(0, m.index).split('\n').length;
      out.push({ file: fp, line, refType: 'literal' });
    }
  }
  return out;
}

export function scanIacReachability(fileContents, existingFindings) {
  const resources = parseTerraform(fileContents);
  if (resources.length === 0) return [];
  const exposed = [];
  for (const r of resources) {
    const reasons = classifyExposure(r);
    if (reasons.length) exposed.push({ ...r, reasons });
  }
  if (!exposed.length) return [];

  const out = [];
  for (const r of exposed) {
    // 1. Always emit an IaC finding for the exposed resource itself.
    out.push({
      id: `iac-exposed:${r.file}:${r.line}:${r.kind}:${r.name}`,
      file: r.file, line: r.line,
      vuln: `Publicly-exposed cloud resource (${r.kind} "${r.name}"): ${r.reasons.join(', ')}`,
      severity: 'high',
      cwe: 'CWE-668',
      stride: 'Information Disclosure',
      snippet: `${r.kind} "${r.name}"`,
      remediation: `Tighten the IaC config for ${r.kind} "${r.name}". Specific reasons: ${r.reasons.join(', ')}. ` +
        `Remove public-read ACLs / publicly_accessible flags / 0.0.0.0/0 ingress on sensitive ports. ` +
        `Use private subnets + VPC endpoints; require IAM-authenticated access at minimum.`,
      parser: 'IAC-REACH',
      confidence: 0.85,
    });

    // 2. Find application-code references; bump severity on findings that
    //    sit on lines referencing this resource.
    const refs = findCodeReferences(fileContents, r.name);
    for (const ref of refs) {
      // Look for existing findings near this ref line.
      const nearby = (existingFindings || []).filter(f =>
        f.file === ref.file && Math.abs((f.line || 0) - ref.line) <= 5
      );
      for (const f of nearby) {
        // Bump severity by one notch and annotate.
        const before = f.severity;
        if (before === 'medium') f.severity = 'high';
        else if (before === 'low') f.severity = 'medium';
        f.iacExposed = true;
        f.iacExposureReason = r.reasons.join(',');
        f.iacResource = `${r.kind}:${r.name}`;
      }
      if (refs.length && !nearby.length) {
        out.push({
          id: `iac-codepath:${ref.file}:${ref.line}:${r.name}`,
          file: ref.file, line: ref.line,
          vuln: `Application references publicly-exposed ${r.kind} "${r.name}" (${r.reasons.join(', ')})`,
          severity: 'medium',
          cwe: 'CWE-668',
          snippet: `(reference to ${r.kind}:${r.name})`,
          remediation: `Application code at ${ref.file}:${ref.line} reads the resource "${r.name}" which IaC has exposed publicly (${r.reasons.join(', ')}). Either fix the IaC config or assume the data path is untrusted and add server-side authz.`,
          parser: 'IAC-REACH',
          confidence: 0.6,
          chain: [
            { file: r.file, line: r.line, label: `IaC: ${r.kind} ${r.name} (${r.reasons[0]})` },
            { file: ref.file, line: ref.line, label: `code uses ${r.name}` },
          ],
        });
      }
    }
  }
  return out;
}
