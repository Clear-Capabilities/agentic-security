// PRD F4.3 — the IaC formats `bench/iac-coverage` measured at zero.
//
// That bench scores VERDICT FLIP: a control counts as covered only when the
// misconfigured variant fires and the hardened variant stays silent. On its
// first run the engine scored 8/14, and the six failures were not spread
// evenly — they were whole formats:
//
//   terraform       4/4      kubernetes      3/4      dockerfile   1/2
//   cloudformation  0/2      bicep           0/1      helm         0/1
//
// Terraform had `iac-terraform.js` and Kubernetes had `k8s-admission.js`.
// CloudFormation, Bicep and Helm values had nothing at all, in either the rule
// set or the file walker — and a CloudFormation template is a `.yaml` that no
// path predicate recognises, so it was never even read.
//
// Every rule here is written to flip. The hardened variant of each control was
// written first and each rule was checked against it, because a rule that fires
// on `AccessControl: Private` as well as `PublicRead` is not detecting the
// control, it is detecting the resource — and a recall-only bench cannot see the
// difference.
//
// Regex over the raw template text, consistent with the rest of this directory:
// no YAML or Bicep parser is added, because `fast-xml-parser` was already
// rejected here on bundle-size and audit-surface grounds and the same argument
// applies. The cost is honest and bounded — deeply nested or heavily
// intrinsic-function'd templates will be missed, and the bench is where that
// shows up.

const ADMIN_PORTS = new Set([22, 23, 3389, 3306, 5432, 6379, 27017, 9200, 1433, 5984]);
const OPEN_CIDRS = /^(?:0\.0\.0\.0\/0|::\/0)$/;

function _line(text, index) { return text.slice(0, index).split('\n').length; }

function _finding(fp, text, index, over) {
  return {
    file: fp,
    line: _line(text, index),
    parser: 'IAC',
    ...over,
  };
}

// ── CloudFormation ──────────────────────────────────────────────────────────

export function isCloudFormationTemplate(relPath, content) {
  if (typeof content !== 'string') return false;
  if (!/\.(?:ya?ml|json)$/i.test(relPath || '')) return false;
  const head = content.length > 65536 ? content.slice(0, 65536) : content;
  if (/AWSTemplateFormatVersion/.test(head)) return true;
  // A template without the (optional) version key is still a template if it
  // declares resources by AWS type. Both signals are required so an ordinary
  // config file mentioning "Resources" is not swept in.
  return /(?:^|\n)\s*Resources\s*:/.test(head) && /Type\s*:\s*["']?AWS::/.test(head);
}

function scanCloudFormation(fp, raw) {
  const out = [];

  // Unrestricted ingress. The port and the CIDR are read from the same ingress
  // block rather than matched independently, so `CidrIp: 0.0.0.0/0` on port 443
  // — which is what a public web listener looks like and is not a finding —
  // does not match.
  const ingressBlock = /-\s*IpProtocol\s*:[\s\S]{0,400}?(?=\n\s*-\s|\n\s*\w+\s*:\s*\n|$)/g;
  let m;
  while ((m = ingressBlock.exec(raw))) {
    const block = m[0];
    const cidr = block.match(/Cidr(?:Ip|Ipv6)\s*:\s*["']?([^\s"',]+)/);
    if (!cidr || !OPEN_CIDRS.test(cidr[1])) continue;
    const from = block.match(/FromPort\s*:\s*["']?(\d+)/);
    const to = block.match(/ToPort\s*:\s*["']?(\d+)/);
    if (!from || !to) continue;
    const lo = Number(from[1]), hi = Number(to[1]);
    const hitsAdmin = [...ADMIN_PORTS].some((p) => p >= lo && p <= hi);
    if (!hitsAdmin) continue;
    out.push(_finding(fp, raw, m.index, {
      id: `cfn-open-ingress:${fp}:${_line(raw, m.index)}`,
      vuln: `CloudFormation security group allows ${cidr[1]} to port ${lo === hi ? lo : `${lo}-${hi}`}`,
      severity: 'high', cwe: 'CWE-284', family: 'iac-network-exposure',
      description: `A SecurityGroupIngress rule opens an administrative port to the whole internet. Anyone who can reach the instance can attempt authentication against it, continuously and from anywhere.`,
      remediation: `Restrict CidrIp to the VPC or office range, or front the port with a bastion / session manager. If public access is genuinely required, say so in the template with a comment so the next reader does not have to guess.`,
      snippet: block.split('\n').slice(0, 6).join('\n').trim().slice(0, 200),
    }));
  }

  // Public object storage. `AccessControl` is the property that grants it; the
  // hardened form sets Private and usually adds a PublicAccessBlockConfiguration.
  const acl = /AccessControl\s*:\s*["']?(PublicRead|PublicReadWrite|AuthenticatedRead)\b/g;
  while ((m = acl.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `cfn-public-bucket:${fp}:${_line(raw, m.index)}`,
      vuln: `CloudFormation bucket grants ${m[1]} access`,
      severity: m[1] === 'PublicReadWrite' ? 'critical' : 'high',
      cwe: 'CWE-732', family: 'iac-public-storage',
      description: `The bucket's canned ACL makes its objects readable${m[1] === 'PublicReadWrite' ? ' AND writable' : ''} by anyone. Public buckets are the single most common cause of accidental data exposure in cloud estates.`,
      remediation: `Set AccessControl: Private and add a PublicAccessBlockConfiguration with BlockPublicAcls and BlockPublicPolicy set to true. Serve public assets through a CDN with an origin access identity instead.`,
      snippet: m[0],
    }));
  }

  // Publicly reachable managed database. The property is unambiguous and the
  // hardened form is the single-word opposite, which is what makes it a good
  // control: there is no judgement call for the rule to get wrong.
  const publicDb = /PubliclyAccessible\s*:\s*["']?true\b/g;
  while ((m = publicDb.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `cfn-public-db:${fp}:${_line(raw, m.index)}`,
      vuln: 'CloudFormation database instance is publicly accessible',
      severity: 'high', cwe: 'CWE-284', family: 'iac-network-exposure',
      description: 'The instance gets a public endpoint, so its authentication is the only thing between the internet and the data. Encryption at rest does not help here — the attacker arrives as a client.',
      remediation: 'Set PubliclyAccessible: false and reach the database from inside the VPC, through a bastion or a private endpoint.',
      snippet: m[0],
    }));
  }

  // Wildcard IAM. Matched on the STATEMENT so that `Action: '*'` with a scoped
  // Resource, or a scoped Action with `Resource: '*'`, do not both have to be
  // present on the same line — YAML puts them on separate ones.
  const stmt = /-\s*Effect\s*:\s*["']?Allow["']?[\s\S]{0,300}?(?=\n\s*-\s*Effect|\n\s{0,6}\w+\s*:\s*\n|$)/g;
  while ((m = stmt.exec(raw))) {
    const block = m[0];
    const wildcardAction = /Action\s*:\s*(?:\[\s*)?["']\*["']/.test(block);
    const wildcardResource = /Resource\s*:\s*(?:\[\s*)?["']\*["']/.test(block);
    if (!wildcardAction || !wildcardResource) continue;
    out.push(_finding(fp, raw, m.index, {
      id: `cfn-iam-wildcard:${fp}:${_line(raw, m.index)}`,
      vuln: 'CloudFormation IAM statement allows Action "*" on Resource "*"',
      severity: 'high', cwe: 'CWE-732', family: 'iac-excessive-privilege',
      description: 'This grants every action on every resource in the account. Any compromise of a principal holding it is a full account compromise, and nothing downstream can constrain it.',
      remediation: 'Enumerate the actions the workload actually calls and scope Resource to the specific ARNs. If the policy is for a break-glass role, keep it out of the default deployment path.',
      snippet: block.split('\n').slice(0, 5).join('\n').trim().slice(0, 200),
    }));
  }

  return out;
}

// ── Bicep ───────────────────────────────────────────────────────────────────

function scanBicep(fp, raw) {
  const out = [];
  let m;

  const publicBlob = /allowBlobPublicAccess\s*:\s*true\b/g;
  while ((m = publicBlob.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `bicep-public-blob:${fp}:${_line(raw, m.index)}`,
      vuln: 'Bicep storage account allows anonymous public blob access',
      severity: 'high', cwe: 'CWE-732', family: 'iac-public-storage',
      description: `allowBlobPublicAccess: true lets containers in this account be configured for anonymous read. The account-level flag is the last line of defence — with it enabled, a single container-level mistake exposes data to the internet.`,
      remediation: `Set allowBlobPublicAccess: false. Grant access with SAS tokens or a managed identity instead; if truly public content is needed, serve it through a CDN endpoint.`,
      snippet: m[0],
    }));
  }

  const plaintextTransit = /supportsHttpsTrafficOnly\s*:\s*false\b/g;
  while ((m = plaintextTransit.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `bicep-http-allowed:${fp}:${_line(raw, m.index)}`,
      vuln: 'Bicep storage account permits unencrypted HTTP traffic',
      severity: 'medium', cwe: 'CWE-319', family: 'iac-transit-encryption',
      description: `supportsHttpsTrafficOnly: false allows clients to reach the account over plain HTTP, so credentials and data can be read by anything on the path.`,
      remediation: 'Set supportsHttpsTrafficOnly: true. There is no compatible client left that requires plain HTTP for this service.',
      snippet: m[0],
    }));
  }

  // An inbound Allow rule whose source is `*` (or the Internet service tag) on
  // an administrative port. Read from the whole rule block so a wildcard source
  // on port 443 — an ordinary public web listener — does not match.
  const nsgRule = /\{[^{}]*?direction\s*:\s*'Inbound'[^{}]*?\}|\{[^{}]*?sourceAddressPrefix[\s\S]{0,400}?\}/g;
  while ((m = nsgRule.exec(raw))) {
    const block = m[0];
    if (!/direction\s*:\s*'Inbound'/i.test(block)) continue;
    if (!/access\s*:\s*'Allow'/i.test(block)) continue;
    const src = block.match(/sourceAddressPrefix\s*:\s*'([^']*)'/);
    if (!src || !/^(?:\*|0\.0\.0\.0\/0|Internet)$/i.test(src[1])) continue;
    const portRange = block.match(/destinationPortRanges?\s*:\s*'?\[?\s*'?([^'\]]*)/);
    const ports = portRange ? portRange[1] : '';
    const hitsAdmin = [...ADMIN_PORTS].some((pnum) => {
      if (new RegExp(`(?:^|[,\\s])${pnum}(?:$|[,\\s])`).test(ports)) return true;
      const range = ports.match(/(\d+)\s*-\s*(\d+)/);
      return !!range && pnum >= Number(range[1]) && pnum <= Number(range[2]);
    });
    if (!hitsAdmin && ports !== '*') continue;
    out.push(_finding(fp, raw, m.index, {
      id: `bicep-nsg-world:${fp}:${_line(raw, m.index)}`,
      vuln: `Bicep network security rule allows inbound from "${src[1]}" to port ${ports || '*'}`,
      severity: 'high', cwe: 'CWE-284', family: 'iac-network-exposure',
      description: 'An inbound Allow rule with a wildcard source exposes an administrative port to the whole internet.',
      remediation: "Set sourceAddressPrefix to the VNet or an office range, or reach the port through a bastion instead.",
      snippet: block.split('\n').slice(0, 6).join('\n').trim().slice(0, 200),
    }));
  }

  const minTls = /minimumTlsVersion\s*:\s*['"]TLS1_0['"]/g;
  while ((m = minTls.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `bicep-weak-tls:${fp}:${_line(raw, m.index)}`,
      vuln: 'Bicep resource accepts TLS 1.0',
      severity: 'medium', cwe: 'CWE-327', family: 'iac-transit-encryption',
      description: 'TLS 1.0 is deprecated and vulnerable to several downgrade and padding-oracle attacks.',
      remediation: "Set minimumTlsVersion: 'TLS1_2'.",
      snippet: m[0],
    }));
  }

  return out;
}

// ── Helm values ─────────────────────────────────────────────────────────────

// A chart's values.yaml is where a workload's defaults live, and a default is
// what most installs actually run. `templates/*.yaml` is deliberately NOT
// handled: it is Go template source, not YAML, and matching text inside `{{ }}`
// would report the template rather than the configuration.
function scanHelmValues(fp, raw) {
  if (!/(?:^|\/)values(?:\.[\w-]+)?\.ya?ml$/i.test(fp)) return [];
  const out = [];
  let m;

  const privileged = /(?:^|\n)\s*privileged\s*:\s*true\b/g;
  while ((m = privileged.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `helm-privileged:${fp}:${_line(raw, m.index)}`,
      vuln: 'Helm chart defaults the workload to privileged execution',
      severity: 'high', cwe: 'CWE-250', family: 'iac-privileged-workload',
      description: `A privileged container has all capabilities and effectively full access to the host. Because this is a chart DEFAULT, every install that does not deliberately override it runs privileged.`,
      remediation: 'Set privileged: false in values.yaml and let an operator opt in explicitly if a workload genuinely needs it.',
      snippet: m[0].trim(),
    }));
  }

  const hostNet = /(?:^|\n)\s*hostNetwork\s*:\s*true\b/g;
  while ((m = hostNet.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `helm-host-network:${fp}:${_line(raw, m.index)}`,
      vuln: 'Helm chart defaults the workload onto the host network',
      severity: 'high', cwe: 'CWE-668', family: 'iac-privileged-workload',
      description: 'A pod on the host network sees every interface on the node, can bind privileged ports, and bypasses NetworkPolicy entirely. As a chart DEFAULT it applies to every install that does not override it.',
      remediation: 'Set hostNetwork: false and expose the workload through a Service.',
      snippet: m[0].trim(),
    }));
  }

  const rootUser = /(?:^|\n)\s*runAsUser\s*:\s*0\b/g;
  while ((m = rootUser.exec(raw))) {
    out.push(_finding(fp, raw, m.index, {
      id: `helm-run-as-root:${fp}:${_line(raw, m.index)}`,
      vuln: 'Helm chart defaults the workload to UID 0 (root)',
      severity: 'medium', cwe: 'CWE-250', family: 'iac-privileged-workload',
      description: 'Running as UID 0 means a container escape starts with root on the node, and any host path mounted into the container is writable.',
      remediation: 'Set runAsNonRoot: true and a non-zero runAsUser, and make the image support it.',
      snippet: m[0].trim(),
    }));
  }

  return out;
}

// ── Dockerfile: base-image pinning ──────────────────────────────────────────

// The bench's `docker-unpinned-base` control. Separate from the existing
// container rules because it is about REPRODUCIBILITY of the supply chain
// rather than what the image contains: `FROM ubuntu:latest` resolves to
// different bytes on different days, so a scan result has no shelf life and a
// compromised upstream tag arrives silently on the next build.
function scanDockerfileBase(fp, raw) {
  const base = (fp.split('/').pop() || '');
  if (!/^(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$/i.test(base) && !/\.dockerfile$/i.test(base)) return [];
  const out = [];
  const from = /(?:^|\n)\s*FROM\s+(\S+)/gi;
  let m;
  while ((m = from.exec(raw))) {
    const ref = m[1];
    if (/^\$\{?\w/.test(ref)) continue;                    // build-arg indirection
    if (ref.includes('@sha256:')) continue;                // pinned by digest — the hardened form
    if (/^scratch$/i.test(ref)) continue;                  // the empty image has no tag
    const tag = ref.includes(':') ? ref.slice(ref.lastIndexOf(':') + 1) : '';
    // A named build stage (`FROM builder`) is an internal reference, not a
    // registry pull.
    if (!tag && !ref.includes('/') && /^[a-z][\w-]*$/i.test(ref) && new RegExp(`AS\\s+${ref}\\b`, 'i').test(raw)) continue;
    const unpinned = !tag || /^latest$/i.test(tag);
    if (!unpinned) continue;
    out.push(_finding(fp, raw, m.index, {
      id: `docker-unpinned-base:${fp}:${_line(raw, m.index)}`,
      vuln: `Base image "${ref}" is not pinned to an immutable reference`,
      severity: 'medium', cwe: 'CWE-1104', family: 'iac-unpinned-base',
      description: `A mutable tag resolves to different bytes over time, so this build is not reproducible and a scan of it has no shelf life. If the upstream tag is ever republished — accidentally or maliciously — the change arrives on the next build with nothing to notice it.`,
      remediation: `Pin by digest: FROM ${ref.split(':')[0]}@sha256:<digest>. Keep the human-readable tag in a comment so the next reader knows which release it is.`,
      snippet: m[0].trim(),
    }));
  }
  return out;
}

// ── Kubernetes: a literal credential in an env value ────────────────────────

// `k8s-admission.js` covers the pod security surface; this is the one control
// the bench found it silent on. A manifest is committed to a repository and
// copied into CI logs and cluster state, so a literal value here is exposed
// several times over.
function scanK8sLiteralSecret(fp, raw) {
  if (!/\.ya?ml$/i.test(fp)) return [];
  if (!/(?:^|\n)\s*kind\s*:/.test(raw)) return [];
  const out = [];
  // `- name: DB_PASSWORD` followed by `value:` — as opposed to `valueFrom:`,
  // which is the hardened form and must not match.
  const envPair = /-\s*name\s*:\s*["']?([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)["']?\s*\n\s*value\s*:\s*["']?([^\s"'#]{6,})/g;
  let m;
  while ((m = envPair.exec(raw))) {
    const value = m[2];
    // A reference or an obvious placeholder is not a leak.
    if (/^\$[({]/.test(value)) continue;
    if (/^(?:changeme|placeholder|example|your[-_]|todo|replace)/i.test(value)) continue;
    out.push(_finding(fp, raw, m.index, {
      id: `k8s-literal-secret:${fp}:${_line(raw, m.index)}`,
      vuln: `Kubernetes manifest sets ${m[1]} to a literal value`,
      severity: 'high', cwe: 'CWE-798', family: 'iac-literal-credential',
      description: `The credential is committed to the repository, copied into CI logs, and stored in cluster state in plaintext. Rotating it means editing and redeploying the manifest, which is why it usually does not happen.`,
      remediation: 'Use valueFrom.secretKeyRef and keep the value in a Secret managed outside the repository. Rotate the exposed credential — treat it as compromised.',
      snippet: `- name: ${m[1]}\n  value: ${value.slice(0, 4)}••••`,
    }));
  }
  return out;
}

/** All template-format IaC rules for one file. */
export function scanCloudTemplates(fp, raw) {
  if (!fp || typeof raw !== 'string' || !raw) return [];
  const out = [];
  if (/\.bicep$/i.test(fp)) out.push(...scanBicep(fp, raw));
  if (isCloudFormationTemplate(fp, raw)) out.push(...scanCloudFormation(fp, raw));
  out.push(...scanHelmValues(fp, raw));
  out.push(...scanDockerfileBase(fp, raw));
  out.push(...scanK8sLiteralSecret(fp, raw));
  return out;
}
