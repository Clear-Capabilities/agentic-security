// Attack-taxonomy annotator — Item #8 of the world-class+3 plan.
//
// Stamps every finding with the relevant standard-taxonomy IDs so that
// downstream SIEM/SOAR systems can correlate scanner findings with their
// existing detection rules, threat intel, and defensive coverage.
//
// Annotations added:
//
//   attck       — MITRE ATT&CK Enterprise / Mobile technique IDs (e.g. "T1190")
//   attckName   — human-readable name (e.g. "Exploit Public-Facing Application")
//   atlas       — MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
//                 technique IDs for ML/AI findings (e.g. "AML.T0043")
//   d3fend      — MITRE D3FEND countermeasure IDs (e.g. "D3-RFS")
//   attckTactic — MITRE ATT&CK Enterprise tactic (initial-access |
//                 execution | persistence | privilege-escalation | etc.)
//   capec       — Common Attack Pattern Enumeration & Classification ID
//
// No exploit generation, no PoC synthesis — those are already covered by
// poc-generator / exploit-bundle / three-agent-pipeline / security-poc-
// generator / security-chain-synthesizer.
//
// Mappings are curated. Coverage is reported via summary; unmapped families
// remain unannotated rather than guessed.
//
// Opt-out: AGENTIC_SECURITY_NO_ATTACK_TAX=1

// ── Mapping table (family → taxonomy IDs) ──────────────────────────────────
//
// Sources:
//   ATT&CK     attack.mitre.org/techniques/enterprise/  (v15.1)
//   ATLAS      atlas.mitre.org  (Jan 2025 release)
//   D3FEND     d3fend.mitre.org (v0.16)
//   CAPEC      capec.mitre.org

const FAMILY_MAP = {
  // ── Injection / RCE ──────────────────────────────────────────────────────
  'sqli':                       { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IAA'], attckTactic: 'exploitation', capec: ['CAPEC-66'] },
  'sql-injection':              { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IAA'], attckTactic: 'exploitation', capec: ['CAPEC-66'] },
  'xss':                        { attck: ['T1059.007'], attckName: 'Command and Scripting Interpreter: JavaScript', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-63'] },
  'mutation-xss':               { attck: ['T1059.007'], attckName: 'Command and Scripting Interpreter: JavaScript', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-63'] },
  'command-injection':          { attck: ['T1059.004'], attckName: 'Command and Scripting Interpreter: Unix Shell', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-88'] },
  'code-injection':             { attck: ['T1059'], attckName: 'Command and Scripting Interpreter', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-242'] },
  'deserialization':            { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-586'] },
  'ldap-injection':             { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IAA'], attckTactic: 'exploitation', capec: ['CAPEC-136'] },
  'xpath-injection':            { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IAA'], attckTactic: 'exploitation', capec: ['CAPEC-83'] },
  'nosql-injection':            { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IAA'], attckTactic: 'exploitation', capec: ['CAPEC-676'] },
  'jndi':                       { attck: ['T1190', 'T1059'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-242'] },
  'ssti':                       { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-94'] },

  // ── Auth / authZ ─────────────────────────────────────────────────────────
  'auth-missing':               { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'initial-access', capec: ['CAPEC-115'] },
  'authz':                      { attck: ['T1078.004'], attckName: 'Valid Accounts: Cloud Accounts', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'idor':                       { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'mass-assignment':            { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-IVV'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'jwt-exp':                    { attck: ['T1550.001'], attckName: 'Use Alternate Authentication Material: Application Access Token', d3fend: ['D3-ANET'], attckTactic: 'defense-evasion', capec: ['CAPEC-593'] },
  'csrf':                       { attck: ['T1059.007'], attckName: 'Command and Scripting Interpreter: JavaScript', d3fend: ['D3-ITF'], attckTactic: 'execution', capec: ['CAPEC-62'] },
  'tx-origin-auth':             { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-94'] },
  'signature-replay':           { attck: ['T1550.001'], attckName: 'Use Alternate Authentication Material: Application Access Token', d3fend: ['D3-ANET'], attckTactic: 'defense-evasion', capec: ['CAPEC-60'] },
  'erc4337-validation':         { attck: ['T1550'], attckName: 'Use Alternate Authentication Material', d3fend: ['D3-ANET'], attckTactic: 'defense-evasion', capec: ['CAPEC-115'] },

  // ── Crypto ───────────────────────────────────────────────────────────────
  'crypto-weak-cipher':         { attck: ['T1573.001'], attckName: 'Encrypted Channel: Symmetric Cryptography', d3fend: ['D3-CH'], attckTactic: 'defense-evasion', capec: ['CAPEC-475'] },
  'crypto-weak-hash':           { attck: ['T1110.002'], attckName: 'Brute Force: Password Cracking', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-461'] },
  'crypto-ecb':                 { attck: ['T1573.001'], attckName: 'Encrypted Channel: Symmetric Cryptography', d3fend: ['D3-CH'], attckTactic: 'defense-evasion', capec: ['CAPEC-475'] },
  'crypto-static-iv':           { attck: ['T1573.001'], attckName: 'Encrypted Channel: Symmetric Cryptography', d3fend: ['D3-CH'], attckTactic: 'defense-evasion', capec: ['CAPEC-475'] },
  'crypto-tls-version':         { attck: ['T1557.002'], attckName: 'Adversary-in-the-Middle: ARP Cache Poisoning', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-94'] },
  'crypto-tls-no-verify':       { attck: ['T1557'], attckName: 'Adversary-in-the-Middle', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-94'] },
  'crypto-jwt-none':            { attck: ['T1550.001'], attckName: 'Use Alternate Authentication Material: Application Access Token', d3fend: ['D3-ANET'], attckTactic: 'defense-evasion', capec: ['CAPEC-593'] },
  'crypto-jwt-key-confusion':   { attck: ['T1550.001'], attckName: 'Use Alternate Authentication Material: Application Access Token', d3fend: ['D3-ANET'], attckTactic: 'defense-evasion', capec: ['CAPEC-593'] },
  'crypto-kdf-weak':            { attck: ['T1110.002'], attckName: 'Brute Force: Password Cracking', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-49'] },
  'crypto-weak-rng':            { attck: ['T1518.001'], attckName: 'Software Discovery', d3fend: ['D3-CH'], attckTactic: 'discovery', capec: ['CAPEC-485'] },
  'pqc-migration':              { attck: ['T1573'], attckName: 'Encrypted Channel', d3fend: ['D3-CH'], attckTactic: 'defense-evasion', capec: ['CAPEC-475'] },

  // ── Supply chain / SCA ───────────────────────────────────────────────────
  'vulnerable-dependency':      { attck: ['T1195.001'], attckName: 'Supply Chain Compromise: Compromise Software Dependencies and Development Tools', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },
  'dependency-confusion':       { attck: ['T1195.002'], attckName: 'Supply Chain Compromise: Compromise Software Supply Chain', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-538'] },
  'dependency-drift':           { attck: ['T1195'], attckName: 'Supply Chain Compromise', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },
  'license-graph':              { attck: ['T1195'], attckName: 'Supply Chain Compromise', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },

  // ── Secrets / credentials ────────────────────────────────────────────────
  'secret':                     { attck: ['T1552.001'], attckName: 'Unsecured Credentials: Credentials In Files', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-117'] },
  'hardcoded-secret':           { attck: ['T1552.001'], attckName: 'Unsecured Credentials: Credentials In Files', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-117'] },
  'aws-no-mfa':                 { attck: ['T1078.004'], attckName: 'Valid Accounts: Cloud Accounts', d3fend: ['D3-MFA'], attckTactic: 'initial-access', capec: ['CAPEC-115'] },
  'rpc-key-inline':             { attck: ['T1552.001'], attckName: 'Unsecured Credentials: Credentials In Files', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-117'] },

  // ── Cloud / IAM ──────────────────────────────────────────────────────────
  'aws-public-s3':              { attck: ['T1530'], attckName: 'Data from Cloud Storage', d3fend: ['D3-ACL'], attckTactic: 'collection', capec: ['CAPEC-186'] },
  'aws-public-trust':           { attck: ['T1078.004'], attckName: 'Valid Accounts: Cloud Accounts', d3fend: ['D3-ANCI'], attckTactic: 'initial-access', capec: ['CAPEC-122'] },
  'aws-passrole-wildcard':      { attck: ['T1098.001'], attckName: 'Account Manipulation: Additional Cloud Credentials', d3fend: ['D3-ANCI'], attckTactic: 'persistence', capec: ['CAPEC-122'] },
  'aws-overbroad-managed':      { attck: ['T1098.001'], attckName: 'Account Manipulation: Additional Cloud Credentials', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'gcp-public-binding':         { attck: ['T1530'], attckName: 'Data from Cloud Storage', d3fend: ['D3-ACL'], attckTactic: 'collection', capec: ['CAPEC-186'] },
  'gcp-owner-overuse':          { attck: ['T1098.001'], attckName: 'Account Manipulation: Additional Cloud Credentials', d3fend: ['D3-ANCI'], attckTactic: 'persistence', capec: ['CAPEC-122'] },
  'azure-auth-wildcard':        { attck: ['T1098.003'], attckName: 'Account Manipulation: Additional Cloud Roles', d3fend: ['D3-ANCI'], attckTactic: 'persistence', capec: ['CAPEC-122'] },
  'azure-owner-sub':            { attck: ['T1098.003'], attckName: 'Account Manipulation: Additional Cloud Roles', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'iam-overpermissive':         { attck: ['T1098.001'], attckName: 'Account Manipulation: Additional Cloud Credentials', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },

  // ── Kubernetes ───────────────────────────────────────────────────────────
  'k8s-rbac-cluster-admin':     { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'k8s-rbac-anonymous':         { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'initial-access', capec: ['CAPEC-115'] },
  'k8s-rbac-wildcard':          { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'k8s-rbac-overbroad-binding': { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'privilege-escalation', capec: ['CAPEC-122'] },
  'k8s-pod-security-privileged':{ attck: ['T1611'], attckName: 'Escape to Host', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-441'] },
  'k8s-pod-security-hostnetwork': { attck: ['T1610'], attckName: 'Deploy Container', d3fend: ['D3-PSEP'], attckTactic: 'lateral-movement', capec: ['CAPEC-441'] },
  'k8s-pod-security-hostpid':   { attck: ['T1611'], attckName: 'Escape to Host', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-441'] },
  'k8s-pod-security-hostipc':   { attck: ['T1611'], attckName: 'Escape to Host', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-441'] },
  'k8s-pod-security-hostpath':  { attck: ['T1611'], attckName: 'Escape to Host', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-441'] },
  'k8s-pod-security-allow-privesc': { attck: ['T1068'], attckName: 'Exploitation for Privilege Escalation', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-69'] },
  'k8s-pod-security-run-as-root':   { attck: ['T1068'], attckName: 'Exploitation for Privilege Escalation', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-69'] },
  'k8s-pod-security-capabilities-broad': { attck: ['T1611'], attckName: 'Escape to Host', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-441'] },
  'k8s-webhook-bypass':         { attck: ['T1562.001'], attckName: 'Impair Defenses: Disable or Modify Tools', d3fend: ['D3-PA'], attckTactic: 'defense-evasion', capec: ['CAPEC-180'] },

  // ── Web3 ─────────────────────────────────────────────────────────────────
  'reentrancy':                 { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IVV'], attckTactic: 'exploitation', capec: ['CAPEC-26'] },
  'defi-no-slippage':           { attck: ['T1565.001'], attckName: 'Data Manipulation: Stored Data Manipulation', d3fend: ['D3-IVV'], attckTactic: 'impact', capec: ['CAPEC-176'] },
  'defi-spot-price-oracle':     { attck: ['T1565.001'], attckName: 'Data Manipulation: Stored Data Manipulation', d3fend: ['D3-IVV'], attckTactic: 'impact', capec: ['CAPEC-176'] },
  'upgradeable-init':           { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IVV'], attckTactic: 'exploitation', capec: ['CAPEC-26'] },
  'ecdsa-malleability':         { attck: ['T1550.001'], attckName: 'Use Alternate Authentication Material: Application Access Token', d3fend: ['D3-CH'], attckTactic: 'defense-evasion', capec: ['CAPEC-475'] },
  'unlimited-approval':         { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ACL'], attckTactic: 'collection', capec: ['CAPEC-122'] },
  'eth-sign-used':              { attck: ['T1550.001'], attckName: 'Use Alternate Authentication Material: Application Access Token', d3fend: ['D3-CH'], attckTactic: 'defense-evasion', capec: ['CAPEC-94'] },
  'private-key-in-frontend':    { attck: ['T1552.001'], attckName: 'Unsecured Credentials: Credentials In Files', d3fend: ['D3-CH'], attckTactic: 'credential-access', capec: ['CAPEC-117'] },

  // ── SSRF / XXE / IDOR / open redirect ────────────────────────────────────
  'ssrf':                       { attck: ['T1090.001'], attckName: 'Proxy: Internal Proxy', d3fend: ['D3-NTA'], attckTactic: 'discovery', capec: ['CAPEC-664'] },
  'ssrf-cloud-metadata':        { attck: ['T1552.005'], attckName: 'Unsecured Credentials: Cloud Instance Metadata API', d3fend: ['D3-NTA'], attckTactic: 'credential-access', capec: ['CAPEC-664'] },
  'xxe':                        { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IAA'], attckTactic: 'exploitation', capec: ['CAPEC-221'] },
  'open-redirect':              { attck: ['T1204.001'], attckName: 'User Execution: Malicious Link', d3fend: ['D3-IDA'], attckTactic: 'initial-access', capec: ['CAPEC-178'] },
  'path-traversal':             { attck: ['T1083'], attckName: 'File and Directory Discovery', d3fend: ['D3-IDA'], attckTactic: 'discovery', capec: ['CAPEC-126'] },
  'zip-slip':                   { attck: ['T1083'], attckName: 'File and Directory Discovery', d3fend: ['D3-IDA'], attckTactic: 'discovery', capec: ['CAPEC-130'] },
  'race-condition':             { attck: ['T1068'], attckName: 'Exploitation for Privilege Escalation', d3fend: ['D3-PSA'], attckTactic: 'privilege-escalation', capec: ['CAPEC-25'] },
  'host-header':                { attck: ['T1190'], attckName: 'Exploit Public-Facing Application', d3fend: ['D3-IDA'], attckTactic: 'exploitation', capec: ['CAPEC-105'] },

  // ── LLM / AI / MCP ───────────────────────────────────────────────────────
  // ATLAS-mapped where appropriate; ATT&CK provides the closest enterprise mapping.
  'llm-app-security':           { attck: ['T1059'], attckName: 'Command and Scripting Interpreter', atlas: ['AML.T0051.000'], atlasName: 'LLM Prompt Injection: Direct', d3fend: ['D3-IDA'], attckTactic: 'execution', capec: ['CAPEC-242'] },
  'training-data-pii':          { attck: ['T1530'], attckName: 'Data from Cloud Storage', atlas: ['AML.T0034'], atlasName: 'Cost Harvesting', d3fend: ['D3-CH'], attckTactic: 'collection', capec: ['CAPEC-118'] },
  'prompt-injection':           { attck: ['T1059'], attckName: 'Command and Scripting Interpreter', atlas: ['AML.T0051.000'], atlasName: 'LLM Prompt Injection: Direct', d3fend: ['D3-IDA'], attckTactic: 'execution', capec: ['CAPEC-242'] },
  'agent-tool-exec':            { attck: ['T1059'], attckName: 'Command and Scripting Interpreter', atlas: ['AML.T0050'], atlasName: 'Command and Scripting Interpreter', d3fend: ['D3-IDA'], attckTactic: 'execution', capec: ['CAPEC-242'] },
  'hf-datasets-rce':            { attck: ['T1195.001'], attckName: 'Supply Chain Compromise: Compromise Software Dependencies and Development Tools', atlas: ['AML.T0010'], atlasName: 'ML Supply Chain Compromise: ML Software', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },
  'mlflow-untrusted-uri':       { attck: ['T1195'], attckName: 'Supply Chain Compromise', atlas: ['AML.T0010.003'], atlasName: 'ML Supply Chain Compromise: Model', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },
  'onnx-providers':             { attck: ['T1583.006'], attckName: 'Acquire Infrastructure: Web Services', atlas: ['AML.T0011'], atlasName: 'Acquire Public ML Artifacts', d3fend: ['D3-SBV'], attckTactic: 'resource-development', capec: ['CAPEC-437'] },
  'streaming-dataset-url':      { attck: ['T1195'], attckName: 'Supply Chain Compromise', atlas: ['AML.T0019'], atlasName: 'Publish Poisoned Datasets', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },
  'prompt-integrity':           { attck: ['T1059'], attckName: 'Command and Scripting Interpreter', atlas: ['AML.T0051.000'], atlasName: 'LLM Prompt Injection: Direct', d3fend: ['D3-IDA'], attckTactic: 'execution', capec: ['CAPEC-242'] },
  'gradio-auth':                { attck: ['T1078'], attckName: 'Valid Accounts', d3fend: ['D3-ANCI'], attckTactic: 'initial-access', capec: ['CAPEC-115'] },
  'hf-endpoint-override':       { attck: ['T1583.006'], attckName: 'Acquire Infrastructure: Web Services', atlas: ['AML.T0010'], atlasName: 'ML Supply Chain Compromise: ML Software', d3fend: ['D3-SBV'], attckTactic: 'resource-development', capec: ['CAPEC-437'] },
  'model-format':               { attck: ['T1195.001'], attckName: 'Supply Chain Compromise: Compromise Software Dependencies and Development Tools', atlas: ['AML.T0010.003'], atlasName: 'ML Supply Chain Compromise: Model', d3fend: ['D3-SBV'], attckTactic: 'initial-access', capec: ['CAPEC-437'] },

  // ── Mobile ───────────────────────────────────────────────────────────────
  'mobile-debuggable':          { attck: ['T1404'], attckName: 'Exploitation for Privilege Escalation (Mobile)', d3fend: ['D3-PSEP'], attckTactic: 'privilege-escalation', capec: ['CAPEC-69'] },
  'mobile-exported-component':  { attck: ['T1421'], attckName: 'System Network Configuration Discovery (Mobile)', d3fend: ['D3-NTA'], attckTactic: 'discovery', capec: ['CAPEC-125'] },
};

// Family aliases — different detectors use slightly different family names
// for the same underlying concept. Map them to a canonical family before lookup.
const FAMILY_ALIAS = {
  'sql':                     'sqli',
  'sql-inj':                 'sqli',
  'xss-reflected':           'xss',
  'xss-stored':              'xss',
  'cmd-injection':           'command-injection',
  'cmd-i':                   'command-injection',
  'rce':                     'code-injection',
  'pickle-rce':              'deserialization',
  'java-deserialization':    'deserialization',
  'pq-migration':            'pqc-migration',
  'sca-vuln':                'vulnerable-dependency',
  'sca':                     'vulnerable-dependency',
  'license':                 'license-graph',
  'cloud-iam-overpermissive': 'iam-overpermissive',
  'http-no-tls':             'crypto-tls-version',
};

function _canonical(family) {
  if (!family) return null;
  const f = String(family).toLowerCase();
  return FAMILY_ALIAS[f] || f;
}

// ── Annotator ──────────────────────────────────────────────────────────────

export function annotateAttackTaxonomy(findings) {
  if (process.env.AGENTIC_SECURITY_NO_ATTACK_TAX === '1') return { annotated: 0, total: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { annotated: 0, total: 0 };
  let annotated = 0;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const canon = _canonical(f.family);
    const map = canon ? FAMILY_MAP[canon] : null;
    if (!map) continue;
    f.attck = map.attck;
    f.attckName = map.attckName;
    if (map.atlas) {
      f.atlas = map.atlas;
      f.atlasName = map.atlasName;
    }
    f.d3fend = map.d3fend;
    f.attckTactic = map.attckTactic;
    f.capec = map.capec;
    annotated++;
  }
  return { annotated, total: findings.length };
}

// ── Summary helper (consumed by report layer / MCP explain_finding) ───────

export function summarizeTaxonomy(findings) {
  const attckCount = new Map();
  const atlasCount = new Map();
  const attckTacticCount = new Map();
  const unmapped = new Set();
  for (const f of findings || []) {
    if (Array.isArray(f.attck)) for (const t of f.attck) attckCount.set(t, (attckCount.get(t) || 0) + 1);
    if (Array.isArray(f.atlas)) for (const t of f.atlas) atlasCount.set(t, (atlasCount.get(t) || 0) + 1);
    if (f.attckTactic) attckTacticCount.set(f.attckTactic, (attckTacticCount.get(f.attckTactic) || 0) + 1);
    if (f.family && !f.attck) unmapped.add(f.family);
  }
  return {
    attckTechniques: Object.fromEntries([...attckCount].sort((a, b) => b[1] - a[1])),
    atlasTechniques: Object.fromEntries([...atlasCount].sort((a, b) => b[1] - a[1])),
    attckTacticDistribution: Object.fromEntries([...attckTacticCount]),
    unmappedFamilies: [...unmapped],
    coverageRatio: findings && findings.length
      ? (findings.filter(f => f.attck).length / findings.length).toFixed(3)
      : '0.000',
  };
}

export const _internals = { FAMILY_MAP, FAMILY_ALIAS, _canonical };
