// Curated rule packs. Each pack is a focused view of the engine's findings
// based on a CWE allowlist. Activated via `--pack <name>` on the CLI.
//
// Packs do not change *detection* — they filter the scan output to the rules
// the user wants to focus on, and optionally bump severity for matching rules.

export const PACKS = {
  'owasp-top-10': {
    description: 'OWASP Top 10 (2021) — A01 through A10',
    cwes: [
      // A01 Broken Access Control
      'CWE-22', 'CWE-200', 'CWE-269', 'CWE-284', 'CWE-352', 'CWE-639', 'CWE-732', 'CWE-862', 'CWE-863',
      // A02 Cryptographic Failures
      'CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323', 'CWE-324',
      'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331', 'CWE-335',
      'CWE-336', 'CWE-337', 'CWE-338', 'CWE-340', 'CWE-347', 'CWE-523', 'CWE-720', 'CWE-757',
      'CWE-759', 'CWE-760', 'CWE-780', 'CWE-818', 'CWE-916',
      // A03 Injection
      'CWE-20', 'CWE-74', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-83', 'CWE-87', 'CWE-88', 'CWE-89',
      'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-98', 'CWE-99',
      'CWE-100', 'CWE-113', 'CWE-116', 'CWE-138', 'CWE-184', 'CWE-470', 'CWE-471', 'CWE-564',
      'CWE-610', 'CWE-643', 'CWE-644', 'CWE-652', 'CWE-917', 'CWE-1336', 'CWE-1427',
      // A04 Insecure Design
      'CWE-209', 'CWE-256', 'CWE-501', 'CWE-522',
      // A05 Security Misconfiguration
      'CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16', 'CWE-260', 'CWE-315', 'CWE-520',
      'CWE-526', 'CWE-537', 'CWE-541', 'CWE-547', 'CWE-611', 'CWE-614', 'CWE-756', 'CWE-776',
      'CWE-942', 'CWE-1004', 'CWE-1032', 'CWE-1174',
      // A06 Vulnerable and Outdated Components
      'CWE-937', 'CWE-1035', 'CWE-1104',
      // A07 Identification and Authentication Failures
      'CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-295', 'CWE-297',
      'CWE-300', 'CWE-302', 'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384', 'CWE-521',
      'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798',
      // A08 Software and Data Integrity Failures
      'CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829',
      'CWE-830', 'CWE-915',
      // A09 Security Logging and Monitoring Failures
      'CWE-117', 'CWE-223', 'CWE-532', 'CWE-778',
      // A10 Server-Side Request Forgery
      'CWE-918',
    ],
  },

  'cwe-top-25': {
    description: 'CWE Top 25 Most Dangerous Software Weaknesses (2023)',
    cwes: [
      'CWE-787', 'CWE-79', 'CWE-89', 'CWE-416', 'CWE-78', 'CWE-20', 'CWE-125', 'CWE-22',
      'CWE-352', 'CWE-434', 'CWE-862', 'CWE-476', 'CWE-287', 'CWE-190', 'CWE-502', 'CWE-77',
      'CWE-119', 'CWE-798', 'CWE-918', 'CWE-306', 'CWE-362', 'CWE-269', 'CWE-94', 'CWE-863',
      'CWE-276',
    ],
  },

  'llm-security': {
    description: 'LLM / agent / prompt-injection risks (OWASP LLM Top 10)',
    cwes: [
      'CWE-20',    // Improper Input Validation (prompts)
      'CWE-74',    // Injection family
      'CWE-77',    // Command Injection (via tools)
      'CWE-78',    // OS Command Injection (via tools)
      'CWE-79',    // XSS (LLM-generated output)
      'CWE-94',    // Code Injection
      'CWE-200',   // Information Disclosure (model leakage)
      'CWE-285',   // Improper Authorization (over-privileged agents)
      'CWE-285',
      'CWE-352',   // CSRF (agent state)
      'CWE-494',   // Download of Code Without Integrity Check (model weights)
      'CWE-502',   // Insecure Deserialization (pickle / torch.load)
      'CWE-732',   // Incorrect Permission Assignment (MCP tools)
      'CWE-798',   // Hardcoded credentials (in prompts / tools)
      'CWE-918',   // SSRF (LLM-controlled requests)
      'CWE-1336',  // Improper Neutralization of Special Elements (template injection)
      'CWE-1357',  // Reliance on Insufficiently Trustworthy Component
      'CWE-1427',  // LLM prompt injection (CWE assigned 2025)
    ],
  },

  'supply-chain': {
    description: 'Dependency vulnerabilities, dep-confusion, pipeline & container risks',
    cwes: [
      'CWE-494',   // Download of Code Without Integrity Check
      'CWE-502',   // Insecure Deserialization
      'CWE-532',   // Insertion of Sensitive Information into Log File
      'CWE-693',   // Protection Mechanism Failure
      'CWE-829',   // Inclusion of Functionality from Untrusted Control Sphere
      'CWE-830',   // Inclusion of Web Functionality from Untrusted Source
      'CWE-915',   // Improperly Controlled Modification of Dynamically-Determined Object Attributes
      'CWE-937',   // Using Components with Known Vulnerabilities
      'CWE-1035',  // OWASP A06 — Vulnerable and Outdated Components
      'CWE-1104',  // Use of Unmaintained Third-Party Components
      'CWE-1188',  // Insecure Default Initialization of Resource
      'CWE-1336',  // Template Injection
      'CWE-1357',  // Reliance on Insufficiently Trustworthy Component
      'CWE-272',   // Least Privilege Violation (CI permissions)
      'CWE-78',    // OS Command Injection (CI script injection)
    ],
  },
};

export function listPacks() {
  return Object.entries(PACKS).map(([name, p]) => ({
    name,
    description: p.description,
    cweCount: p.cwes.length,
  }));
}

export function loadPack(name) {
  const p = PACKS[name];
  if (!p) {
    const known = Object.keys(PACKS).join(', ');
    throw new Error(`Unknown pack "${name}". Known: ${known}`);
  }
  return { name, ...p };
}

// Return the set of CWE IDs covered by the given pack names.
// Multiple packs union their CWE sets.
export function packsCweSet(names) {
  const set = new Set();
  for (const n of names) {
    const p = loadPack(n);
    for (const c of p.cwes) set.add(c);
  }
  return set;
}

// Filter a scan object's findings/secrets/supplyChain arrays to those whose CWE
// is present in the union of `packNames`' CWE sets. Returns a new scan object.
// If `packNames` is empty/falsy, returns the scan unchanged.
export function applyPacks(scan, packNames) {
  if (!packNames || !packNames.length) return scan;
  const cwes = packsCweSet(packNames);
  const keep = (f) => f && f.cwe && cwes.has(f.cwe);
  return {
    ...scan,
    findings: (scan.findings || []).filter(keep),
    secrets: (scan.secrets || []).filter(keep),
    logicVulns: (scan.logicVulns || []).filter(keep),
    supplyChain: (scan.supplyChain || []).filter(keep),
  };
}
