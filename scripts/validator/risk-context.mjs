#!/usr/bin/env node
// Render a risk-context block for ONE finding by pulling all available
// signals out of .agentic-security/last-scan.json.
//
// Usage: risk-context.js <finding-id>
// Output: a formatted block to stdout suitable for inclusion in a verdict.

import * as fs from 'node:fs';
import * as path from 'node:path';

const id = process.argv[2];
if (!id) { console.error('Usage: risk-context.js <finding-id>'); process.exit(2); }

const scanPath = path.join(process.cwd(), '.agentic-security', 'last-scan.json');
if (!fs.existsSync(scanPath)) { console.error('No .agentic-security/last-scan.json — run /scan first.'); process.exit(2); }
let scan;
try { scan = JSON.parse(fs.readFileSync(scanPath, 'utf8')); } catch (e) { console.error('Cannot parse scan:', e.message); process.exit(2); }

const findings = [...(scan.findings || []), ...(scan.logicVulns || []), ...(scan.supplyChain || []), ...(scan.secrets || [])];
const f = findings.find(x => x.id === id);
if (!f) { console.error(`Finding ${id} not found in last-scan.json`); process.exit(1); }

// Pull route data
const routes = scan.routes || [];
const fileOf = f.file || f.sink?.file || '';
const route = routes.find(r => r.file === fileOf && Math.abs((r.line||0) - (f.sink?.line||f.line||0)) <= 80);

// Severity / scores
const sev = (f.severity || '').toUpperCase().padEnd(8);
const triage = f.triageScore != null ? `${f.triageScore}/100 (${f.triageLabel || '?'})` : 'n/a';
const tox = f.toxicityScore != null ? `${f.toxicityScore}/100 (${f.toxicityLabel || '?'})` : 'n/a';

// Compliance mapping for common CWEs
const COMPLIANCE_MAP = {
  'CWE-89':  ['OWASP ASVS V5.3.4', 'PCI 6.2.4', 'NIST AC-3'],
  'CWE-78':  ['OWASP ASVS V5.3.8', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-79':  ['OWASP ASVS V5.3.3', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-22':  ['OWASP ASVS V5.3.7', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-611': ['OWASP ASVS V5.5.2', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-918': ['OWASP ASVS V5.2.6', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-639': ['OWASP ASVS V4.2.1', 'PCI 7.1', 'NIST AC-3'],
  'CWE-502': ['OWASP ASVS V5.5.1', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-94':  ['OWASP ASVS V5.2.5', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-327': ['OWASP ASVS V6.2.1', 'PCI 4.1', 'NIST SC-13'],
  'CWE-916': ['OWASP ASVS V6.2.1', 'PCI 3.5.1', 'NIST SC-13'],
  'CWE-798': ['OWASP ASVS V2.10.4', 'PCI 8.2.1', 'NIST IA-5'],
  'CWE-862': ['OWASP ASVS V4.1.1', 'PCI 7.1', 'NIST AC-3'],
  'CWE-863': ['OWASP ASVS V4.1.3', 'PCI 7.2', 'NIST AC-3'],
  'CWE-352': ['OWASP ASVS V4.2.2', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-601': ['OWASP ASVS V5.1.5', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-1321': ['OWASP ASVS V5.5.3', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-917': ['OWASP ASVS V5.3.10', 'PCI 6.2.4', 'NIST SI-10'],
  'CWE-841': ['NIST SI-10'],
  'CWE-345': ['OWASP ASVS V4.1.1'],
  'CWE-190': ['OWASP ASVS V5.2.7'],
};

const compliance = COMPLIANCE_MAP[f.cwe] || [];

// Data classification
const dataClasses = route?.classifications || [];

// KEV / EPSS for SCA findings
const isSCA = f.type === 'vulnerable_dep' || f.osvId;
const kev = f.kev ? 'YES — actively abused' : (isSCA ? 'no' : 'n/a');
const epss = (typeof f.epssScore === 'number') ? `${Math.round(f.epssScore * 100)}%` : 'n/a';

// Reachability
const reach = f.reachable === true ? 'yes (called from route)' :
              f.reachable === false ? 'no (unused / orphan)' :
              f.routeRooted ? 'route-rooted' : 'unknown';

// Render
const out = [
  'Risk context',
  `  Severity:        ${sev} Triage: ${triage}   Toxicity: ${tox}`,
  `  Reachability:    ${reach}`,
  `  Route:           ${route ? `${route.method} ${route.path}` : 'n/a'}`,
  `  Data classes:    ${dataClasses.length ? dataClasses.join(', ') : 'none classified'}`,
  `  CWE:             ${f.cwe || 'n/a'}    STRIDE: ${f.stride || 'n/a'}`,
  `  Compliance:      ${compliance.length ? compliance.join(', ') : 'n/a'}`,
  `  KEV:             ${kev}    EPSS: ${epss}`,
];
process.stdout.write(out.join('\n') + '\n');
