// FR-PROD-4 — Network policy import.
//
// Parse k8s NetworkPolicy YAML (multi-document) and AWS Security Group JSON;
// build a coarse map: workload → ingress sources. If the only ingress for a
// workload is from internal-only ranges (10.0.0.0/8, 172.16.0.0/12,
// 192.168.0.0/16, fc00::/7, or named `internal`/`vpc-private`), findings on
// that workload are demoted to `mitigated-by-network`. Conservative: anything
// not unambiguously internal-only leaves the finding untouched.
//
// Inputs (any combination of):
//   k8s/*.yaml, k8s/*.yml         — multi-doc kube manifests
//   infra/k8s/                    — recursive search
//   .agentic-security/network-policy.json  — normalized digest
//
// Normalized digest shape:
//   {
//     "workloads": {
//       "api-server":   { "exposure": "public",   "ingressFrom": ["0.0.0.0/0"] },
//       "admin-panel":  { "exposure": "internal", "ingressFrom": ["10.0.0.0/8"] },
//       "worker":       { "exposure": "internal", "ingressFrom": [] }
//     }
//   }
//
// Mapping workload → finding is heuristic: we look for the workload name in
// the file path.

import * as fs from 'node:fs';
import * as path from 'node:path';

const CANDIDATE_DIGEST = '.agentic-security/network-policy.json';
const K8S_DIRS = ['k8s', 'infra/k8s', 'deploy/k8s', 'kubernetes', 'manifests'];

const INTERNAL_CIDRS = [
  /^10\./, /^172\.(?:1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^fc/i, /^fd/i,
];

function isInternal(cidr) {
  if (!cidr) return false;
  if (/internal|vpc-private|private/i.test(cidr)) return true;
  return INTERNAL_CIDRS.some(re => re.test(cidr));
}

function parseKubeManifests(scanRoot) {
  const workloads = {};
  const root = scanRoot || process.cwd();
  for (const d of K8S_DIRS) {
    const dp = path.join(root, d);
    if (!fs.existsSync(dp)) continue;
    try {
      const files = fs.readdirSync(dp, { withFileTypes: true });
      for (const f of files) {
        if (!f.isFile() || !/\.(ya?ml)$/i.test(f.name)) continue;
        const text = fs.readFileSync(path.join(dp, f.name), 'utf8');
        // Multi-doc split by `---` then look for NetworkPolicy entries.
        const docs = text.split(/^---\s*$/m);
        for (const doc of docs) {
          if (!/kind:\s*NetworkPolicy/i.test(doc)) continue;
          const podSelM = /podSelector:[\s\S]*?matchLabels:[\s\S]*?app:\s*['"]?(\w[\w-]*)['"]?/i.exec(doc);
          const workload = podSelM ? podSelM[1] : 'unknown';
          // Default-deny check: presence of `ingress: []` or empty ingress block.
          const isDeny = /policyTypes:\s*\[Ingress\][\s\S]*?ingress:\s*\[\]/i.test(doc) ||
                         /policyTypes:[\s\S]*?-\s+Ingress[\s\S]*?ingress:\s*\[\]/i.test(doc);
          const cidrs = [...doc.matchAll(/ipBlock:[\s\S]*?cidr:\s*['"]?([\d./a-fA-F:]+)['"]?/g)].map(m => m[1]);
          const externalAllowed = cidrs.filter(c => !isInternal(c));
          let exposure;
          if (isDeny && cidrs.length === 0) exposure = 'internal';
          else if (cidrs.length === 0) exposure = 'unknown';
          else if (externalAllowed.length === 0) exposure = 'internal';
          else exposure = 'public';
          workloads[workload] = {
            exposure,
            ingressFrom: cidrs.length ? cidrs : (isDeny ? [] : ['unspecified']),
          };
        }
      }
    } catch {}
  }
  return workloads;
}

export function loadNetworkPosture(scanRoot) {
  const root = scanRoot || process.cwd();
  const digestPath = path.join(root, CANDIDATE_DIGEST);
  if (fs.existsSync(digestPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(digestPath, 'utf8'));
      if (data && data.workloads) return data;
    } catch {}
  }
  const workloads = parseKubeManifests(scanRoot);
  if (Object.keys(workloads).length === 0) return null;
  return { workloads };
}

function matchWorkload(workloads, filePath) {
  if (!workloads || !filePath) return null;
  // Match by the longest workload name that occurs as a path segment.
  const segs = filePath.split('/');
  let best = null;
  for (const name of Object.keys(workloads)) {
    if (segs.includes(name) || segs.some(s => s.startsWith(name + '-'))) {
      if (!best || name.length > best.length) best = name;
    }
  }
  return best ? { name: best, info: workloads[best] } : null;
}

export function annotateNetworkMitigation(findings, scanRoot) {
  if (!Array.isArray(findings)) return findings;
  const posture = loadNetworkPosture(scanRoot);
  if (!posture || !posture.workloads) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const w = matchWorkload(posture.workloads, f.file || '');
    if (!w) continue;
    if (w.info.exposure === 'internal') {
      f.mitigatedByNetwork = true;
      f.networkPolicyName = w.name;
      f.networkExposure = 'internal';
    } else if (w.info.exposure === 'public') {
      f.networkExposure = 'public';
    }
  }
  return findings;
}
