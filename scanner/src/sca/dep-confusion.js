// 0.9.0 Feat-15: Dependency confusion + typosquat detection (Levenshtein distance against top-1000 npm/PyPI packages).
//
// (a) Typosquat: Levenshtein distance 1–2 from a popular package.
// (b) Confusion: internal-scoped names (`@your-org/...`) that also appear on the
//     public registry — declared via .agentic-security/internal-scopes.yml.
//
// Both checks are local-first; we only consult OSV (already cached) for the
// confusion check when an internal-scoped name appears in the public registry.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from '../util/yaml.js';
import { createRequire } from 'node:module';

import { statePath } from '../posture/state-dir.js';
const _require = createRequire(import.meta.url);
const _POPULAR = (() => {
  try {
    const raw = _require('./popular-packages.json');
    const out = {};
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith('_')) continue;
      out[k] = new Set(v.map(s => s.toLowerCase()));
    }
    return out;
  } catch (_) {
    return null;
  }
})();

// Levenshtein distance with early-exit at maxDistance.
export function levenshtein(a, b, maxDistance = 2) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = Array(b.length + 1).fill(0).map((_, i) => i);
  let curr = Array(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

function _loadInternalScopes(scanRoot) {
  if (!scanRoot) return [];
  for (const name of ['internal-scopes.yml', 'internal-scopes.yaml']) {
    const p = statePath(scanRoot, name);
    if (!fs.existsSync(p)) continue;
    try {
      const doc = yaml.load(fs.readFileSync(p, 'utf8'));
      return Array.isArray(doc?.scopes) ? doc.scopes : [];
    } catch (_) { return []; }
  }
  return [];
}

function _eqEcosystemMap(eco) {
  // Engine uses 'npm' / 'pypi' / etc. — map to popular-packages keys.
  if (eco === 'pypi' || eco === 'pip') return 'pypi';
  return eco;
}

// Run typosquat + confusion checks against a components[] array.
// Returns logicVulns-shaped findings (kind: 'sca').
export function detectDepConfusion(components, scanRoot) {
  if (!_POPULAR) return [];
  const internalScopes = _loadInternalScopes(scanRoot);
  const findings = [];
  const seen = new Set();
  for (const c of components || []) {
    if (!c.name) continue;
    const eco = _eqEcosystemMap(c.ecosystem);
    const popularSet = _POPULAR[eco];
    if (!popularSet) continue;
    const lowerName = c.name.toLowerCase();
    // (1) Typosquat — only run if the dep is NOT itself in the popular set
    if (!popularSet.has(lowerName)) {
      let bestMatch = null, bestDist = 3;
      for (const popular of popularSet) {
        const d = levenshtein(lowerName, popular, 2);
        if (d > 0 && d <= 2 && d < bestDist) { bestMatch = popular; bestDist = d; }
      }
      if (bestMatch) {
        const id = `dep-confusion:${c.ecosystem}:${c.name}@${c.version}:typosquat`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id, kind: 'sca', severity: bestDist === 1 ? 'critical' : 'high',
            vuln: `Possible typosquat: "${c.name}" (1–2 chars from "${bestMatch}")`,
            cwe: 'CWE-1357', stride: 'Tampering',
            // CMP-1 (Stage 6 follow-up): neither finding here set `family`,
            // so both fell through to the generic `vulnerable-dep` default
            // every unset supplyChain finding gets — invisible to any
            // compliance control mapped to the more specific
            // family:dependency-confusion (ccpa.json).
            family: 'dependency-confusion',
            file: c.filePath || 'package.json', line: 0,
            snippet: `${c.ecosystem}:${c.name}@${c.version}`,
            fix: `Verify "${c.name}" is the package you actually meant. The popular package "${bestMatch}" is ${bestDist} edit(s) away — typosquat malware commonly registers names like this. Double-check the publisher, weekly downloads, and recent changes before keeping this dep.`,
            package: c.name, version: c.version, ecosystem: c.ecosystem, levenshteinDistance: bestDist,
          });
        }
      }
    }
    // (2) Internal-scope confusion — declared scope, but published on public registry
    for (const scope of internalScopes) {
      const sc = String(scope).toLowerCase();
      if (lowerName.startsWith(sc + '/') || lowerName === sc) {
        // Heuristic: if this dep was successfully resolved by OSV (i.e. has CVE data),
        // OR if the registry returned ANY metadata for it, it's published publicly —
        // which is the threat. We approximate "published publicly" by
        // assuming if components.parseManifests returned the dep, the user expected it
        // to be installable; the OSV / queryRegistries pipeline upstream determines
        // public availability. Here we just flag it for review.
        const id = `dep-confusion:${c.ecosystem}:${c.name}@${c.version}:scope`;
        if (!seen.has(id)) {
          seen.add(id);
          findings.push({
            id, kind: 'sca', severity: 'high',
            vuln: `Internal-scoped package on public registry: "${c.name}"`,
            cwe: 'CWE-1357', stride: 'Tampering',
            family: 'dependency-confusion',
            file: c.filePath || 'package.json', line: 0,
            snippet: `${c.ecosystem}:${c.name}@${c.version}`,
            fix: `"${c.name}" matches your internal scope "${scope}", but is being resolved from the public registry. Confirm whether your private registry is configured (e.g. .npmrc / .pypirc) — if a public copy exists with the same name an attacker could publish malicious updates and your installs would silently switch.`,
            package: c.name, version: c.version, ecosystem: c.ecosystem,
          });
        }
      }
    }
  }
  return findings;
}
