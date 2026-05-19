// FR-PROD-6 — Feature-flag awareness.
//
// When a security finding lives behind a feature-flag check, its real-world
// exposure depends on the flag's rollout state, not on the code itself.
// A flag at 0% rollout is `info`; the same code at 100% is `critical`.
//
// This module recognizes flag-gated code regions for the major providers:
//   - LaunchDarkly (`ldClient.variation`, `useFlag`)
//   - Statsig (`Statsig.checkGate`, `useGate`)
//   - ConfigCat (`configCatClient.getValue`)
//   - Unleash (`unleash.isEnabled`)
//   - OpenFeature (`client.getBooleanValue`)
//   - Vercel Flags (`@vercel/flags`)
//   - Custom env-var flags (`process.env.FEATURE_X === 'true'`)
//
// We tag findings with the gating flag name when detected. Rollout percentage
// can be supplied via `.agentic-security/feature-flag-rollouts.json` (a map
// of flag name → percentage 0..100); if absent, default to 100% (assume the
// flag is on) — fail-open against the security side.

import * as fs from 'node:fs';
import * as path from 'node:path';

const FLAG_PATTERNS = [
  // LaunchDarkly
  [/\bldClient\.variation\s*\(\s*['"`]([^'"`]+)['"`]/g, 'launchdarkly'],
  [/\buseFlag\s*\(\s*['"`]([^'"`]+)['"`]/g, 'launchdarkly'],
  [/\bvariation\s*\(\s*['"`]([^'"`]+)['"`]/g, 'launchdarkly'],
  // Statsig
  [/\bStatsig\.(?:checkGate|getExperiment|getConfig)\s*\(\s*['"`]([^'"`]+)['"`]/g, 'statsig'],
  [/\buseGate\s*\(\s*['"`]([^'"`]+)['"`]/g, 'statsig'],
  // ConfigCat
  [/\bconfigCatClient\.getValue\s*\(\s*['"`]([^'"`]+)['"`]/g, 'configcat'],
  // Unleash
  [/\bunleash\.isEnabled\s*\(\s*['"`]([^'"`]+)['"`]/g, 'unleash'],
  // OpenFeature
  [/\b(?:client|of)\.get(?:Boolean|String|Number)Value\s*\(\s*['"`]([^'"`]+)['"`]/g, 'openfeature'],
  // Vercel
  [/\b(?:flag|getFlag|flags)\s*\(\s*['"`]([^'"`]+)['"`]/g, 'vercel-or-generic'],
  // env-var flags
  [/process\.env\.(FEATURE_[A-Z0-9_]+)\s*===?\s*['"`]?(?:true|1)/g, 'env-var'],
  [/process\.env\.(FF_[A-Z0-9_]+)\s*===?\s*['"`]?(?:true|1)/g, 'env-var'],
];

function loadRollouts(scanRoot) {
  const candidates = [
    '.agentic-security/feature-flag-rollouts.json',
    '.agentic-security/feature-flags.json',
  ];
  for (const rel of candidates) {
    const fp = path.join(scanRoot || process.cwd(), rel);
    try {
      if (fs.existsSync(fp)) {
        const data = JSON.parse(fs.readFileSync(fp, 'utf8'));
        if (data && typeof data === 'object') return data;
      }
    } catch {}
  }
  return null;
}

// Walk every file once and build a map: file → list of { flagName, line, vendor }.
// Cheap regex scan, suitable to call per-scan.
export function detectFlagSites(fileContents) {
  const out = {};
  if (!fileContents || typeof fileContents !== 'object') return out;
  for (const [fp, text] of Object.entries(fileContents)) {
    if (!text || typeof text !== 'string') continue;
    const sample = text.length > 100_000 ? text.slice(0, 100_000) : text;
    const hits = [];
    for (const [re, vendor] of FLAG_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(sample))) {
        const flagName = m[1];
        const line = sample.slice(0, m.index).split('\n').length;
        hits.push({ flagName, vendor, line });
      }
    }
    if (hits.length) out[fp] = hits;
  }
  return out;
}

// For each finding, search ±20 lines around the finding location in its file
// for a flag site. If found, tag with the controlling flag and rollout %.
export function annotateFeatureFlagGating(findings, fileContents, opts = {}) {
  if (!Array.isArray(findings)) return findings;
  const rollouts = opts.rollouts || loadRollouts(opts.scanRoot);
  const sites = detectFlagSites(fileContents || {});
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fp = f.file;
    const ln = f.line || 0;
    if (!fp || !sites[fp]) continue;
    const window = 20;
    const nearby = sites[fp].find(s => Math.abs(s.line - ln) <= window);
    if (!nearby) continue;
    f.featureFlag = nearby.flagName;
    f.featureFlagVendor = nearby.vendor;
    const rollout = rollouts && Object.prototype.hasOwnProperty.call(rollouts, nearby.flagName)
      ? Number(rollouts[nearby.flagName])
      : 100;
    f.featureFlagRollout = Number.isFinite(rollout) ? Math.max(0, Math.min(100, rollout)) : 100;
    if (f.featureFlagRollout === 0) f.featureFlagState = 'gated-off';
    else if (f.featureFlagRollout < 100) f.featureFlagState = 'partial-rollout';
    else f.featureFlagState = 'fully-rolled-out';
  }
  return findings;
}
