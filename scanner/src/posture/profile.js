// Persona profile: vibecoder | pro
// Loaded from .agentic-security/profile.yml. Used everywhere a default differs
// by audience (rendering verbosity, confidence threshold, command visibility,
// suppression schema, integration set, etc.).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { statePath, safeWriteState, resolveProjectRoot } from './state-dir.js';

export const PROFILES = ['vibecoder', 'pro'];

export const DEFAULTS = {
  vibecoder: {
    profile: 'vibecoder',
    confidenceMin: 0.9,         // hide low-confidence findings
    showTaxonomy: false,         // no CWE/CVSS/STRIDE/OWASP/MITRE in default output
    severityFloor: 'high',       // by default only show high+critical
    commandTier: 'primary',      // /help shows ~5 commands
    suppression: 'soft',         // accepted.json, 30-day, no reviewer required
    machineOutput: false,        // don't write SARIF/JSON unless asked
    onboardingPrompts: true,
    showAttribution: true,
  },
  pro: {
    profile: 'pro',
    confidenceMin: 0.3,          // show all but the lowest-signal findings
    showTaxonomy: true,           // CWE/CVSS/STRIDE/OWASP/MITRE visible by default
    severityFloor: 'low',         // show everything down to info
    commandTier: 'all',           // /help shows all commands
    suppression: 'audit',         // suppressions.yml, requires reason+reviewer+expiry
    machineOutput: true,          // SARIF + JSON every scan
    onboardingPrompts: false,
    showAttribution: true,
  },
};

function _profilePath(scanRoot) {
  return statePath(scanRoot, 'profile.yml');
}

export function loadProfile(scanRoot) {
  const fp = _profilePath(scanRoot);
  let parsed = {};
  try {
    if (fs.existsSync(fp)) {
      parsed = yaml.load(fs.readFileSync(fp, 'utf8')) || {};
    }
  } catch (_) { /* fall through */ }
  const name = PROFILES.includes(parsed.profile) ? parsed.profile : 'vibecoder';
  return { ...DEFAULTS[name], ...parsed, profile: name };
}

export function saveProfile(scanRoot, updates) {
  const fp = _profilePath(scanRoot);
  const current = loadProfile(scanRoot);
  const next = { ...current, ...updates };
  const defaults = DEFAULTS[next.profile];
  const out = {};
  for (const k of Object.keys(next)) {
    if (defaults[k] === next[k]) continue;
    out[k] = next[k];
  }
  if (!('profile' in out)) out.profile = next.profile;
  safeWriteState(fp, yaml.dump(out));
  return next;
}

// Detect profile heuristically from project state when no profile.yml exists.
// Returns 'pro' if the repo has signals indicating professional security work,
// otherwise 'vibecoder'. Run only on first scan.
export function detectProfile(scanRoot) {
  const root = resolveProjectRoot(scanRoot);
  const signals = ['SECURITY.md', '.github/workflows/security.yml', '.semgrep.yml',
                   '.snyk', 'codeql-config.yml', 'compliance/', 'docs/threat-model.md'];
  for (const s of signals) {
    if (fs.existsSync(path.join(root, s))) return 'pro';
  }
  // Repos with `security` or `compliance` in package.json description → pro.
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    if (/security|compliance|appsec|pentest/i.test(pkg.description || '')) return 'pro';
  } catch (_) { /* no pkg or unreadable */ }
  return 'vibecoder';
}

export const ATTRIBUTION = 'agentic-security · created by ClearCapabilities.Com';
export const ATTRIBUTION_URL = 'https://clearcapabilities.com';

export function renderAttributionLine() {
  return `🛡  ${ATTRIBUTION}  ·  ${ATTRIBUTION_URL}`;
}
