// Dep-add interception — validate a package about to be installed before
// it lands in node_modules / site-packages / etc.
//
// Checks:
//   1. Is the package known-malicious? (OSV malicious-packages catalog)
//   2. Is the package yanked / unpublished / withdrawn?
//   3. Was it published in the last 7 days? (typosquat-attack indicator)
//   4. Does the name closely match a popular package? (Levenshtein ≤ 2
//      against a curated top-1000 list — typosquat risk)
//   5. Is the package on the project's SCA-policy.yml deny list?
//
// Backed by ~/.claude/agentic-security/osv-cache/ (already populated by
// the engine's SCA pass) plus a bundled top-popular-packages list
// from sca/popular-packages.json.
//
// Intended caller: hooks/pre-bash-guard.js when it spots `npm install <pkg>`,
// `yarn add`, `pnpm add`, `pip install`, `cargo add`, `gem install` etc.

import * as fs from 'node:fs';
import * as path from 'node:path';

const CACHE = path.join(process.env.HOME || '/tmp', '.claude', 'agentic-security', 'osv-cache');
const TYPOSQUAT_LEVENSHTEIN = 2;
const NEW_PACKAGE_WINDOW_DAYS = 7;

function _osvLookup(ecosystem, name) {
  const fp = path.join(CACHE, ecosystem, `${name}.json`);
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

function _levenshtein(a, b) {
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (!al || !bl) return Math.max(al, bl);
  const v0 = new Array(bl + 1);
  for (let i = 0; i <= bl; i++) v0[i] = i;
  for (let i = 0; i < al; i++) {
    let v1 = i + 1;
    for (let j = 0; j < bl; j++) {
      const cost = a[i] === b[j] ? 0 : 1;
      const ins = v1 + 1;
      const del = v0[j + 1] + 1;
      const sub = v0[j] + cost;
      const next = Math.min(ins, del, sub);
      v0[j] = v1;
      v1 = next;
    }
    v0[bl] = v1;
  }
  return v0[bl];
}

function _loadPopular(ecosystem) {
  try {
    const here = path.dirname(new URL(import.meta.url).pathname);
    const fp = path.resolve(here, '..', 'sca', 'popular-packages.json');
    const all = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return all[ecosystem] || [];
  } catch { return []; }
}

function _loadPolicy(scanRoot) {
  const fp = path.join(scanRoot, '.agentic-security', 'sca-policy.yml');
  if (!fs.existsSync(fp)) return { deny: [] };
  try {
    const body = fs.readFileSync(fp, 'utf8');
    const names = [];
    const lines = body.split('\n');
    let inBlock = false;
    let blockIndent = -1;
    for (const ln of lines) {
      if (/^deny\s*:/.test(ln)) { inBlock = true; blockIndent = -1; continue; }
      if (!inBlock) continue;
      if (!ln.trim()) continue;
      const m = ln.match(/^(\s+)-\s+(.*)$/);
      if (!m) {
        if (!/^\s+/.test(ln)) inBlock = false;
        continue;
      }
      const indent = m[1].length;
      if (blockIndent < 0) blockIndent = indent;
      if (indent < blockIndent) { inBlock = false; continue; }
      const val = m[2].trim();
      // Two shapes:  - name: foo   OR   - foo
      const nameMatch = val.match(/^name\s*:\s*['"]?([^'"#\s]+)/);
      if (nameMatch) names.push(nameMatch[1]);
      else if (!/:/.test(val)) names.push(val.replace(/^['"]|['"]$/g, ''));
    }
    return { deny: names };
  } catch { return { deny: [] }; }
}

/**
 * Inspect a single package before install. Returns
 *   { decision: 'allow' | 'review' | 'deny', reasons: [...] }
 */
export function inspectPackage({ ecosystem, name, scanRoot }) {
  const reasons = [];
  let decision = 'allow';

  // 1. Project deny list.
  if (scanRoot) {
    const policy = _loadPolicy(scanRoot);
    if (policy.deny.includes(name)) {
      reasons.push(`Project sca-policy.yml lists ${name} in deny`);
      decision = 'deny';
    }
  }

  // 2. OSV malicious / yanked status from the disk cache.
  const osv = _osvLookup(ecosystem, name);
  if (osv) {
    if (Array.isArray(osv.vulns)) {
      const mal = osv.vulns.filter(v => /malicious/i.test(JSON.stringify(v.aliases || []).concat(JSON.stringify(v.id || ''))) ||
                                        /MAL-/.test(v.id || ''));
      if (mal.length) {
        reasons.push(`OSV catalog marks ${name} as malicious (${mal.map(v => v.id).join(', ')})`);
        decision = 'deny';
      }
    }
    if (osv.withdrawn || osv.yanked) {
      reasons.push(`${name} is withdrawn / yanked from registry`);
      if (decision === 'allow') decision = 'review';
    }
  }

  // 3. New package (potential typosquat).
  if (osv && osv.published) {
    const ageMs = Date.now() - new Date(osv.published).getTime();
    const ageDays = ageMs / 86400000;
    if (ageDays < NEW_PACKAGE_WINDOW_DAYS) {
      reasons.push(`${name} published ${Math.round(ageDays)} day(s) ago — fresh-package risk`);
      if (decision === 'allow') decision = 'review';
    }
  }

  // 4. Typosquat distance.
  const popular = _loadPopular(ecosystem);
  if (popular.length) {
    const closest = popular
      .map(p => ({ p, d: _levenshtein(name.toLowerCase(), p.toLowerCase()) }))
      .filter(x => x.d > 0 && x.d <= TYPOSQUAT_LEVENSHTEIN)
      .sort((a, b) => a.d - b.d)[0];
    if (closest) {
      reasons.push(`Name is ${closest.d} edit(s) from popular package "${closest.p}" — typosquat risk`);
      if (decision === 'allow') decision = 'review';
    }
  }

  return { decision, reasons };
}

/**
 * Parse a shell command line to extract install requests. Returns
 *   [{ ecosystem, name }, ...] for every package that would be installed.
 */
export function parseInstallCommand(cmdline) {
  if (!cmdline) return [];
  const reqs = [];
  // npm / yarn / pnpm
  const npm = cmdline.match(/\b(?:npm\s+install|yarn\s+add|pnpm\s+add)\s+([^\s|;&]+(?:\s+[^\s|;&]+)*)/);
  if (npm) {
    for (const tok of npm[1].split(/\s+/)) {
      if (tok.startsWith('-')) continue;          // flags
      if (tok.startsWith('@types/')) continue;    // type defs are low risk
      const name = tok.replace(/@[\d.^~*<>=].*$/, '').replace(/@latest$/, '');
      if (name) reqs.push({ ecosystem: 'npm', name });
    }
  }
  // pip
  const pip = cmdline.match(/\bpip\s+install\s+([^\s|;&]+(?:\s+[^\s|;&]+)*)/);
  if (pip) {
    for (const tok of pip[1].split(/\s+/)) {
      if (tok.startsWith('-') || tok.startsWith('git+') || tok.startsWith('http')) continue;
      const name = tok.replace(/[<>=!~].*$/, '');
      if (name && name !== '.') reqs.push({ ecosystem: 'pypi', name });
    }
  }
  // gem install
  const gem = cmdline.match(/\bgem\s+install\s+([^\s|;&]+(?:\s+[^\s|;&]+)*)/);
  if (gem) {
    for (const tok of gem[1].split(/\s+/)) {
      if (tok.startsWith('-')) continue;
      reqs.push({ ecosystem: 'rubygems', name: tok });
    }
  }
  // cargo add
  const cargo = cmdline.match(/\bcargo\s+add\s+([^\s|;&]+)/);
  if (cargo) reqs.push({ ecosystem: 'cargo', name: cargo[1].split('@')[0] });
  // go get
  const goget = cmdline.match(/\bgo\s+get\s+([^\s|;&]+)/);
  if (goget) reqs.push({ ecosystem: 'golang', name: goget[1].split('@')[0] });
  return reqs;
}

export const _internals = { _levenshtein, _osvLookup, _loadPopular, _loadPolicy };
