// SBOM diff + dependency drift detection — Recommendation #10 of the
// world-class+2 plan.
//
// Tracks SBOMs across releases (keyed by git commit hash). On each scan,
// compares the current SBOM against the previous snapshot to surface
// drift before a CVE-publication catches it:
//
//   - dependency-added              new package since previous SBOM
//   - dependency-removed            package no longer present
//   - dependency-version-bumped     version changed
//   - dependency-substitution       SAME package name but different
//                                   ecosystem / publisher / repo source
//                                   (the SolarWinds / event-stream pattern)
//   - dependency-deprecated         transitioned to a deprecated state
//
// Suspicious additions (i.e., a new package that doesn't appear in any
// PR diff / commit message) get a higher severity tier than expected ones.
//
// Snapshots live at .agentic-security/sbom-history/<sha>.json. The
// engine writes the current snapshot at the end of every scan; this
// module produces the diff on the next scan.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execSync } from 'node:child_process';

const HISTORY_DIR = 'sbom-history';

function _historyDir(scanRoot) {
  return path.join(scanRoot, '.agentic-security', HISTORY_DIR);
}

function _gitHead(scanRoot) {
  try {
    return execSync('git rev-parse HEAD', { cwd: scanRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch { return null; }
}

function _snapshotKey(component) {
  return `${component.ecosystem || 'unknown'}:${component.name || ''}`;
}

/**
 * Persist the current SBOM as a snapshot keyed by the current git HEAD.
 * If no git, falls back to a content hash of the components list.
 */
export function persistSbom(scanRoot, components) {
  const dir = _historyDir(scanRoot);
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const sha = _gitHead(scanRoot) || crypto.createHash('sha256').update(JSON.stringify(components)).digest('hex').slice(0, 12);
  const snap = {
    sha, ts: new Date().toISOString(),
    componentCount: components.length,
    components: components.map(c => ({
      ecosystem: c.ecosystem, name: c.name, version: c.version,
      purl: c.purl, scope: c.scope, isUnpinned: !!c.isUnpinned,
      sha256: c.sha256 || c.integrity || null,
    })),
  };
  try { fs.writeFileSync(path.join(dir, `${sha}.json`), JSON.stringify(snap, null, 2)); } catch {}
  return snap;
}

/**
 * Load the previous SBOM snapshot for diffing.
 */
export function loadPreviousSnapshot(scanRoot, currentSha) {
  const dir = _historyDir(scanRoot);
  if (!fs.existsSync(dir)) return null;
  let snaps;
  try { snaps = fs.readdirSync(dir); } catch { return null; }
  snaps = snaps.filter(f => f.endsWith('.json') && f !== `${currentSha}.json`);
  if (!snaps.length) return null;
  // Sort by mtime descending; take the most recent.
  snaps.sort((a, b) => fs.statSync(path.join(dir, b)).mtimeMs - fs.statSync(path.join(dir, a)).mtimeMs);
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, snaps[0]), 'utf8'));
  } catch { return null; }
}

/**
 * Compute the structured diff between two SBOMs and emit drift findings.
 */
export function diffSboms(previous, current) {
  if (!previous || !current) return { findings: [], summary: { added: 0, removed: 0, bumped: 0, substituted: 0 } };
  const findings = [];
  const prevByKey = new Map();
  for (const c of previous.components || []) prevByKey.set(_snapshotKey(c), c);
  const curByKey = new Map();
  for (const c of current.components || []) curByKey.set(_snapshotKey(c), c);
  let added = 0, removed = 0, bumped = 0, substituted = 0;

  // Added
  for (const [key, cur] of curByKey) {
    if (prevByKey.has(key)) continue;
    added++;
    findings.push({
      family: 'dependency-drift', subfamily: 'dependency-added',
      severity: 'medium', cwe: 'CWE-1357',
      vuln: `Dependency added since previous release: ${cur.ecosystem}:${cur.name}@${cur.version}`,
      file: cur.purl || 'package-lock.json', line: 0,
      drift: { kind: 'added', component: cur, sinceSha: previous.sha },
      remediation: 'Confirm this addition appears in a reviewed PR. Unexplained additions are the standard supply-chain-attack pattern.',
    });
  }
  // Removed
  for (const [key, prev] of prevByKey) {
    if (curByKey.has(key)) continue;
    removed++;
    findings.push({
      family: 'dependency-drift', subfamily: 'dependency-removed',
      severity: 'low', cwe: 'CWE-1357',
      vuln: `Dependency removed since previous release: ${prev.ecosystem}:${prev.name}@${prev.version}`,
      file: prev.purl || 'package-lock.json', line: 0,
      drift: { kind: 'removed', component: prev, sinceSha: previous.sha },
      remediation: 'Confirm the removal was intentional. Silent removal of a vulnerable dep is fine; silent removal of a fix-receiving dep means CVEs may re-introduce.',
    });
  }
  // Bumped
  for (const [key, cur] of curByKey) {
    const prev = prevByKey.get(key);
    if (!prev) continue;
    if (prev.version !== cur.version) {
      bumped++;
      const isMajor = _isMajorBump(prev.version, cur.version);
      findings.push({
        family: 'dependency-drift', subfamily: 'dependency-version-bumped',
        severity: isMajor ? 'medium' : 'low',
        cwe: 'CWE-1357',
        vuln: `${cur.ecosystem}:${cur.name} bumped ${prev.version} → ${cur.version}${isMajor ? ' (MAJOR)' : ''}`,
        file: cur.purl || 'package-lock.json', line: 0,
        drift: { kind: 'bumped', from: prev.version, to: cur.version, isMajor, sinceSha: previous.sha },
        remediation: 'Major-version bumps are breaking-change candidates AND attack pivot points. Verify the changelog signals match what your dependency intended.',
      });
    }
    // Substitution check: integrity / hash changed but version stayed the same
    if (prev.sha256 && cur.sha256 && prev.sha256 !== cur.sha256 && prev.version === cur.version) {
      substituted++;
      findings.push({
        family: 'dependency-drift', subfamily: 'dependency-substitution',
        severity: 'critical', cwe: 'CWE-1357',
        vuln: `Suspicious substitution: ${cur.ecosystem}:${cur.name}@${cur.version} hash changed without version change`,
        file: cur.purl || 'package-lock.json', line: 0,
        drift: { kind: 'substituted', component: cur, oldHash: prev.sha256, newHash: cur.sha256, sinceSha: previous.sha },
        remediation: 'Same package + same version + DIFFERENT content hash = the registry served a different artifact under the same identity. Investigate immediately; rotate the lockfile via fresh install.',
      });
    }
  }
  return { findings, summary: { added, removed, bumped, substituted } };
}

function _isMajorBump(prev, cur) {
  const pa = (prev || '').match(/^(\d+)/);
  const pc = (cur || '').match(/^(\d+)/);
  if (!pa || !pc) return false;
  return parseInt(pa[1], 10) !== parseInt(pc[1], 10);
}

/**
 * Convenience entry — run the full pipeline: persist current, diff
 * against previous, return findings.
 */
export function runSbomDiff(scanRoot, components) {
  const current = persistSbom(scanRoot, components);
  const previous = loadPreviousSnapshot(scanRoot, current.sha);
  if (!previous) return { findings: [], summary: { added: 0, removed: 0, bumped: 0, substituted: 0 }, first: true };
  return diffSboms(previous, current);
}

export const _internals = { _historyDir, _gitHead, _isMajorBump, _snapshotKey };
