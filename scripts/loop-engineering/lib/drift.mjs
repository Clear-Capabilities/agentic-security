// Drift detection (LOOP-004.AC01). At `init` the inputs that define "done" are
// frozen: the PRD bytes, the canonical profile, every protected suite wrapper
// and the trusted controller code itself. While a run is initialised, any change
// to one of them stops the run with a named drift reason. A legitimate change is
// made in the supervising session and takes effect only through an explicit
// `init`, which re-freezes the inputs and, because evidence is bound to the PRD
// digest, the acceptance definition and the watched tree, invalidates the
// evidence that depended on what changed.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, canonicalJson } from './util.mjs';

const LOOP_DIR = fileURLToPath(new URL('..', import.meta.url));

const digestOf = (abs) => { try { return sha256(readFileSync(abs)); } catch { return 'missing'; } };

// The code that decides completion: lib/*.mjs, schemas/*.json, run.mjs and digest.mjs.
let _ctl = null;
export function controllerDigest() {
  const files = [join(LOOP_DIR, 'run.mjs'), join(LOOP_DIR, 'digest.mjs')];
  for (const d of ['lib', 'schemas']) {
    let names = [];
    try { names = readdirSync(join(LOOP_DIR, d)).sort(); } catch { /* absent */ }
    for (const n of names) if (/\.(mjs|json)$/.test(n)) files.push(join(LOOP_DIR, d, n));
  }
  const stamp = files.map((f) => { try { const st = statSync(f); return `${f}:${st.mtimeMs}:${st.size}`; } catch { return `${f}:missing`; } }).join('|');
  if (_ctl && _ctl.stamp === stamp) return _ctl.digest;
  const digest = sha256(files.map((f) => `${relative(LOOP_DIR, f)}\0${digestOf(f)}`).join('\n'));
  _ctl = { stamp, digest };
  return digest;
}

export function protectedFiles(profile) {
  const out = new Set();
  for (const s of Object.values(profile.suites || {})) {
    if (!s.protectedWrapper || s.kind !== 'node-test' || s.notYetRunnable) continue;
    for (const f of s.files || []) out.add(join(s.cwd || '.', f).split('\\').join('/'));
  }
  return [...out].sort();
}

/** What an `init` freezes. */
export function captureFrozenInputs({ repoRoot, prdPath, profile }) {
  const root = resolve(repoRoot);
  return {
    capturedAt: new Date().toISOString(),
    prdPath,
    prdSha256: digestOf(resolve(root, prdPath)),
    profileSha256: sha256(canonicalJson(profile)),
    suiteInputs: Object.fromEntries(protectedFiles(profile).map((f) => [f, digestOf(resolve(root, f))])),
    controllerSha256: controllerDigest(),
  };
}

/**
 * Compare the frozen inputs with the current ones.
 * -> { drifted, reasons: [{ input, path?, detail }] }. A run with no frozen record
 * (created before this control existed) cannot be judged and reports no drift.
 */
export function detectDrift({ repoRoot, frozen, profile }) {
  if (!frozen) return { drifted: false, reasons: [], unfrozen: true };
  const now = captureFrozenInputs({ repoRoot, prdPath: frozen.prdPath, profile: profile || {} });
  const reasons = [];
  if (now.prdSha256 !== frozen.prdSha256) reasons.push({ input: 'prd', path: frozen.prdPath, detail: 'the PRD changed after init' });
  if (profile === null) reasons.push({ input: 'profile', detail: 'the execution profile is missing or unreadable' });
  else if (profile && now.profileSha256 !== frozen.profileSha256) reasons.push({ input: 'profile', detail: 'the execution profile changed after init' });
  for (const [f, sha] of Object.entries(frozen.suiteInputs || {})) {
    const cur = digestOf(resolve(repoRoot, f));
    if (cur !== sha) reasons.push({ input: 'suite-input', path: f, detail: cur === 'missing' ? 'a protected suite wrapper was removed' : 'a protected suite wrapper changed' });
  }
  for (const f of Object.keys(now.suiteInputs || {})) if (!(f in (frozen.suiteInputs || {}))) reasons.push({ input: 'suite-input', path: f, detail: 'a protected suite wrapper was added after init' });
  if (now.controllerSha256 !== frozen.controllerSha256) reasons.push({ input: 'controller', detail: 'the trusted controller code changed after init' });
  return { drifted: reasons.length > 0, reasons };
}

export const driftSummary = (reasons) => reasons.map((r) => `${r.input}${r.path ? ` ${r.path}` : ''}: ${r.detail}`).join('; ');
