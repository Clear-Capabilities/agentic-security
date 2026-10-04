// Controlled proof witnesses for Haskell and Nix findings (X-009).
//
// A witness is a small, bounded program that DEMONSTRATES the predicted effect inside the confinement sandbox
// (src/sandbox: writes confined to a temporary root, no network, wall-clock and resource limits, fail-closed when no
// primitive is available). The effect is always the same observable: the witness payload creates the marker file
// `PROVEN` in its working directory. Nothing else counts.
//
// Supported witnesses, stated explicitly:
//
//   nix-shell   A shell script a Nix expression generates (systemd script, build phase). The generated script text is
//               taken from the NIX-003 analysis, the interpolation the finding concerns is replaced by an attacker
//               payload shaped for its shell context and passed through the SAME escaping the Nix code applies
//               (lib.escapeShellArg), and the script is run for real by the host shell. The payload is only shell
//               text: it runs only inside the sandbox, and only `touch PROVEN` is ever asked of it.
//   haskell     Needs a Haskell toolchain (runghc). Without one the result is `unavailable`, which is neither proof
//               nor refutation. This module never installs or downloads a toolchain.
//
// What is NOT proof, ever: a syntax error in the witness, a missing executable, a sandbox that could not start or was
// refused, a timeout or resource limit, or an output cap. Each is reported as `invalid` with its reason and leaves
// the finding's static proof tier unchanged. Only the marker proves; its absence after a clean run is
// `not-reproduced`, which is evidence about THIS witness, not a proof that the code is safe.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runConfined, sandboxAvailable } from '../sandbox/index.js';
import { analyzeNixScripts, SHELL_PLACEHOLDER } from './nix-script-taint.js';

export const WITNESS_VERSION = 'language-witness/1';
export const PROOF_MARKER = 'PROVEN';
export const WITNESS_STATUS = Object.freeze(['reproduced', 'not-reproduced', 'invalid', 'unavailable', 'unsupported']);
const SHELLS = new Set(['bash', 'sh', 'dash', 'ash', 'ksh', 'mksh']);
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_SCRIPT_BYTES = 256 * 1024;

const shEscape = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/** The text one placeholder takes in the generated script, given the Nix-side protection and the shell context. */
export function witnessPayload(context, protection) {
  const cmd = `touch ${PROOF_MARKER}`;
  let raw;
  if (context === 'single') raw = `'; ${cmd}; echo '`;
  else if (context === 'double') raw = `$(${cmd})`;
  else raw = `$(${cmd})`;
  // escapeShellArg(s) wraps in single quotes at EVALUATION time, before the shell ever sees the text. The shell then
  // reads that result inside whatever quote context the script put it in, which is exactly the wrong-context case.
  if (protection === 'escapeShellArg') return shEscape(raw);
  if (protection === 'escapeShellArgs') return shEscape(raw);
  return raw;
}

const placeholderIndexes = (text) => { const out = []; for (let i = 0; i < text.length; i++) if (text[i] === SHELL_PLACEHOLDER) out.push(i); return out; };
const indexOfPosition = (text, line, col) => { let l = 1; let i = 0; while (i < text.length && l < line) { if (text[i] === '\n') l++; i++; } return i + col; };

/**
 * Builds a witness for one flow of one generated script.
 * @param {{script:{generated:string, shell:string|null, attrPath:string, file:string}, flow:{generatedLocation:{line:number,startColumn:number}, context:string, protection:string|null}}} t
 */
export function buildNixScriptWitness({ script, flow }) {
  if (!script || typeof script.generated !== 'string' || !flow || !flow.generatedLocation) return { status: 'unsupported', reason: 'the flow has no generated-script location' };
  const shell = script.shell || 'bash';
  if (!SHELLS.has(shell)) return { status: 'unsupported', reason: `shell "${shell}" is not supported by the witness runner` };
  if (Buffer.byteLength(script.generated) > MAX_SCRIPT_BYTES) return { status: 'unsupported', reason: 'the generated script exceeds the witness size limit' };
  const all = placeholderIndexes(script.generated);
  const at = indexOfPosition(script.generated, flow.generatedLocation.line, flow.generatedLocation.startColumn);
  const ordinal = all.indexOf(at);
  if (ordinal < 0) return { status: 'unsupported', reason: 'the flow location does not match an interpolation in the generated script' };
  const payload = witnessPayload(flow.context, flow.protection);
  let out = ''; let n = 0;
  for (const ch of script.generated) { if (ch === SHELL_PLACEHOLDER) { out += n === ordinal ? payload : 'benign'; n++; } else out += ch; }
  const body = out.replace(/^#!.*\n/, '');
  return { status: 'ready', lang: 'nix-shell', shell, ordinal, attrPath: script.attrPath, file: script.file, payload, code: `${body}\n`, context: flow.context, protection: flow.protection || null };
}

function which(name) {
  for (const d of String(process.env.PATH || '').split(path.delimiter)) { const p = path.join(d, name); try { fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* next */ } }
  return null;
}

/** Runs a witness built by buildNixScriptWitness inside the confinement sandbox. Never throws. */
export function runNixScriptWitness(w, { timeoutMs = DEFAULT_TIMEOUT_MS, force } = {}) {
  const base = { witness: WITNESS_VERSION, lang: 'nix-shell', ran: false, backend: null, marker: PROOF_MARKER };
  if (!w || w.status !== 'ready') return { ...base, status: w && w.status === 'unsupported' ? 'unsupported' : 'invalid', reason: (w && w.reason) || 'no witness' };
  const shellBin = which(w.shell);
  if (!shellBin) return { ...base, status: 'invalid', reason: `executable not found: ${w.shell}` };
  if (!sandboxAvailable()) return { ...base, status: 'invalid', reason: 'no confinement primitive available; refusing to execute' };
  let root;
  try {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'witness-')));
    fs.writeFileSync(path.join(root, 'witness.sh'), w.code, 'utf8');
    // 1. a witness that does not parse proves nothing in either direction
    const syn = runConfined([shellBin, '-n', 'witness.sh'], { root, timeoutMs, force });
    if (syn.status === 'disabled' || syn.status === 'error') return { ...base, backend: syn.backend, status: 'invalid', reason: `the sandbox could not run the syntax check (${syn.backend}): ${String(syn.stderr || '').trim() || 'no detail'}` };
    if (syn.timedOut) return { ...base, backend: syn.backend, status: 'invalid', reason: 'the syntax check exceeded its time budget' };
    if (syn.exitCode !== 0) return { ...base, backend: syn.backend, status: 'invalid', reason: `syntax error in the generated witness: ${String(syn.stderr || '').trim().split('\n')[0] || 'shell rejected it'}` };
    // 2. the real run
    const r = runConfined([shellBin, 'witness.sh'], { root, timeoutMs, force });
    const ran = !r.timedOut && r.status !== 'disabled' && r.status !== 'error';
    if (!ran) return { ...base, backend: r.backend, status: 'invalid', reason: r.timedOut ? 'the witness exceeded its time budget' : `the sandbox could not execute it (${r.backend}): ${String(r.stderr || '').trim() || r.status}`, timedOut: !!r.timedOut };
    const proven = fs.existsSync(path.join(root, PROOF_MARKER));
    return { ...base, ran: true, backend: r.backend, status: proven ? 'reproduced' : 'not-reproduced', exitCode: r.exitCode,
      observed: proven ? `the payload created '${PROOF_MARKER}' by running inside the generated script` : null,
      reason: proven ? null : 'the script ran and the marker was not created: this witness did not reproduce the effect' };
  } catch (e) {
    return { ...base, status: 'invalid', reason: `witness harness error: ${String((e && e.message) || e)}` };
  } finally { if (root) fs.rmSync(root, { recursive: true, force: true }); }
}

/** Finds the flow for (attrPath, ordinal) in a fresh analysis of `files`, and builds+runs its witness. */
export function witnessNixFlow(files, target, opts = {}) {
  const a = analyzeNixScripts({ files });
  const script = a.scripts.find((s) => s.attrPath === target.attrPath && (!target.file || s.file === target.file));
  if (!script) return { status: 'unsupported', ran: false, reason: `no generated script ${target.attrPath}` };
  const idx = placeholderIndexes(script.generated);
  const flow = a.flows.find((f) => f.attrPath === script.attrPath && f.generatedLocation && idx.indexOf(indexOfPosition(script.generated, f.generatedLocation.line, f.generatedLocation.startColumn)) === target.ordinal);
  if (!flow) return { status: 'unsupported', ran: false, reason: `no interpolation #${target.ordinal} in ${target.attrPath}` };
  return runNixScriptWitness(buildNixScriptWitness({ script, flow }), opts);
}

/** The (attrPath, ordinal) of the flow a finding describes, taken from a fresh analysis. */
export function nixFlowTarget(files, finding) {
  const a = analyzeNixScripts({ files });
  const flow = a.flows.find((f) => f.file === finding.file && f.line === finding.line && f.attrPath && f.generatedLocation)
    || a.flows.find((f) => f.file === finding.file && f.attrPath === finding.attrPath && f.generatedLocation);
  if (!flow) return null;
  const script = a.scripts.find((s) => s.attrPath === flow.attrPath && s.file === (flow.generatedLocation.file || finding.file));
  if (!script) return null;
  const ordinal = placeholderIndexes(script.generated).indexOf(indexOfPosition(script.generated, flow.generatedLocation.line, flow.generatedLocation.startColumn));
  return ordinal < 0 ? null : { attrPath: script.attrPath, file: script.file, ordinal };
}

/**
 * Before/after judgement for a fix. A fix is witness-verified only when the ORIGINAL reproduced and the PATCHED code
 * ran cleanly without reproducing. Anything invalid on either side verifies nothing.
 */
export function judgeFixWitness(before, after) {
  if (!before || before.status !== 'reproduced') return { ok: false, verified: false, reason: `the original code did not reproduce (${(before && before.status) || 'no witness'}${before && before.reason ? `: ${before.reason}` : ''}), so the fix cannot be witness-verified` };
  if (!after || after.status === 'invalid' || after.status === 'unavailable' || after.status === 'unsupported') return { ok: false, verified: false, reason: `the patched witness could not be judged (${(after && after.status) || 'no witness'}${after && after.reason ? `: ${after.reason}` : ''})` };
  if (after.status === 'reproduced') return { ok: false, verified: false, stillReproduces: true, reason: 'the patched code still reproduces the effect' };
  return { ok: true, verified: true, reason: null, note: 'the witness reproduced before the patch and not after; this is evidence about this witness, not a proof of safety' };
}

// ── Haskell: optional, toolchain-gated ───────────────────────────────────────
/** Whether a Haskell runner exists. Never installs anything. */
export function haskellRunner() {
  const p = which('runghc') || which('runhaskell');
  if (!p) return { available: false, reason: 'no Haskell toolchain (runghc) on PATH; witnesses for Haskell findings are unavailable here' };
  const v = spawnSync(p, ['--version'], { encoding: 'utf8', timeout: 10_000 });
  return v.status === 0 ? { available: true, path: p, version: String(v.stdout || v.stderr).trim() } : { available: false, reason: 'the Haskell runner did not start' };
}

/**
 * Runs a Haskell program text as a witness. `main` must create PROVEN in its working directory when the effect is
 * reproduced. Without a toolchain the answer is `unavailable`: not proof, not refutation.
 */
export function runHaskellWitness(source, { timeoutMs = 60_000, force } = {}) {
  const base = { witness: WITNESS_VERSION, lang: 'haskell', ran: false, backend: null, marker: PROOF_MARKER };
  const hr = haskellRunner();
  if (!hr.available) return { ...base, status: 'unavailable', reason: hr.reason };
  if (!sandboxAvailable()) return { ...base, status: 'invalid', reason: 'no confinement primitive available; refusing to execute' };
  let root;
  try {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'witness-hs-')));
    fs.writeFileSync(path.join(root, 'Witness.hs'), source, 'utf8');
    const r = runConfined([hr.path, 'Witness.hs'], { root, timeoutMs, force });
    if (r.status === 'disabled' || r.status === 'error') return { ...base, backend: r.backend, status: 'invalid', reason: `the sandbox could not execute it: ${String(r.stderr || '').trim() || r.status}` };
    if (r.timedOut) return { ...base, backend: r.backend, status: 'invalid', reason: 'the witness exceeded its time budget', timedOut: true };
    if (/error|parse error|Could not find module/i.test(String(r.stderr || '')) && r.exitCode !== 0) return { ...base, backend: r.backend, status: 'invalid', reason: `the program did not compile or run: ${String(r.stderr).trim().split('\n')[0]}` };
    const proven = fs.existsSync(path.join(root, PROOF_MARKER));
    return { ...base, ran: true, backend: r.backend, status: proven ? 'reproduced' : 'not-reproduced', exitCode: r.exitCode, reason: proven ? null : 'the program ran and the marker was not created' };
  } catch (e) {
    return { ...base, status: 'invalid', reason: `witness harness error: ${String((e && e.message) || e)}` };
  } finally { if (root) fs.rmSync(root, { recursive: true, force: true }); }
}

/** A `witness` hook for runFixLifecycle over a Nix generated-script finding: runs the original and the patched tree. */
export function nixFixWitness(finding, opts = {}) {
  return (plan, files, patched) => {
    const nixOnly = (t) => Object.fromEntries(Object.entries(t).filter(([p, x]) => /\.nix$/i.test(p) && typeof x === 'string'));
    const target = nixFlowTarget(nixOnly(files), finding);
    if (!target) return { ok: false, verified: false, reason: 'the finding is not a generated-script interpolation, so no witness applies' };
    return judgeFixWitness(witnessNixFlow(nixOnly(files), target, opts), witnessNixFlow(nixOnly(patched), target, opts));
  };
}
