export const id = 8798;
export const ids = [8798];
export const modules = {

/***/ 18798:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   PROOF_MARKER: () => (/* binding */ PROOF_MARKER),
/* harmony export */   WITNESS_STATUS: () => (/* binding */ WITNESS_STATUS),
/* harmony export */   WITNESS_VERSION: () => (/* binding */ WITNESS_VERSION),
/* harmony export */   buildNixScriptWitness: () => (/* binding */ buildNixScriptWitness),
/* harmony export */   haskellRunner: () => (/* binding */ haskellRunner),
/* harmony export */   judgeFixWitness: () => (/* binding */ judgeFixWitness),
/* harmony export */   nixFixWitness: () => (/* binding */ nixFixWitness),
/* harmony export */   nixFlowTarget: () => (/* binding */ nixFlowTarget),
/* harmony export */   runHaskellWitness: () => (/* binding */ runHaskellWitness),
/* harmony export */   runNixScriptWitness: () => (/* binding */ runNixScriptWitness),
/* harmony export */   witnessNixFlow: () => (/* binding */ witnessNixFlow),
/* harmony export */   witnessPayload: () => (/* binding */ witnessPayload)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31421);
/* harmony import */ var _sandbox_index_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(75778);
/* harmony import */ var _nix_script_taint_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(11793);
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








const WITNESS_VERSION = 'language-witness/1';
const PROOF_MARKER = 'PROVEN';
const WITNESS_STATUS = Object.freeze(['reproduced', 'not-reproduced', 'invalid', 'unavailable', 'unsupported']);
const SHELLS = new Set(['bash', 'sh', 'dash', 'ash', 'ksh', 'mksh']);
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_SCRIPT_BYTES = 256 * 1024;

const shEscape = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/** The text one placeholder takes in the generated script, given the Nix-side protection and the shell context. */
function witnessPayload(context, protection) {
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

const placeholderIndexes = (text) => { const out = []; for (let i = 0; i < text.length; i++) if (text[i] === _nix_script_taint_js__WEBPACK_IMPORTED_MODULE_5__/* .SHELL_PLACEHOLDER */ .v0) out.push(i); return out; };
const indexOfPosition = (text, line, col) => { let l = 1; let i = 0; while (i < text.length && l < line) { if (text[i] === '\n') l++; i++; } return i + col; };

/**
 * Builds a witness for one flow of one generated script.
 * @param {{script:{generated:string, shell:string|null, attrPath:string, file:string}, flow:{generatedLocation:{line:number,startColumn:number}, context:string, protection:string|null}}} t
 */
function buildNixScriptWitness({ script, flow }) {
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
  for (const ch of script.generated) { if (ch === _nix_script_taint_js__WEBPACK_IMPORTED_MODULE_5__/* .SHELL_PLACEHOLDER */ .v0) { out += n === ordinal ? payload : 'benign'; n++; } else out += ch; }
  const body = out.replace(/^#!.*\n/, '');
  return { status: 'ready', lang: 'nix-shell', shell, ordinal, attrPath: script.attrPath, file: script.file, payload, code: `${body}\n`, context: flow.context, protection: flow.protection || null };
}

function which(name) {
  for (const d of String(process.env.PATH || '').split(node_path__WEBPACK_IMPORTED_MODULE_2__.delimiter)) { const p = node_path__WEBPACK_IMPORTED_MODULE_2__.join(d, name); try { node_fs__WEBPACK_IMPORTED_MODULE_0__.accessSync(p, node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.X_OK); return p; } catch { /* next */ } }
  return null;
}

/** Runs a witness built by buildNixScriptWitness inside the confinement sandbox. Never throws. */
function runNixScriptWitness(w, { timeoutMs = DEFAULT_TIMEOUT_MS, force } = {}) {
  const base = { witness: WITNESS_VERSION, lang: 'nix-shell', ran: false, backend: null, marker: PROOF_MARKER };
  if (!w || w.status !== 'ready') return { ...base, status: w && w.status === 'unsupported' ? 'unsupported' : 'invalid', reason: (w && w.reason) || 'no witness' };
  const shellBin = which(w.shell);
  if (!shellBin) return { ...base, status: 'invalid', reason: `executable not found: ${w.shell}` };
  if (!(0,_sandbox_index_js__WEBPACK_IMPORTED_MODULE_4__/* .sandboxAvailable */ .$G)()) return { ...base, status: 'invalid', reason: 'no confinement primitive available; refusing to execute' };
  let root;
  try {
    root = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'witness-')));
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'witness.sh'), w.code, 'utf8');
    // 1. a witness that does not parse proves nothing in either direction
    const syn = (0,_sandbox_index_js__WEBPACK_IMPORTED_MODULE_4__/* .runConfined */ .id)([shellBin, '-n', 'witness.sh'], { root, timeoutMs, force });
    if (syn.status === 'disabled' || syn.status === 'error') return { ...base, backend: syn.backend, status: 'invalid', reason: `the sandbox could not run the syntax check (${syn.backend}): ${String(syn.stderr || '').trim() || 'no detail'}` };
    if (syn.timedOut) return { ...base, backend: syn.backend, status: 'invalid', reason: 'the syntax check exceeded its time budget', timedOut: true };
    if (syn.exitCode !== 0) return { ...base, backend: syn.backend, status: 'invalid', reason: `syntax error in the generated witness: ${String(syn.stderr || '').trim().split('\n')[0] || 'shell rejected it'}` };
    // 2. the real run
    const r = (0,_sandbox_index_js__WEBPACK_IMPORTED_MODULE_4__/* .runConfined */ .id)([shellBin, 'witness.sh'], { root, timeoutMs, force });
    const ran = !r.timedOut && r.status !== 'disabled' && r.status !== 'error';
    if (!ran) return { ...base, backend: r.backend, status: 'invalid', reason: r.timedOut ? 'the witness exceeded its time budget' : `the sandbox could not execute it (${r.backend}): ${String(r.stderr || '').trim() || r.status}`, timedOut: !!r.timedOut };
    const proven = node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, PROOF_MARKER));
    return { ...base, ran: true, backend: r.backend, status: proven ? 'reproduced' : 'not-reproduced', exitCode: r.exitCode,
      observed: proven ? `the payload created '${PROOF_MARKER}' by running inside the generated script` : null,
      reason: proven ? null : 'the script ran and the marker was not created: this witness did not reproduce the effect' };
  } catch (e) {
    return { ...base, status: 'invalid', reason: `witness harness error: ${String((e && e.message) || e)}` };
  } finally { if (root) node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(root, { recursive: true, force: true }); }
}

/** Finds the flow for (attrPath, ordinal) in a fresh analysis of `files`, and builds+runs its witness. */
function witnessNixFlow(files, target, opts = {}) {
  const a = (0,_nix_script_taint_js__WEBPACK_IMPORTED_MODULE_5__/* .analyzeNixScripts */ .S3)({ files });
  const script = a.scripts.find((s) => s.attrPath === target.attrPath && (!target.file || s.file === target.file));
  if (!script) return { status: 'unsupported', ran: false, reason: `no generated script ${target.attrPath}` };
  const idx = placeholderIndexes(script.generated);
  const flow = a.flows.find((f) => f.attrPath === script.attrPath && f.generatedLocation && idx.indexOf(indexOfPosition(script.generated, f.generatedLocation.line, f.generatedLocation.startColumn)) === target.ordinal);
  if (!flow) return { status: 'unsupported', ran: false, reason: `no interpolation #${target.ordinal} in ${target.attrPath}` };
  return runNixScriptWitness(buildNixScriptWitness({ script, flow }), opts);
}

/** The (attrPath, ordinal) of the flow a finding describes, taken from a fresh analysis. */
function nixFlowTarget(files, finding) {
  const a = (0,_nix_script_taint_js__WEBPACK_IMPORTED_MODULE_5__/* .analyzeNixScripts */ .S3)({ files });
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
function judgeFixWitness(before, after) {
  if (!before || before.status !== 'reproduced') return { ok: false, verified: false, reason: `the original code did not reproduce (${(before && before.status) || 'no witness'}${before && before.reason ? `: ${before.reason}` : ''}), so the fix cannot be witness-verified` };
  if (!after || after.status === 'invalid' || after.status === 'unavailable' || after.status === 'unsupported') return { ok: false, verified: false, reason: `the patched witness could not be judged (${(after && after.status) || 'no witness'}${after && after.reason ? `: ${after.reason}` : ''})` };
  if (after.status === 'reproduced') return { ok: false, verified: false, stillReproduces: true, reason: 'the patched code still reproduces the effect' };
  return { ok: true, verified: true, reason: null, note: 'the witness reproduced before the patch and not after; this is evidence about this witness, not a proof of safety' };
}

// ── Haskell: optional, toolchain-gated ───────────────────────────────────────
/** Whether a Haskell runner exists. Never installs anything. */
function haskellRunner() {
  const p = which('runghc') || which('runhaskell');
  if (!p) return { available: false, reason: 'no Haskell toolchain (runghc) on PATH; witnesses for Haskell findings are unavailable here' };
  // GHC's first start on a cold, loaded machine (a CI runner) has taken more than 10 s; a probe that gives up there reports a toolchain
  // that is installed as absent, and the answer then differs between two calls in one run.
  const v = (0,node_child_process__WEBPACK_IMPORTED_MODULE_3__.spawnSync)(p, ['--version'], { encoding: 'utf8', timeout: 60_000 });
  return v.status === 0 ? { available: true, path: p, version: String(v.stdout || v.stderr).trim() } : { available: false, reason: v.error && v.error.code === 'ETIMEDOUT' ? 'the Haskell runner did not start within 60 s' : 'the Haskell runner did not start' };
}

/**
 * Runs a Haskell program text as a witness. `main` must create PROVEN in its working directory when the effect is
 * reproduced. Without a toolchain the answer is `unavailable`: not proof, not refutation.
 */
function runHaskellWitness(source, { timeoutMs = 60_000, force } = {}) {
  const base = { witness: WITNESS_VERSION, lang: 'haskell', ran: false, backend: null, marker: PROOF_MARKER };
  const hr = haskellRunner();
  if (!hr.available) return { ...base, status: 'unavailable', reason: hr.reason };
  if (!(0,_sandbox_index_js__WEBPACK_IMPORTED_MODULE_4__/* .sandboxAvailable */ .$G)()) return { ...base, status: 'invalid', reason: 'no confinement primitive available; refusing to execute' };
  let root;
  try {
    root = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'witness-hs-')));
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'Witness.hs'), source, 'utf8');
    const r = (0,_sandbox_index_js__WEBPACK_IMPORTED_MODULE_4__/* .runConfined */ .id)([hr.path, 'Witness.hs'], { root, timeoutMs, force });
    if (r.status === 'disabled' || r.status === 'error') return { ...base, backend: r.backend, status: 'invalid', reason: `the sandbox could not execute it: ${String(r.stderr || '').trim() || r.status}` };
    if (r.timedOut) return { ...base, backend: r.backend, status: 'invalid', reason: 'the witness exceeded its time budget', timedOut: true };
    if (/error|parse error|Could not find module/i.test(String(r.stderr || '')) && r.exitCode !== 0) return { ...base, backend: r.backend, status: 'invalid', reason: `the program did not compile or run: ${String(r.stderr).trim().split('\n')[0]}` };
    const proven = node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, PROOF_MARKER));
    return { ...base, ran: true, backend: r.backend, status: proven ? 'reproduced' : 'not-reproduced', exitCode: r.exitCode, reason: proven ? null : 'the program ran and the marker was not created' };
  } catch (e) {
    return { ...base, status: 'invalid', reason: `witness harness error: ${String((e && e.message) || e)}` };
  } finally { if (root) node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(root, { recursive: true, force: true }); }
}

/** A `witness` hook for runFixLifecycle over a Nix generated-script finding: runs the original and the patched tree. */
function nixFixWitness(finding, opts = {}) {
  return (plan, files, patched) => {
    const nixOnly = (t) => Object.fromEntries(Object.entries(t).filter(([p, x]) => /\.nix$/i.test(p) && typeof x === 'string'));
    const target = nixFlowTarget(nixOnly(files), finding);
    if (!target) return { ok: false, verified: false, reason: 'the finding is not a generated-script interpolation, so no witness applies' };
    return judgeFixWitness(witnessNixFlow(nixOnly(files), target, opts), witnessNixFlow(nixOnly(patched), target, opts));
  };
}


/***/ })

};
