export const id = 2873;
export const ids = [2873];
export const modules = {

/***/ 32873:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   EngineError: () => (/* binding */ EngineError),
/* harmony export */   saveFromEngine: () => (/* binding */ saveFromEngine)
/* harmony export */ });
/* unused harmony export ENGINE_LIMITS */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31421);
// Read an image from a LOCAL container engine (`docker save` / `podman save`), for `image scan --engine <name>` (PRD 5, requirement 1:
// "local image"). The engine produces a docker-archive tar, which then goes through the same hardened parser as any other archive.
//
// Nothing here runs the image: `save` only exports it. The engine is a process like any other in this codebase, so it has what the
// shared contract asks of one: a timeout, cancellation, process-group cleanup, and a byte cap on what it may produce. The cap
// matters because the output is streamed to a temporary file and counted as it arrives: an engine (or a mislabelled "engine") that
// writes without end is stopped at the cap instead of filling the disk. The temporary file is removed on every exit path.





class EngineError extends Error {
  constructor(message, code) { super(message); this.name = 'EngineError'; this.code = code; }
}

const ENGINE_LIMITS = Object.freeze({ timeoutMs: 5 * 60_000, maxBytes: 2 * 1024 * 1024 * 1024 });
const RUNTIMES = Object.freeze(['docker', 'podman']);
// a reference, never an option: it must start with a letter or digit, so it can never be read as a flag
const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@+-]{0,254}$/;

function findTool(name, pathEnv = process.env.PATH || '') {
  for (const dir of pathEnv.split(node_path__WEBPACK_IMPORTED_MODULE_2__.delimiter)) {
    if (!dir) continue;
    const p = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, name);
    try { node_fs__WEBPACK_IMPORTED_MODULE_0__.accessSync(p, node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.X_OK); if (node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p).isFile()) return node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(p); } catch { /* next */ }
  }
  return null;
}

function saveFromEngine(ref, { runtime = 'docker', limits = ENGINE_LIMITS, signal = null, pathEnv = process.env.PATH } = {}) {
  const L = { ...ENGINE_LIMITS, ...limits };
  if (!RUNTIMES.includes(runtime)) return Promise.reject(new EngineError(`the container engine must be one of ${RUNTIMES.join(', ')}`, 'bad_runtime'));
  if (!REF_RE.test(String(ref ?? '')) || String(ref).includes('..')) return Promise.reject(new EngineError('not a valid image reference', 'bad_reference'));
  const bin = findTool(runtime, pathEnv);
  if (!bin) return Promise.reject(new EngineError(`${runtime} is not installed or not on PATH; nothing was read`, 'engine_unavailable'));
  const dir = node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'engine-save-'));
  const file = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, 'image.tar');
  const cleanup = () => { try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } };
  return new Promise((resolve, reject) => {
    const out = node_fs__WEBPACK_IMPORTED_MODULE_0__.createWriteStream(file, { mode: 0o600 });
    out.on('error', (e) => fail(new EngineError(`could not write the export: ${e.code ?? e.message}`, 'engine_error')));
    const child = (0,node_child_process__WEBPACK_IMPORTED_MODULE_3__.spawn)(bin, ['save', ref], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let bytes = 0; let stderr = ''; let settled = false; let reason = null;
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } } };
    const fail = (e) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); kill(); out.destroy(); cleanup(); reject(e); };
    const timer = setTimeout(() => { reason = 'timeout'; fail(new EngineError(`${runtime} save did not finish within ${Math.round(L.timeoutMs / 1000)}s`, 'timeout')); }, L.timeoutMs);
    const onAbort = () => fail(new EngineError('cancelled', 'cancelled'));
    if (signal) { if (signal.aborted) { onAbort(); return; } signal.addEventListener('abort', onAbort, { once: true }); }
    child.stdout.on('data', (d) => {
      if (settled) return;
      bytes += d.length;
      if (bytes > L.maxBytes) { fail(new EngineError(`the image export is larger than ${L.maxBytes} bytes`, 'too_large')); return; }
      out.write(d);
    });
    child.stderr.on('data', (d) => { if (stderr.length < 4096) stderr += d; });
    child.on('error', (e) => fail(new EngineError(`could not start ${runtime}: ${e.code ?? e.message}`, 'engine_unavailable')));
    child.on('close', (code) => {
      if (settled) return;
      out.end(() => {
        if (settled) return;
        if (code !== 0) return fail(new EngineError(`${runtime} save failed: ${stderr.trim().split('\n').pop()?.slice(0, 200) || `exit ${code}`}`, /no such image|not found|unable to find/i.test(stderr) ? 'not_found' : 'engine_error'));
        try {
          const buf = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file);
          settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); cleanup();
          resolve({ tar: buf, source: { kind: 'engine', runtime, reference: ref, bytes: buf.length } });
        } catch (e) { fail(new EngineError(`could not read the exported image: ${e.code ?? e.message}`, 'engine_error')); }
      });
    });
    void reason;
  });
}


/***/ })

};
