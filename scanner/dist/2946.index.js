export const id = 2946;
export const ids = [2946];
export const modules = {

/***/ 52946:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   verifyWithCosign: () => (/* binding */ verifyWithCosign)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _sandbox_supervise_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(74676);
/* harmony import */ var _sandbox_trust_domains_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(38832);
// Signature verification by DELEGATION to cosign (PRD 5, requirement 5: "Sigstore, cosign"). This module does not implement keyless
// verification (certificate chains, transparency-log proofs, identity matching); cosign does, and this runs it and reads its answer.
//
// The state is one of verified | invalid | missing | unavailable, and the rules are conservative:
//   * the check is bound to the DIGEST we scanned (`<repo>@sha256:...`), never to a tag, so a signature for some other image cannot
//     be mistaken for this one;
//   * `verified` needs cosign to exit 0 AND its output to name that exact digest in a signature payload. Exit 0 with a different (or no)
//     digest is `invalid`;
//   * a cosign that is not installed, that timed out, or that could not reach what it needed is `unavailable` and says so. It is never
//     read as verified, and never as invalid either: a check that did not run is not a failed check;
//   * the key is passed as a temporary file (mode 0600, removed afterwards) and the child gets a scrubbed environment.






const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9.\-_/:]{0,300}$/;

function findTool(name, pathEnv = process.env.PATH || '') {
  for (const dir of pathEnv.split(node_path__WEBPACK_IMPORTED_MODULE_2__.delimiter)) {
    if (!dir) continue;
    const p = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, name);
    try { node_fs__WEBPACK_IMPORTED_MODULE_0__.accessSync(p, node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.X_OK); if (node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p).isFile()) return node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(p); } catch { /* next */ }
  }
  return null;
}

/** @param {{repository: string, digest: string, publicKeyPem?: string, certificateIdentity?: string, certificateOidcIssuer?: string}} o */
async function verifyWithCosign({ repository, digest, publicKeyPem = null, certificateIdentity = null, certificateOidcIssuer = null, timeoutMs = 60_000, signal, pathEnv = process.env.PATH } = {}) {
  const na = (reason) => ({ state: 'unavailable', via: 'cosign', reason });
  if (!DIGEST_RE.test(String(digest))) return na('there is no sha256 image digest to verify a signature against');
  if (!REPO_RE.test(String(repository ?? '')) || String(repository).includes('..') || String(repository).startsWith('-')) return na('the repository name is not valid');
  const keyless = !!(certificateIdentity && certificateOidcIssuer);
  if (!publicKeyPem && !keyless) return na('no verification material: give a public key, or a certificate identity and OIDC issuer for keyless verification');
  if (publicKeyPem && keyless) return na('give either a public key or a keyless identity, not both');
  const bin = findTool('cosign', pathEnv);
  if (!bin) return na('cosign is not installed; nothing was verified');
  const dir = node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'cosign-'));
  try {
    const args = ['verify'];
    if (publicKeyPem) { const kf = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, 'key.pub'); node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(kf, publicKeyPem, { mode: 0o600 }); args.push('--key', kf); } else args.push('--certificate-identity', certificateIdentity, '--certificate-oidc-issuer', certificateOidcIssuer);
    args.push(`${repository}@${digest}`);
    const r = await (0,_sandbox_supervise_js__WEBPACK_IMPORTED_MODULE_3__/* .superviseSpawn */ .u)(bin, args, { cwd: dir, env: (0,_sandbox_trust_domains_js__WEBPACK_IMPORTED_MODULE_4__/* .scrubEnv */ .LK)(process.env), timeoutMs, signal, maxOutputBytes: 2 * 1024 * 1024 });
    if (r.spawnError) return na(`could not start cosign: ${r.spawnError}`);
    if (r.timedOut) return na('cosign did not answer in time');
    if (r.cancelled) return na('cancelled');
    const err = String(r.stderr).toLowerCase();
    if (r.exitCode === 0) {
      let payloads = [];
      try { const j = JSON.parse(r.stdout); payloads = Array.isArray(j) ? j : [j]; } catch { /* handled below */ }
      const matching = payloads.filter((p) => p?.critical?.image?.['docker-manifest-digest'] === digest);
      if (matching.length) return { state: 'verified', via: 'cosign', mode: keyless ? 'keyless' : 'key', signatures: matching.length, identity: keyless ? certificateIdentity : null, reason: null };
      return { state: 'invalid', via: 'cosign', reason: 'cosign reported success but none of the verified signatures names this image digest' };
    }
    if (/no signatures found|no matching signatures|no signatures associated|manifest unknown/.test(err)) return { state: 'missing', via: 'cosign', reason: 'no signature exists for this digest' };
    if (/invalid signature|signature verification failed|crypto\/ecdsa|verification failed|certificate identity|none of the expected identities/.test(err)) return { state: 'invalid', via: 'cosign', reason: 'cosign rejected the signature or the identity' };
    return na(`cosign could not complete the check (exit ${r.exitCode}): ${String(r.stderr).trim().split('\n').pop()?.slice(0, 160) ?? ''}`);
  } finally { try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
}


/***/ })

};
