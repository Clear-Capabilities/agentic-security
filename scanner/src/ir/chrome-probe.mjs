// chrome-probe.mjs — Milestone 4, sub-project PNG/SVG/PDF export.
//
// Chrome/Chromium binary discovery, mirroring parser-py-cst.js's own
// already-proven probePythonAvailable() pattern exactly — this
// codebase's established convention for "optional local tool, detect
// and degrade gracefully" (see that file's own header comment for the
// full rationale this file inherits without repeating).

import * as cp from 'node:child_process';
import * as fs from 'node:fs';

let _capability = null;

// A malformed env var (e.g. AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS=oops)
// must fall back to the default, never reach spawnSync as NaN — found by
// the final whole-branch review: `Number('oops')` is NaN, and NaN as a
// spawnSync `timeout` option throws ERR_OUT_OF_RANGE synchronously.
// _tryBinary's own try/catch swallows that throw and returns null for
// EVERY candidate, so probeChromeAvailable would misreport
// `no-chrome-found` on a machine with a perfectly working Chrome install.
function _validTimeoutMs(raw, fallback) {
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}
const PROBE_TIMEOUT_MS = _validTimeoutMs(process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS, 5000);

// Real, common install locations, per platform. Deliberately excludes
// AGENTIC_SECURITY_CHROME_PATH — that override is handled separately in
// probeChromeAvailable() as an authoritative, non-fallback choice (see
// the comment there for why).
//
// KNOWN-GOOD ABSOLUTE PATHS ARE TRIED FIRST, PATH-resolvable bare names
// LAST — found by the final whole-branch review, reproduced live: with
// bare names tried first, a `chrome` shell script anywhere earlier on
// PATH than the real browser is silently preferred and then executed
// with this process's own render arguments. The `--version` output
// check (`_tryBinary` below) is a functional smoke test, not a security
// gate — it cannot distinguish a real Chrome/Chromium binary from any
// script that echoes a matching string. Preferring the well-known
// install locations narrows, though does not eliminate, this exposure
// (a compromised PATH entry named exactly `chrome`/`google-chrome`/etc.
// is still tried if no absolute-path candidate exists on this machine —
// this feature already assumes local machine trust, same as every other
// "optional local tool" this codebase shells out to).
function _candidatePaths() {
  const onPath = ['google-chrome-stable', 'google-chrome', 'chromium-browser', 'chromium', 'chrome'];
  const platformPaths = {
    darwin: [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      `${process.env.HOME || ''}/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
    ],
    win32: [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      `${process.env.LOCALAPPDATA || ''}\\Google\\Chrome\\Application\\chrome.exe`,
    ],
    linux: [],
  };
  const platformSpecific = platformPaths[process.platform] || [];
  return [...platformSpecific, ...onPath];
}

// Tries one candidate binary. Returns {ok:true, chrome:bin} on a real,
// working Chrome/Chromium, or null on any failure (missing binary, spawn
// error, non-zero exit, unrecognized --version output) — never throws.
function _tryBinary(bin) {
  if (!bin) return null;
  // An absolute-path candidate that doesn't exist can't spawn — skip the
  // spawnSync call entirely rather than let it throw ENOENT.
  if (bin.includes('/') || bin.includes('\\')) {
    if (!fs.existsSync(bin)) return null;
  }
  let r;
  try {
    r = cp.spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  } catch { return null; }
  if (r.error || r.status !== 0) return null;
  const out = (r.stdout || r.stderr || '');
  if (!/Chrom(e|ium)/i.test(out)) return null;
  return { ok: true, chrome: bin };
}

export function resetChromeProbe() { _capability = null; }

export function probeChromeAvailable() {
  if (_capability) return _capability;

  // An explicit override is authoritative, not just "try this one first
  // then fall back": an operator (or CI environment) who deliberately
  // pointed AGENTIC_SECURITY_CHROME_PATH at a binary wants a failure
  // reported when that binary doesn't work — not a silent switch to
  // whatever else this process happens to auto-detect on the machine.
  const fromEnv = process.env.AGENTIC_SECURITY_CHROME_PATH;
  if (fromEnv) {
    const hit = _tryBinary(fromEnv);
    _capability = hit || { ok: false, reason: 'chrome-path-invalid' };
    return _capability;
  }

  for (const bin of _candidatePaths()) {
    const hit = _tryBinary(bin);
    if (hit) { _capability = hit; return _capability; }
  }
  _capability = { ok: false, reason: 'no-chrome-found' };
  return _capability;
}
