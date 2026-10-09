// Advisory output can never reach authoritative state (X-207.AC01).
//
// Hunt (`discovery/`) is advisory: a model proposes candidates and the output is a hypothesis, never a finding that gates a
// release. Two ways that separation could fail quietly are closed here, both by construction rather than by convention:
//
//   1. SHARED-FILE SIDE EFFECTS. Advisory code writes to exactly one file name from a closed allowlist, through
//      `writeAdvisoryState`. The write goes to a fresh temporary file that is renamed over the target, so a target that is a
//      symlink or a hard link to `last-scan.json` (planted by a hostile tree) is REPLACED, never written through. The state
//      directory must resolve inside the project root. A name outside the allowlist, a path separator in a name, or the
//      authoritative scan files are refused with a typed reason.
//   2. SERIALIZATION. A hypothesis is recognisable (`isAdvisoryHypothesis`) from what the hunt pipeline stamps on it, and the
//      report normalizer excludes it from every gating output. Promotion into a finding is the only way across, and it is a
//      different shape (`hypothesis-promotion.js`), so a hypothesis cannot be turned into a blocker by being merged into a
//      scan's finding list.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { isPlainObject } from '../assurance/schema-kit.js';
import { STATE_DIR_NAME, stateWritesEnabled } from '../state-dir.js';

/** The state file names advisory code may write. Everything else is refused. */
export const ADVISORY_STATE_FILES = Object.freeze(['discovery-memory.json']);

/** Files that decide a gate and that no advisory writer may name, even by mistake in the allowlist above. */
const AUTHORITATIVE_STATE_FILES = Object.freeze(['last-scan.json', 'last-scan.json.sig', 'rules.yml', 'rules.yml.sig', 'scan-key']);

const MAX_BYTES = 4 * 1024 * 1024;

/** True for a hunt hypothesis: it carries the hunt stamp (`parser: DISCOVERY` and/or a `discovery` object). */
export function isAdvisoryHypothesis(f) {
  return isPlainObject(f) && (f.parser === 'DISCOVERY' || isPlainObject(f.discovery));
}

/**
 * Write an advisory state file. Returns `{ ok: true, path }` or `{ ok: false, code, reason }`; never throws.
 * `body` is a string. The write is atomic (temp file + rename) and never follows a link at the target.
 */
export function writeAdvisoryState(scanRoot, name, body) {
  const refuse = (code, reason) => ({ ok: false, code, reason });
  try {
    if (typeof name !== 'string' || name.includes('/') || name.includes('\\') || name.includes('\0') || name === '' || name.startsWith('.')) {
      return refuse('bad-name', 'an advisory state file name is a plain file name');
    }
    if (AUTHORITATIVE_STATE_FILES.includes(name) || /^last-scan/.test(name)) return refuse('authoritative', `'${name}' is authoritative scan state; advisory output never writes it`);
    if (!ADVISORY_STATE_FILES.includes(name)) return refuse('not-allowlisted', `'${name}' is not an advisory state file`);
    if (!stateWritesEnabled()) return refuse('state-writes-disabled', 'state writes are switched off for this process (read-only scan)');
    if (typeof body !== 'string' || Buffer.byteLength(body) > MAX_BYTES) return refuse('bad-body', `advisory state is a string of at most ${MAX_BYTES} bytes`);
    if (typeof scanRoot !== 'string' || !scanRoot) return refuse('no-root', 'no project root');
    const rootReal = fs.realpathSync(scanRoot);
    const dir = path.join(rootReal, STATE_DIR_NAME);
    fs.mkdirSync(dir, { recursive: true });
    const dirReal = fs.realpathSync(dir);
    if (dirReal !== path.join(rootReal, STATE_DIR_NAME)) return refuse('state-dir-escapes', 'the state directory resolves outside the project root');
    const target = path.join(dirReal, name);
    const tmp = path.join(dirReal, `.${name}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
    let fd = null;
    try {
      fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o644);
      fs.writeSync(fd, body);
      fs.closeSync(fd); fd = null;
      fs.renameSync(tmp, target);
    } catch (e) {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
      try { fs.rmSync(tmp, { force: true }); } catch { /* best effort */ }
      return refuse('write-failed', String(e?.message || e).slice(0, 160));
    }
    return { ok: true, path: target };
  } catch (e) {
    return refuse('write-failed', String(e?.message || e).slice(0, 160));
  }
}
