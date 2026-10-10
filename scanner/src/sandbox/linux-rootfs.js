// Pure construction of the Linux root filesystem the namespace backend pivots
// into (capability mode, X-502).
//
// Nothing in this file touches the kernel. It turns declared roots into a PLAN
// (which host paths are made visible, read-only or read-write, and which are
// masked) and a POSIX shell script that carries the plan out inside fresh user,
// mount and PID namespaces. Keeping it pure is the point: the construction can
// be unit-tested on any host, with stand-in mount tools, and the claim that the
// kernel then enforces it is made only by the active probes that run on a Linux
// host (`linux-probes.js`, the `sandbox-linux` CI job).
//
// The model, in one paragraph. A new mount namespace gets a tmpfs root that
// holds NOTHING. Only the paths in the plan are bind-mounted into it, at the
// same absolute path they have on the host: the minimal runtime baseline
// (interpreter, libraries, a few identity files) and the declared read roots
// read-only, the declared write roots read-write, then a fresh /proc and a
// minimal /dev. The skeleton is remounted read-only and the process pivots into
// it; the old root is detached. A protected path is not denied, it is ABSENT:
// the kernel has no name for it, so there is nothing to open, to follow a link
// to, or to reach with `..`. Paths keep their meaning, so a caller's absolute
// paths mean the same thing on this backend as on the userspace one.
import fs from 'node:fs';
import path from 'node:path';

// What every confined process needs just to start: the dynamic loader, system
// libraries, the shell and coreutils. Mounted read-only. Directories that are
// symlinks on the host (`/bin -> usr/bin`) are recreated as symlinks.
export const BASELINE_DIRS = Object.freeze([
  '/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/libx32', '/etc/alternatives',
]);
// Identity and loader files; no credentials. Read-only. A missing one is skipped.
export const BASELINE_FILES = Object.freeze([
  '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/localtime', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
]);
// Device nodes a process legitimately needs. Nothing else from /dev.
export const DEV_NODES = Object.freeze(['null', 'zero', 'full', 'random', 'urandom', 'tty']);

const BAD_CHARS = /[\0\n\t]/;

/** True for a path the plan format can carry (absolute, no NUL/newline/tab, not the root). */
export function isPlanPath(p) {
  return typeof p === 'string' && p.startsWith('/') && p !== '/' && !BAD_CHARS.test(p);
}

function realOrResolved(p, realpath) {
  const abs = path.resolve(p);
  try { return realpath(abs); } catch { return abs; }
}

function within(parent, child) {
  return child === parent || child.startsWith(parent.endsWith('/') ? parent : parent + '/');
}

/**
 * Build the plan.
 * @param {object} o
 * @param {string}   o.root            the sandbox root (always read-write)
 * @param {string[]} [o.readRoots]     read-only roots (directories or files)
 * @param {string[]} [o.writeRoots]    read-write roots
 * @param {string[]} [o.denyReadPaths] paths that must not be readable
 * @param {string}   [o.cwd]           working directory (must lie inside a bound path)
 * @param {boolean}  [o.baseline=true] include the runtime baseline
 * @param {(p:string)=>string} [o.realpath]  seam for tests
 * @returns {{ok:true, entries:{path:string, mode:'ro'|'rw'}[], masks:string[], cwd:string} | {ok:false, error:string}}
 */
export function buildRootPlan({
  root, readRoots = [], writeRoots = [], denyReadPaths = [], cwd = null, baseline = true,
  realpath = fs.realpathSync,
} = {}) {
  if (!root) return { ok: false, error: 'a sandbox root is required' };
  const want = new Map(); // path -> 'ro' | 'rw' (rw wins)
  const add = (p, mode) => {
    if (want.get(p) === 'rw') return;
    want.set(p, mode);
  };
  const clean = (p, what) => {
    if (typeof p !== 'string' || !p) return { error: `${what} must be a non-empty path` };
    const real = realOrResolved(p, realpath);
    if (real === '/') return { error: `${what} may not be the filesystem root` };
    if (!isPlanPath(real)) return { error: `${what} cannot be carried into a mount plan (${JSON.stringify(p)})` };
    return { path: real };
  };

  if (baseline) {
    for (const p of [...BASELINE_DIRS, ...BASELINE_FILES]) add(p, 'ro');
  }
  const rootC = clean(root, 'the sandbox root');
  if (rootC.error) return { ok: false, error: rootC.error };
  add(rootC.path, 'rw');
  for (const p of readRoots || []) {
    const c = clean(p, 'a read root');
    if (c.error) return { ok: false, error: c.error };
    add(c.path, 'ro');
  }
  for (const p of writeRoots || []) {
    const c = clean(p, 'a write root');
    if (c.error) return { ok: false, error: c.error };
    add(c.path, 'rw');
  }

  // Drop an entry already covered by a bound ancestor with at least its access:
  // binding a file over a path inside a read-only mount would have to create it
  // there, which a read-only mount refuses, and it adds nothing.
  const all = [...want.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const entries = [];
  for (const [p, mode] of all) {
    const covered = entries.some((e) => e.path !== p && within(e.path, p) && (e.mode === 'rw' || mode === 'ro'));
    if (!covered) entries.push({ path: p, mode });
  }

  const masks = [];
  for (const p of denyReadPaths || []) {
    if (typeof p !== 'string' || !p) continue;
    const real = realOrResolved(p, realpath);
    if (!isPlanPath(real)) {
      if (real === '/' || BAD_CHARS.test(real)) return { ok: false, error: `a denied path cannot be carried into a mount plan (${JSON.stringify(p)})` };
      continue;
    }
    // A denied path that contains a bound root would hide the root; refuse
    // rather than guess which of the two the caller meant.
    const hides = [rootC.path, ...[...(readRoots || []), ...(writeRoots || [])].map((r) => realOrResolved(r, realpath))]
      .find((r) => within(real, r));
    if (hides) return { ok: false, error: `a denied path overlaps a bound root (${real})` };
    if (!masks.includes(real)) masks.push(real);
  }

  let workdir = rootC.path;
  if (cwd) {
    const c = clean(cwd, 'the working directory');
    if (c.error) return { ok: false, error: c.error };
    if (!entries.some((e) => within(e.path, c.path))) return { ok: false, error: `the working directory is outside every bound path (${c.path})` };
    workdir = c.path;
  }
  return { ok: true, entries, masks, cwd: workdir };
}

/** The plan as the tab-separated text the setup script reads. */
export function serializePlan(plan) {
  const lines = [];
  for (const e of plan.entries) lines.push(`B\t${e.mode}\t${e.path}`);
  for (const m of plan.masks) lines.push(`M\t-\t${m}`);
  return lines.join('\n');
}

export const MARK_SETUP_FAILED = 'AGSEC_SANDBOX_SETUP_FAILED:';
export const MARK_NO_PRIVDROP = 'AGSEC_SANDBOX_PRIVDROP_UNAVAILABLE';

/**
 * The setup script for capability mode. Runs inside the new namespaces as the
 * mapped root, before anything of the caller's. Reads, from the environment:
 *   SBX_MOUNT SBX_UMOUNT SBX_PIVOT SBX_PRIVDROP   absolute tool paths
 *   SBX_NEWROOT   an empty host directory to become the new root
 *   SBX_PLAN      the serialized plan
 *   SBX_FINAL     the second-stage script (final privilege state)
 * Every step is fail-closed: a failure prints the marker and exits before the
 * caller's command is exec'd.
 */
export const PIVOT_SETUP_SCRIPT = `
_fail() { echo "${MARK_SETUP_FAILED} $1" >&2; exit 91; }
# Make one bind mount read-only. A plain remount is tried first; some kernels
# lock the flags a bind inherits inside a user namespace (nosuid, nodev, ...),
# in which case the remount must restate them, so the second attempt reads the
# mount's current options and replaces only the access mode.
_ro() {
  "$SBX_MOUNT" -o remount,bind,ro "$1" 2>/dev/null && return 0
  _cur=$(while read -r _a _b _c _d _mp _o _rest; do if [ "$_mp" = "$1" ]; then echo "$_o"; break; fi; done < /proc/self/mountinfo)
  case "$_cur" in *,*) "$SBX_MOUNT" -o "remount,bind,ro,\${_cur#*,}" "$1" ;; *) "$SBX_MOUNT" -o remount,bind,ro "$1" ;; esac
}
NR="$SBX_NEWROOT"
[ -n "$NR" ] && [ -d "$NR" ] || _fail "no new root directory"
"$SBX_MOUNT" --make-rprivate / || _fail "mount propagation could not be made private"
"$SBX_MOUNT" -t tmpfs -o mode=0755,size=16m tmpfs "$NR" || _fail "the new root could not be created"
_tab=$(printf '\\t')
while IFS="$_tab" read -r _op _mode _p; do
  [ -n "$_op" ] || continue
  case "$_op" in
    B)
      if [ -L "$_p" ]; then
        mkdir -p "$NR\${_p%/*}" || _fail "could not prepare a link"
        ln -s "$(readlink "$_p")" "$NR$_p" || _fail "could not recreate a link"
      elif [ -d "$_p" ]; then
        mkdir -p "$NR$_p" || _fail "could not prepare a mount point"
        "$SBX_MOUNT" --bind "$_p" "$NR$_p" || _fail "a path could not be made visible"
        if [ "$_mode" = ro ]; then
          _ro "$NR$_p" || _fail "a path could not be made read-only"
        fi
      elif [ -e "$_p" ]; then
        mkdir -p "$NR\${_p%/*}" || _fail "could not prepare a mount point"
        [ -e "$NR$_p" ] || : > "$NR$_p" || _fail "could not prepare a file mount point"
        "$SBX_MOUNT" --bind "$_p" "$NR$_p" || _fail "a file could not be made visible"
        if [ "$_mode" = ro ]; then
          _ro "$NR$_p" || _fail "a file could not be made read-only"
        fi
      fi
      ;;
  esac
done <<SBX_PLAN_EOF
$SBX_PLAN
SBX_PLAN_EOF
mkdir -p "$NR/proc" "$NR/dev" || _fail "could not prepare /proc and /dev"
"$SBX_MOUNT" -t proc proc "$NR/proc" 2>/dev/null || true
"$SBX_MOUNT" -t tmpfs -o mode=0755,size=64k tmpfs "$NR/dev" || _fail "could not create /dev"
for _n in ${DEV_NODES.join(' ')}; do
  [ -e "/dev/$_n" ] || continue
  : > "$NR/dev/$_n" || continue
  "$SBX_MOUNT" --bind "/dev/$_n" "$NR/dev/$_n" 2>/dev/null || { [ "$_n" = null ] && _fail "/dev/null could not be provided"; }
done
while IFS="$_tab" read -r _op _mode _p; do
  [ "$_op" = M ] || continue
  if [ -d "$NR$_p" ]; then
    "$SBX_MOUNT" -t tmpfs -o size=4k,mode=000 tmpfs "$NR$_p" || _fail "a protected directory could not be masked"
  elif [ -e "$NR$_p" ]; then
    "$SBX_MOUNT" --bind /dev/null "$NR$_p" || _fail "a protected file could not be masked"
  fi
done <<SBX_PLAN_EOF
$SBX_PLAN
SBX_PLAN_EOF
mkdir "$NR/.old" || _fail "could not prepare the old-root mount point"
_ro "$NR" || _fail "the new root could not be made read-only"
cd "$NR" || _fail "could not enter the new root"
"$SBX_PIVOT" "$NR" "$NR/.old" || _fail "pivot_root failed"
cd / || _fail "could not enter the pivoted root"
"$SBX_UMOUNT" -l /.old || _fail "the old root could not be detached"
if [ -z "$SBX_PRIVDROP" ] || ! "$SBX_PRIVDROP" --no-new-privs --securebits=+noroot,+noroot_locked --bounding-set=-all --inh-caps=-all /bin/sh -c 'exit 0' 2>/dev/null; then
  _fail "privilege drop is unavailable, and capability mode does not run without it"
fi
exec "$SBX_PRIVDROP" --no-new-privs --securebits=+noroot,+noroot_locked --bounding-set=-all --inh-caps=-all /bin/sh -c "$SBX_FINAL" _sbx "$@"
`;

/**
 * Second stage, in the final privilege state. Both directions are checked by
 * execution on every run: the host canary and the filesystem root are refused,
 * the sandbox root is writable. Either check failing means the sandbox is not
 * what it claims, so the command is not run.
 */
export const FINAL_SCRIPT = `
_fail() { echo "${MARK_SETUP_FAILED} $1" >&2; exit 91; }
if ( : > "$SBX_CANARY" ) 2>/dev/null; then
  _fail "an out-of-root write is still possible; refusing to execute"
fi
if [ -n "$SBX_STRICT" ]; then
  if ( : > /.agsec-rootcheck ) 2>/dev/null; then
    _fail "the filesystem root is writable; refusing to execute"
  fi
  if [ -e /.old/usr ]; then
    _fail "the old root is still reachable; refusing to execute"
  fi
fi
if ! ( : > "$ROOT/.agsec-sbx-wcheck" ) 2>/dev/null; then
  _fail "the sandbox root is not writable; refusing to execute"
fi
rm -f "$ROOT/.agsec-sbx-wcheck"
_cwd="\${SBX_CWD:-$ROOT}"
unset SBX_PLAN SBX_FINAL SBX_MOUNT SBX_UMOUNT SBX_PIVOT SBX_PRIVDROP SBX_NEWROOT SBX_MASKS SBX_CANARY SBX_STRICT SBX_CWD
cd "$_cwd" && exec "$@"
`;
