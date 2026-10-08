// Read tracer, preloaded with `node --import` by scripts/gate-trace-reads.mjs.
//
// It exists to keep the pre-push gate's per-check input scopes HONEST. A cached
// verdict is sound only if the scope digest covers every file the check can
// read; this records what a real run reads so a scope that is too narrow is
// found by a command rather than by a stale green.
//
// Every filesystem read-ish call and every child process spawn is appended to
// the file named by GATE_TRACE_OUT as one JSON line. It records, it never
// alters behaviour. Limits (stated, not hidden): module loading performed by
// the ESM loader itself does not pass through these wrappers, and reads done
// by non-node children (python) are not seen. Both are covered by the scope
// always including scanner/src and the check's fixtures; see gate-check-scopes.
import { createRequire, syncBuiltinESMExports } from 'node:module';
import * as path from 'node:path';

// The CJS module objects are the mutable ones; the ESM namespaces are read-only.
const req = createRequire(import.meta.url);
const fs = req('node:fs');
const cp = req('node:child_process');
const OUT = process.env.GATE_TRACE_OUT;
if (OUT) {
  const append = fs.appendFileSync.bind(fs);
  // appendFileSync calls the (wrapped) public writeFileSync internally, so emitting must not re-enter itself.
  let inEmit = false;
  const emit = (rec) => {
    if (inEmit) return;
    inEmit = true;
    try { append(OUT, JSON.stringify(rec) + '\n'); } catch { /* tracing must never break the run */ } finally { inEmit = false; }
  };
  const abs = (p) => {
    try {
      if (p instanceof URL) return p.pathname;
      if (typeof p === 'string') return path.resolve(p);
      if (Buffer.isBuffer(p)) return path.resolve(p.toString());
    } catch { /* fallthrough */ }
    return null;
  };
  const wrap = (obj, names, kind) => {
    for (const n of names) {
      const orig = obj[n];
      if (typeof orig !== 'function') continue;
      obj[n] = function (...args) {
        const p = abs(args[0]);
        if (p) emit({ op: n, path: p, kind });
        return orig.apply(this, args);
      };
    }
  };
  const READS = ['readFileSync', 'readFile', 'readdirSync', 'readdir', 'statSync', 'lstatSync', 'stat', 'lstat',
    'existsSync', 'openSync', 'open', 'createReadStream', 'readlinkSync', 'accessSync', 'access', 'opendirSync',
    'copyFileSync', 'cpSync'];
  const WRITES = ['writeFileSync', 'writeFile', 'appendFileSync', 'appendFile', 'mkdirSync', 'mkdir', 'rmSync', 'rm',
    'rmdirSync', 'unlinkSync', 'unlink', 'renameSync', 'rename', 'mkdtempSync', 'createWriteStream', 'truncateSync', 'symlinkSync'];
  wrap(fs, READS, 'fs');
  wrap(fs, WRITES, 'write');
  wrap(fs.promises, ['writeFile', 'appendFile', 'mkdir', 'rm', 'unlink', 'rename'], 'write');
  wrap(fs.promises, ['readFile', 'readdir', 'stat', 'lstat', 'open', 'access', 'opendir', 'readlink', 'copyFile', 'cp'], 'fs');
  for (const n of ['spawnSync', 'execFileSync', 'execSync', 'spawn', 'execFile', 'exec']) {
    const orig = cp[n];
    cp[n] = function (cmd, ...rest) {
      const a1 = rest[0];
      const opts = rest.find((x) => x && typeof x === 'object' && !Array.isArray(x));
      emit({ op: n, cmd: String(cmd), args: Array.isArray(a1) ? a1.map(String) : [], cwd: abs((opts && opts.cwd) || process.cwd()), kind: 'spawn' });
      return orig.call(this, cmd, ...rest);
    };
  }
  syncBuiltinESMExports();
}
