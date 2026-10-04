// STAND-IN evaluator for the NIX-011 isolation tests. It is NOT Nix: it speaks just enough of the CLI
// (--version, `eval --help`, `eval <flags> <installable>`) and performs the hostile operations a malicious
// flake could make an evaluator perform (read outside roots, read credentials, fetch, spawn native code,
// write the lock, recurse without bound, hang, flood output, balloon memory), driven by <root>/adversary.json.
// The isolation under test is the OS sandbox, which is independent of what this program is.
const fs = require('fs'), net = require('net'), cp = require('child_process');
const argv = process.argv.slice(2);
if (argv[0] === '--version') { console.log('nix (Nix) 2.24.0'); process.exit(0); }
if (argv[0] === 'eval' && argv.includes('--help')) { console.log(['--offline', '--no-update-lock-file', '--pure-eval', '--json', '--option NAME VALUE'].join('\n')); process.exit(0); }
if (argv[0] !== 'eval') { console.error('unsupported'); process.exit(2); }
const installable = argv[argv.length - 1];
const m = /^path:(.*)#(.*)$/.exec(installable);
if (!m) { console.error('bad installable'); process.exit(2); }
const root = m[1];
const plan = JSON.parse(fs.readFileSync(root + '/adversary.json', 'utf8'));
const out = { attribute: m[2], attempts: {} };
const attempt = (k, f) => { try { out.attempts[k] = f(); } catch (e) { out.attempts[k] = 'refused:' + (e.code || 'error'); } };
const done = () => { console.log(JSON.stringify(out)); process.exit(0); };
for (const a of plan.actions || []) {
  if (a.kind === 'readFile') attempt('readFile:' + a.path, () => { fs.readFileSync(a.path, 'utf8'); return 'READ'; });
  if (a.kind === 'getEnv') attempt('getEnv:' + a.name, () => process.env[a.name] || 'absent');
  if (a.kind === 'spawn') attempt('spawn', () => { cp.execFileSync('/bin/echo', ['native']); return 'SPAWNED'; });
  if (a.kind === 'writeLock') attempt('writeLock', () => { fs.writeFileSync(root + '/flake.lock', '{"tampered":true}'); return 'WROTE'; });
  if (a.kind === 'writeOutside') attempt('writeOutside', () => { fs.writeFileSync(a.path, 'x'); return 'WROTE'; });
  if (a.kind === 'ifd') attempt('ifd', () => { cp.execFileSync('/usr/bin/true'); return 'BUILT'; });
  if (a.kind === 'recurse') { const f = (n) => f(n + 1) + 1; try { f(0); } catch (e) { out.attempts.recurse = 'stack:' + e.constructor.name; } }
  if (a.kind === 'sleep') { setInterval(() => {}, 1000); out.pending = true; }
  if (a.kind === 'spin') { const end = Date.now() + 1e9; while (Date.now() < end) { /* never returns */ } }
  if (a.kind === 'flood') { const chunk = 'x'.repeat(65536); for (let i = 0; i < 4000; i++) { for (;;) { try { fs.writeSync(1, chunk); break; } catch (e) { if (e.code !== 'EAGAIN') throw e; } } } }
  if (a.kind === 'memory') { const keep = []; for (let i = 0; i < 4000; i++) keep.push(Buffer.alloc(8 * 1024 * 1024, 1)); out.attempts.memory = keep.length; }
}
const nets = (plan.actions || []).filter((a) => a.kind === 'fetch');
if (nets.length) {
  let left = nets.length;
  for (const a of nets) { const s = net.connect(a.port, '127.0.0.1'); s.on('connect', () => { out.attempts['fetch:' + a.port] = 'CONNECTED'; s.destroy(); if (--left === 0) done(); }); s.on('error', (e) => { out.attempts['fetch:' + a.port] = 'refused:' + e.code; if (--left === 0) done(); }); }
} else if (!out.pending) done();
