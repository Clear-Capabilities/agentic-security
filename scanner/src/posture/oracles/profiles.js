// Real application profiles for repair verification (contract-driven verification, Epic F-02 and F-03).
//
// A PROFILE is a framework and a database that a repair is verified against for real: the actual framework serving HTTP, the actual
// database holding durable state, migrations, two tenants, an authorized and a forbidden request, and an inspectable durable effect.
// The lifecycle is declared once here (provision, migrate, seed, serve, exercise, inspect, teardown) and each profile names what it
// needs. Before anything runs, `probeProfile` establishes whether this host can provide those needs WITHOUT installing or fetching
// anything: a missing database server, a framework that is not already installed, a container runtime that is not running, or a
// dependency that would have to be fetched without an operator fetch policy is a typed SETUP BLOCKER, and the profile's legs are
// `unsupported` in every record that cites them. Nothing here installs a package, pulls an image, or runs target code on the host;
// a stand-in (an in-memory store, a homemade router) never counts as the framework or the database.
//
// Platform status is separate from availability. `PLATFORM_STATUS` is what the repository may ADVERTISE: Linux stays `unverified` for
// this oracle path until the confinement, tamper, resource, cancellation and process-tree controls have been executed on Linux for
// it (F-03); a passing schema check is not that evidence.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { digestOf } from '../assurance/identity.js';

export const PROFILE_LIFECYCLE = Object.freeze(['provision', 'migrate', 'seed', 'serve', 'exercise', 'inspect', 'teardown']);
export const SETUP_BLOCKERS = Object.freeze(['runtime-unavailable', 'framework-unavailable', 'database-unavailable', 'container-runtime-unavailable', 'dependency-fetch-not-authorized', 'platform-unverified']);
export const PLATFORM_STATUS = Object.freeze({ darwin: 'host-run-only', linux: 'unverified', win32: 'unsupported' });

export const PROFILES = Object.freeze({
  'express-postgres': Object.freeze({ id: 'express-postgres', runtime: 'node', framework: { kind: 'node-module', name: 'express' }, database: { kind: 'postgres', binaries: ['postgres', 'initdb', 'pg_ctl'], image: 'postgres' }, migrations: 'sql', note: 'Express serving the application, PostgreSQL holding the durable state' }),
  'fastapi-postgres': Object.freeze({ id: 'fastapi-postgres', runtime: 'python', framework: { kind: 'python-module', name: 'fastapi', server: 'uvicorn' }, database: { kind: 'postgres', binaries: ['postgres', 'initdb', 'pg_ctl'], image: 'postgres' }, migrations: 'sql', note: 'FastAPI under uvicorn serving the application, PostgreSQL holding the durable state' }),
});

const which = (bin) => {
  // PATH lookup without a shell: each directory on PATH is checked for an executable of that name.
  if (!/^[\w.+-]{1,64}$/.test(bin)) return null;
  for (const dir of String(process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    const f = path.join(dir, bin);
    try { fs.accessSync(f, fs.constants.X_OK); if (fs.statSync(f).isFile()) return f; } catch { /* not here */ }
  }
  return null;
};
const nodeModuleFrom = (root) => (name) => { try { createRequire(path.join(root, 'package.json')).resolve(name); return true; } catch { return false; } };
const pythonModule = (name) => { try { const r = spawnSync('python3', ['-I', '-c', `import ${name}`], { encoding: 'utf8', timeout: 10_000 }); return r.status === 0; } catch { return false; } };

/**
 * What this host can provide for a profile, with nothing installed or fetched.
 * @param {string} id  profile id
 * @param {object} [o] { appRoot (where the application's own dependencies live), fetchPolicy (operator's: null means no fetching),
 *                      platform, probes: { which, nodeModule, pythonModule } (test seams) }
 */
export function probeProfile(id, { appRoot = process.cwd(), fetchPolicy = null, platform = process.platform, probes = {} } = {}) {
  const p = PROFILES[id];
  if (!p) return { profile: id, status: 'unknown-profile', blockers: [{ code: 'framework-unavailable', message: `no profile ${id}` }] };
  const w = probes.which || which; const nm = probes.nodeModule || nodeModuleFrom(appRoot); const pm = probes.pythonModule || pythonModule;
  const blockers = [];
  if (!w(p.runtime === 'node' ? 'node' : 'python3')) blockers.push({ code: 'runtime-unavailable', message: `${p.runtime} is not on PATH` });
  const fw = p.framework.kind === 'node-module' ? nm(p.framework.name) : pm(p.framework.name);
  if (!fw) blockers.push({ code: 'framework-unavailable', message: `${p.framework.name} is not installed where the application's dependencies live; it is not installed for you` });
  if (p.framework.server && !w(p.framework.server)) blockers.push({ code: 'framework-unavailable', message: `${p.framework.server} is not on PATH` });
  const localDb = p.database.binaries.every((b) => w(b));
  if (!localDb) {
    const docker = w('docker');
    if (!docker) blockers.push({ code: 'database-unavailable', message: 'no PostgreSQL server binaries and no container runtime' });
    else if (!fetchPolicy || fetchPolicy.allowImages !== true) blockers.push({ code: 'dependency-fetch-not-authorized', message: 'PostgreSQL would have to come from a container image, and the operator configured no fetch policy that allows pulling it' });
    else {
      const info = (probes.dockerInfo || (() => { try { return spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], { encoding: 'utf8', timeout: 10_000 }).status === 0; } catch { return false; } }))();
      if (!info) blockers.push({ code: 'container-runtime-unavailable', message: 'a container runtime is installed but not running' });
    }
  }
  if (PLATFORM_STATUS[platform] === 'unsupported') blockers.push({ code: 'platform-unverified', message: `${platform} is unsupported for this oracle path` });
  for (const b of blockers) if (!SETUP_BLOCKERS.includes(b.code)) throw new Error(`unknown blocker ${b.code}`);
  return { profile: id, status: blockers.length ? 'setup-blocked' : 'available', platformStatus: PLATFORM_STATUS[platform] ?? 'unsupported', blockers, lifecycle: PROFILE_LIFECYCLE, database: localDb ? 'local-binaries' : 'container-or-none' };
}

/**
 * The pinned environment manifest a profile run binds into its evidence: what would make two runs comparable. A field this host cannot
 * establish is null with a reason, never guessed.
 */
export function environmentManifest(id, { appRoot, lockfile = null, migrations = [], seed = null, imageDigest = null, runtimeVersion = process.version } = {}) {
  const read = (f) => { try { return fs.readFileSync(f); } catch { return null; } };
  const lock = lockfile ? read(path.resolve(appRoot || '.', lockfile)) : null;
  const m = {
    profile: id, runtimeVersion,
    lockfile: lockfile ? { path: lockfile, digest: lock ? digestOf(lock.toString('utf8')) : null, reason: lock ? null : 'unreadable' } : { path: null, digest: null, reason: 'no lockfile named' },
    imageDigest: imageDigest ?? null, imageReason: imageDigest ? null : 'no image used or no digest pinned',
    migrations: migrations.map((f) => ({ path: f, digest: (() => { const b = read(path.resolve(appRoot || '.', f)); return b ? digestOf(b.toString('utf8')) : null; })() })),
    seed: seed ? { path: seed, digest: (() => { const b = read(path.resolve(appRoot || '.', seed)); return b ? digestOf(b.toString('utf8')) : null; })() } : null,
  };
  return { ...m, digest: digestOf(m) };
}

/**
 * Run a profile leg. On this build every profile run ends at the probe when a blocker exists; when the probe passes the legs still
 * return `unsupported` because the confined runner for a real database is not implemented: this function never falls back to the host.
 */
export function runProfileLeg(id, o = {}) {
  const probe = probeProfile(id, o);
  if (probe.status !== 'available') return { status: 'unsupported', reason: 'setup-blocked', probe };
  return { status: 'unsupported', reason: 'confined-runner-not-implemented', probe, note: 'the host can provide the profile, but no confined runner for a real framework and database exists in this build; running it on the host is refused' };
}
