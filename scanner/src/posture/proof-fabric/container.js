// Container execution for the proof fabric (PRD 1, requirement 2). The runner prefers a container when a responsive runtime and a
// locally present image exist, and it never pulls an image: nothing is fetched during a proof.
//
// What the container is allowed to be, by construction (`containerArgs`, pure and tested flag by flag):
//   * no network at all (`--network none`); a reproducer that needs the loopback callback listener cannot run in a container and says so;
//   * not privileged, no capabilities (`--cap-drop ALL`), no privilege escalation (`no-new-privileges`), a read-only root filesystem;
//   * bounded CPU, memory (swap = memory), process count and a small writable /tmp;
//   * one bind mount: the proof's own scratch directory, as `/work`. Nothing of the host's home, repository or credentials;
//   * the host user's uid and gid, never root;
//   * the environment is exactly the reproducer's, plus a minimal PATH/HOME.
// The container is named, and removed (`rm -f`) on every exit path including timeout and cancellation, because killing the `docker`
// client does not by itself stop the container.
//
// HONEST LIMIT: this has been exercised against a fake engine that records the arguments and runs the command locally, which proves
// the plumbing and the flags. It has not been run against a real Docker or Podman daemon in this repository's test environment.
import { spawnSync } from 'node:child_process';
import { superviseSpawn } from '../../sandbox/supervise.js';
import { scrubEnv } from '../../sandbox/trust-domains.js';

export const CONTAINER_ROOT = '/work';
// the image's own toolchain directories matter: the Temurin image puts the JDK at /opt/java/openjdk/bin and sets it through ENV, which a
// bare PATH override throws away (found by the first run against a real engine: `javac: not found`)
const CONTAINER_PATH = '/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
// the interpreter names inside the image; the host paths the runner uses locally mean nothing in there
export const CONTAINER_TOOLS = Object.freeze({ node: 'node', python: 'python3', java: 'java', javac: 'javac', cc: 'gcc', dotnet: 'dotnet' });

export function containerArgs({ image, name, hostRoot, argv, env = {}, limits, user = null }) {
  if (!image || !name || !hostRoot || !Array.isArray(argv) || !argv.length) throw new Error('container run needs image, name, root and argv');
  const uid = user ?? (typeof process.getuid === 'function' ? `${process.getuid()}:${process.getgid()}` : '65534:65534');
  const args = [
    'run', '--rm', '--pull', 'never', '--name', name,
    '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--pids-limit', String(limits.pids), '--memory', `${limits.memoryMb}m`, '--memory-swap', `${limits.memoryMb}m`, '--cpus', String(limits.cpus),
    '--tmpfs', `/tmp:rw,nosuid,size=${limits.diskMb}m`, '--user', uid,
    '-v', `${hostRoot}:${CONTAINER_ROOT}:rw`, '--workdir', CONTAINER_ROOT,
    '-e', 'HOME=/work', '-e', `PATH=${CONTAINER_PATH}`, '-e', 'CI=1',
  ];
  for (const [k, v] of Object.entries(env)) args.push('-e', `${k}=${v}`);
  args.push(image, ...argv);
  return args;
}

/** Run one command in a container. Returns the same shape `runInBoundary` does for the fields the runner reads. Never throws. */
export async function runInContainer({ runtime, image, name, hostRoot, argv, env, limits, timeoutMs, signal, maxOutputBytes, user }) {
  const args = containerArgs({ image, name, hostRoot, argv, env, limits, user });
  const cleanup = () => { try { spawnSync(runtime, ['rm', '-f', name], { timeout: 10_000, killSignal: 'SIGKILL', stdio: 'ignore' }); } catch { /* best effort */ } };
  let r;
  try {
    r = await superviseSpawn(runtime, args, { cwd: hostRoot, // the client needs its own configuration (DOCKER_HOST, contexts, XDG paths); credential-looking names are dropped
    env: scrubEnv(process.env), timeoutMs, signal, maxOutputBytes, graceMs: 1000 });
  } finally { cleanup(); }
  if (r.spawnError) return { blocked: true, reasons: [`could not start the container runtime: ${r.spawnError}`] };
  if (r.cancelled) return { blocked: true, reasons: ['cancelled'] };
  // a runtime failure (image gone, daemon died) is exit 125/126/127 from the client before the target ran: that is not the target's verdict
  if (!r.timedOut && [125, 126, 127].includes(r.exitCode)) return { blocked: true, reasons: [`the container runtime could not run the command (exit ${r.exitCode}): ${String(r.stderr).trim().split('\n').pop()?.slice(0, 160) ?? ''}`] };
  return {
    executed: true, status: 'completed', blocked: false, exitCode: r.exitCode, timedOut: r.timedOut, outputCapped: r.outputCapped,
    targetOutput: { stdout: r.stdout, stderr: r.stderr }, termination: r.termination, backend: 'container',
  };
}
