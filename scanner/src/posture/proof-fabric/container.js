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
// WHAT HAS AND HAS NOT BEEN RUN. The arguments are pinned flag by flag against a fake engine that records them. Against a REAL engine it has
// run: bench/proof-fabric/RESULT-linux-container.json records 72 container runs (36 vulnerable reproducers confirmed, 0 false confirmations, the
// timeouts degraded as designed) on Docker 28.0.4 on a Linux x64 runner, over the gcc, eclipse-temurin:21, node:24-slim and python:3-slim images
// (the Temurin run is what found the `javac: not found` PATH problem above), and the `proof-container` CI job runs it on every change. The
// residual limits, none of them closed by that run:
//   * ONE engine and ONE version on ONE host class. Other Docker versions, rootless Docker and other kernels are unmeasured.
//   * Podman is not probed: it is a supported engine name, and no run against it exists.
//   * macOS is unmeasured. Docker Desktop runs containers in a VM, so bind mounts, uids and file ownership behave differently from the Linux
//     measurement; no macOS container run has been recorded.
//   * The haskell:9 image: its first real-engine run (0.194.0 pull request) failed with `ghc: not found`, because GHC lives in /opt/ghc/<version>/bin
//     and not /opt/ghc/bin; `containerArgs` now resolves that directory inside the container. Whether the leg then passes is the `proof-container`
//     job's result; the measurement still skips Haskell unless AGENTIC_SECURITY_PROOF_CONTAINER_HASKELL=1 (bench/proof-fabric/measure.mjs). The
//     result file names no .NET image either, so the dotnet SDK image is unverified in the same way.
//   * A reproducer that needs the loopback callback listener (SSRF) cannot run with `--network none` and is skipped, not measured.
import { spawnSync } from 'node:child_process';
import { superviseSpawn } from '../../sandbox/supervise.js';
import { scrubEnv } from '../../sandbox/trust-domains.js';

export const CONTAINER_ROOT = '/work';
// the image's own toolchain directories matter: the Temurin image puts the JDK at /opt/java/openjdk/bin and sets it through ENV, which a
// bare PATH override throws away (found by the first run against a real engine: `javac: not found`)
const CONTAINER_PATH = '/opt/java/openjdk/bin:/opt/ghc/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
// the interpreter names inside the image; the host paths the runner uses locally mean nothing in there
export const CONTAINER_TOOLS = Object.freeze({ node: 'node', python: 'python3', java: 'java', javac: 'javac', cc: 'gcc', dotnet: 'dotnet', ghc: 'ghc', runghc: 'runghc' });

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
  // The haskell image keeps GHC in a VERSIONED directory (/opt/ghc/<version>/bin, found by the first real-engine Haskell run: `ghc: not found` with an
  // unversioned /opt/ghc/bin on PATH), and the version floats with the tag. The directory is resolved inside the container, after the environment
  // (including a reproducer's own PATH) has been applied, so nothing here depends on which GHC the image carries.
  const inner = /^haskell:/.test(image) ? ['sh', '-c', 'for d in /opt/ghc/*/bin; do PATH="$d:$PATH"; done; export PATH; exec "$@"', 'sh', ...argv] : argv;
  args.push(image, ...inner);
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
