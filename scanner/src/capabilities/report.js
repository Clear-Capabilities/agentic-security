// The capability report: requested, checked and enforced, side by side.
//
// Three different things get confused when a sandbox is described, so each is its
// own field for every capability:
//
//   requested   what the manifest asked for
//   checked     the state of each control that would enforce it, as established by
//               the active probes on THIS host in THIS process
//   enforced    true only when the platform's backend is an advertised one AND
//               every control the manifest depends on was proved. A host that
//               proves the controls but is not an advertised backend reports
//               `level: 'host-proved'` and `enforced: false` for everything.
//
// A capability that only an in-process check covers (tools, delegation) says so
// and is never `enforced`; that check explains a decision, it does not stop the
// task. A process-count cap is `enforced` only on a run whose process-cap probe
// proved it (the Linux namespace backend); on the macOS backend it is carried and
// reported `unverified`.
import { platformStatements } from './probes.js';

const FS_READ = ['fs-read-confinement', 'read-denial'];
const FS_WRITE = ['write-confinement', 'fs-multi-root-write'];
const COMMAND = ['tree-termination', 'env-scrub'];
const NETWORK = ['network', 'network-mediation'];

export const REPORT_LIMITATIONS = Object.freeze([
  'Top-level executables and arguments are mediated. A descendant inherits file and network confinement and is terminated with the task, but its own exec calls are not allowlisted.',
  'Metadata of the ancestors of a declared root is visible; the existence and size of other paths are not.',
  'HTTPS is an opaque tunnel to a declared destination: its payload is not inspected. Plaintext HTTP is filtered for secrets before it is forwarded.',
  'The mediation proxy accepts connections from any local process. It only forwards to declared destinations, so the exposure is the declared set.',
  'A process that double-forks and calls setsid between two supervisor sweeps can outlive the task; only a PID namespace or cgroup closes that gap.',
  'A process-count cap is enforced only on the Linux namespace backend, where it is applied by prlimit after the confinement is built and was proved by an active probe; on macOS it is per-user and system-wide on the host, a soft brake that is carried and not claimed.',
  'Address-space (memory) caps are not enforceable on macOS and are carried, not enforced.',
]);

function states(controls, names) {
  return Object.fromEntries(names.map((n) => [n, controls?.[n]?.state ?? 'not-probed']));
}

/**
 * @param {object} o
 * @param {{manifest: object}} o.bound
 * @param {{platform:string, backend:string, controls:object, probeDigest:string}} o.probeReport
 * @param {'enforced'|'host-proved'|'none'} o.level
 * @param {string[]} o.required   controls the manifest depends on
 */
export function buildCapabilityReport({ bound, probeReport, level, required }) {
  const m = bound.manifest;
  const c = probeReport?.controls || {};
  const allProved = required.every((n) => c[n]?.state === 'proved');
  const enforcedOn = (names) => level === 'enforced' && names.every((n) => c[n]?.state === 'proved') && allProved;
  const fileLimitProved = c['file-size-limit']?.state === 'proved';
  return {
    version: 1,
    platform: probeReport?.platform ?? process.platform,
    backend: probeReport?.backend ?? 'disabled',
    level,
    probeDigest: probeReport?.probeDigest ?? null,
    platforms: platformStatements(),
    controls: Object.fromEntries(Object.entries(c).map(([k, v]) => [k, { state: v.state, ...(v.reason ? { reason: v.reason } : {}) }])),
    capabilities: [
      { kind: 'filesystem-read', requested: { roots: m.filesystem.read.length + m.filesystem.write.length }, checked: states(c, FS_READ), enforcedBy: 'runner', enforced: enforcedOn(FS_READ) },
      { kind: 'filesystem-write', requested: { roots: m.filesystem.write.length }, checked: states(c, FS_WRITE), enforcedBy: 'runner', enforced: enforcedOn(FS_WRITE) },
      { kind: 'command', requested: { commands: m.commands.length }, checked: states(c, COMMAND), enforcedBy: 'runner', enforced: enforcedOn(COMMAND), descendantExec: 'not-allowlisted' },
      {
        kind: 'network', requested: { destinations: m.network.length }, checked: states(c, m.network.length ? NETWORK : ['network']),
        enforcedBy: m.network.length ? 'proxy' : 'runner', enforced: enforcedOn(m.network.length ? NETWORK : ['network']),
        payloadFiltering: 'plaintext-http-only',
      },
      { kind: 'tool', requested: { tools: m.tools.length }, checked: {}, enforcedBy: 'in-process-policy', enforced: false },
      { kind: 'delegation', requested: { allow: m.delegation.allow, maxDepth: m.delegation.maxDepth }, checked: {}, enforcedBy: 'in-process-policy', enforced: false },
    ],
    resources: {
      timeoutMs: { requested: m.resources.timeoutMs ?? null, enforced: level === 'enforced', by: 'supervisor deadline with process-tree termination' },
      maxOutputBytes: { requested: m.resources.maxOutputBytes ?? null, enforced: level === 'enforced', by: 'supervisor output cap with process-tree termination' },
      maxFileSizeKb: { requested: m.resources.maxFileSizeKb ?? null, enforced: level === 'enforced' && fileLimitProved, state: c['file-size-limit']?.state ?? 'not-probed' },
      maxProcesses: { requested: m.resources.maxProcesses ?? null, enforced: m.resources.maxProcesses != null && level === 'enforced' && c['process-cap']?.state === 'proved', state: c['process-cap']?.state === 'proved' ? 'proved' : 'unverified' },
      maxMemoryMiB: { requested: m.resources.maxMemoryMiB ?? null, enforced: false, state: 'not-enforced' },
    },
    limitations: [...REPORT_LIMITATIONS],
  };
}
