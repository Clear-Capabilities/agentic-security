#!/usr/bin/env node
// A local blocked-capability example (DOC-001.AC02): bind a deny-by-default capability manifest and show three refusals, none of
// which executes anything.
//
//   node scripts/blocked-capability-example.mjs
//
//   1. a read of a protected-looking path outside every declared root is denied by the policy decision;
//   2. a command the manifest does not list is blocked by the runner with a reviewable, narrowest proposed change (the proposal is
//      data for an operator; nothing here applies it);
//   3. without the development opt-in, an isolation-required task on this host is reported unsupported (or blocked with the
//      missing control named), never run.
//
// The runner is reached through `runCapabilityTask` with the `capability-enforcement` feature enabled for this one process (it is
// off by default and operator-only). No target process is started in any of the three. The manifest is synthetic.
//
// Exit: 0 all three were refused as described / 1 one was not.
import os from 'node:os';
import path from 'node:path';
import { bindManifest } from '../scanner/src/capabilities/manifest.js';
import { decide } from '../scanner/src/capabilities/decide.js';
import { runCapabilityTask } from '../scanner/src/capabilities/runner.js';
import { resolveAssuranceConfig } from '../scanner/src/posture/assurance/config.js';

const REV = 'a'.repeat(40);
const workRoot = path.join(os.tmpdir(), 'capability-example-root');
const bound = (() => {
  const r = bindManifest({
    schema: 'agentic-security/capability-manifest', schemaVersion: '1.0.0', taskId: 'doc-example-task',
    repository: { revision: REV }, policyVersion: 1,
    filesystem: { read: [workRoot], write: [] },
  });
  if (!r.ok) { console.error(`example manifest invalid: ${JSON.stringify(r.errors)}`); process.exit(1); }
  return r.bound;
})();
const config = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1' } });
let ok = true;

const read = decide(bound, { kind: 'filesystem-read', path: path.join(os.homedir(), '.ssh', 'id_ed25519') }, { binding: bound.binding });
console.log(`1. read of ~/.ssh/id_ed25519: ${read.verdict ?? read.decision}${read.code ? ` (${read.code})` : ''}`);
if ((read.verdict ?? read.decision) !== 'deny') ok = false;

const cmd = await runCapabilityTask(bound, { executable: '/bin/echo', args: ['hi'] }, { binding: bound.binding, config, allowUnadvertisedBackend: true });
console.log(`2. unlisted command /bin/echo: ${cmd.status}, code ${cmd.code}, executed ${cmd.executed}${cmd.policyCode ? `, policy ${cmd.policyCode}` : ''}`);
if (cmd.proposal) console.log(`   proposal (data only, not applied): missing ${cmd.proposal.missing?.capability} (${cmd.proposal.missing?.code}), risk ${cmd.proposal.risk}, self-grantable ${cmd.proposal.selfGrantable}`);
if (cmd.executed !== false || cmd.status !== 'blocked') ok = false;

const host = await runCapabilityTask(bound, { executable: '/bin/echo', args: [] }, { binding: bound.binding, config });
console.log(`3. isolation-required task on ${process.platform} without the development opt-in: ${host.status}, code ${host.code}, executed ${host.executed}`);
if (host.executed !== false || !['unsupported', 'blocked'].includes(host.status)) ok = false;

console.log(ok ? 'all three were refused; nothing was executed' : 'UNEXPECTED: a refusal did not happen as described');
process.exit(ok ? 0 : 1);
