// The child half of supervised-analyzers.js (E6-05). Runs ONE exported function in its own process and reports the result over the IPC channel. It is
// started by the supervisor, never imported: the supervisor owns the limits, the deadline and the kill, so a child that hangs, exhausts memory or
// forks more processes can be stopped from outside without its cooperation.
import { pathToFileURL } from 'node:url';

async function main() {
  const spec = JSON.parse(process.env.AGENTIC_SECURITY_SUPERVISED_SPEC || '{}');
  try {
    const mod = await import(pathToFileURL(spec.modulePath).href);
    if (typeof mod[spec.exportName] !== 'function') throw new Error(`${spec.exportName} is not an exported function of ${spec.modulePath}`);
    const result = await mod[spec.exportName](...(spec.args || []));
    process.send({ ok: true, result }, () => process.exit(0));
  } catch (e) {
    process.send({ ok: false, error: String((e && e.message) || e).slice(0, 2000) }, () => process.exit(1));
  }
}
main();
