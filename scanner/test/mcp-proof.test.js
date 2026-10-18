// The MCP proof tools (PRD 1): they run code, so every refusal path is tested alongside the happy path.
import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/mcp/server.js';
import { signLastScan } from '../src/posture/integrity.js';
import { sandboxAvailable } from '../src/sandbox/index.js';
import { TOOL_CAPABILITIES } from '../src/capabilities/tool-registry.js';

const sandbox = sandboxAvailable() ? false : 'no confinement backend on this host';
const LIB = "const { execSync } = require('child_process');\nfunction run(name) {\n  execSync('echo ' + name, { stdio: 'ignore' });\n}\nmodule.exports = { run };\n";
const SAFE = "const { execFileSync } = require('child_process');\nfunction run(name) {\n  execFileSync('echo', [name], { stdio: 'ignore' });\n}\nmodule.exports = { run };\n";
const FINDING = { id: 'F1', stableId: 'stable-0001-f1', cwe: 'CWE-78', file: 'lib.js', line: 3, parser: 'IR-TAINT', severity: 'critical', vuln: 'command injection' };

async function session({ findings = [FINDING], files = { 'lib.js': LIB } } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-proof-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"s"}');
  for (const [f, c] of Object.entries(files)) { await fsp.mkdir(path.dirname(path.join(dir, f)), { recursive: true }); await fsp.writeFile(path.join(dir, f), c); }
  const body = JSON.stringify({ findings });
  await fsp.writeFile(path.join(dir, '.agentic-security', 'last-scan.json'), body);
  await fsp.writeFile(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
  const { handleRequest } = createServer({ sessionRoot: dir });
  return { dir, call: async (name, args) => JSON.parse((await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })).result.content[0].text), cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('both tools are registered, classified as mutating, and have closed schemas', async () => {
  assert.equal(TOOL_CAPABILITIES.prove_finding.effect, 'mutating'); assert.equal(TOOL_CAPABILITIES.prove_fix.effect, 'mutating');
  const s = await session();
  try {
    const { handleRequest } = createServer({ sessionRoot: s.dir });
    const list = (await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/list' })).result.tools;
    for (const n of ['prove_finding', 'prove_fix']) { const t = list.find((x) => x.name === n); assert.ok(t, n); assert.equal(t.inputSchema.additionalProperties, false); assert.ok(t.inputSchema.required.includes('confirm')); }
  } finally { await s.cleanup(); }
});

test('nothing runs without confirm, a verified scan, a real non-shadow finding, or an acceptable reproducer', async () => {
  const s = await session({ findings: [FINDING, { ...FINDING, id: 'S1', stableId: 'stable-0002-s1', _shadow: true }] });
  try {
    const noConfirm = await s.call('prove_finding', { finding_id: 'F1', confirm: false });
    assert.equal(noConfirm.ok, false); assert.match(noConfirm.reason, /requires confirm: true/);
    assert.match((await s.call('prove_finding', { finding_id: 'NOPE', confirm: true })).reason, /Finding not found/);
    assert.match((await s.call('prove_finding', { finding_id: 'S1', confirm: true })).reason, /shadow findings cannot be proven/);
    const hostile = await s.call('prove_finding', { finding_id: 'F1', confirm: true, reproducer: { schema: 'agentic-security/reproducer', version: 1, findingId: 'F1', lang: 'javascript', files: { '../../etc/x': 'y' }, run: 'rm -rf /', oracle: { type: 'command_execution' } } });
    assert.equal(hostile.ok, false); assert.match(hostile.reason, /not acceptable/); assert.match(hostile.reason, /unsafe file path|argv array/);
    const unproven = await session({ findings: [{ ...FINDING, cwe: 'CWE-89' }] });
    try { assert.match((await unproven.call('prove_finding', { finding_id: 'F1', confirm: true })).reason, /none could be generated: no payload and oracle exist for CWE-89/); } finally { await unproven.cleanup(); }
    // tampered scan: the signature no longer matches
    await fsp.writeFile(path.join(s.dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ ...FINDING, line: 99 }] }));
    assert.match((await s.call('prove_finding', { finding_id: 'F1', confirm: true })).reason, /integrity check/);
    assert.equal(fs.existsSync(path.join(s.dir, '.agentic-security', 'proofs')), false, 'no refusal wrote a proof');
  } finally { await s.cleanup(); }
});

test('prove_finding confirms a generated reproducer by execution and reports state and counts, not output', { skip: sandbox, timeout: 120000 }, async () => {
  const s = await session();
  try {
    const r = await s.call('prove_finding', { finding_id: 'F1', confirm: true });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.state, 'EXPLOIT_CONFIRMED'); assert.equal(r.attempts.successes, 3); assert.equal(r.independentReplay, 'confirmed');
    assert.equal(r.generated.shape, 'function'); assert.equal(r.stored, true); assert.match(r.note, /Not reproduced is not proof of safety/);
    assert.equal('stdout' in r, false); assert.doesNotMatch(JSON.stringify(r), /SECRET-/);
    assert.equal(r._meta.untrusted_excerpts, true);
  } finally { await s.cleanup(); }
});

test('prove_fix verifies a patch against the original exploit, writes nothing to the project, and reports siblings', { skip: sandbox, timeout: 180000 }, async () => {
  const s = await session({ files: { 'lib.js': LIB, 'other.js': "const { execSync } = require('child_process');\nfunction go(arg) {\n  execSync('echo ' + arg, { stdio: 'ignore' });\n}\nmodule.exports = go;\n" } });
  try {
    const good = await s.call('prove_fix', { finding_id: 'F1', confirm: true, patch: { 'lib.js': SAFE } });
    assert.equal(good.ok, true, JSON.stringify(good));
    assert.equal(good.legs.postPatch.exploitSucceeded, 0); assert.match(good.report, /Post-patch exploit: BLOCKED/);
    assert.ok(good.siblings.some((x) => x.file === 'other.js'), 'the same shape elsewhere is reported');
    assert.equal(fs.readFileSync(path.join(s.dir, 'lib.js'), 'utf8'), LIB, 'the project file is untouched');
    const bad = await s.call('prove_fix', { finding_id: 'F1', confirm: true, patch: { 'lib.js': LIB.replace('execSync(', 'execSync(').replace('stdio', 'stdio') } });
    assert.equal(bad.verified, false); assert.match(bad.legs.postPatch.exploitSucceeded > 0 ? 'still succeeds' : bad.reason ?? '', /still succeeds|exploit/);
  } finally { await s.cleanup(); }
});

test('prove_fix refuses escaping, reserved and missing patch paths before anything runs', async () => {
  const s = await session();
  try {
    assert.match((await s.call('prove_fix', { finding_id: 'F1', confirm: true, patch: { '../../etc/cron.d/x': 'y' } })).reason, /path-escape refused/);
    assert.match((await s.call('prove_fix', { finding_id: 'F1', confirm: true, patch: { '.git/hooks/pre-commit': 'y' } })).reason, /reserved path refused/);
    assert.match((await s.call('prove_fix', { finding_id: 'F1', confirm: false, patch: { 'lib.js': SAFE } })).reason, /requires confirm: true/);
    // a missing required argument is refused by the schema layer, before the handler
    const { handleRequest } = createServer({ sessionRoot: s.dir });
    const raw = await handleRequest({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'prove_fix', arguments: { finding_id: 'F1', confirm: true } } });
    assert.match(raw.result.content[0].text, /Invalid arguments/);
  } finally { await s.cleanup(); }
});
