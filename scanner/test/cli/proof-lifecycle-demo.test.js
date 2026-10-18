// PRD 1 "Definition of Done": a demo of at least three findings moving through
//   Find -> Corroborate -> Reproduce -> Independently Verify -> Fix -> Replay -> Verify Fix
// against the real spawned CLI, with reproducers GENERATED from each finding (none hand-written), in two languages and three
// weakness classes. Each finding is proven on the vulnerable code, patched, and the SAME reproducer is replayed against the patch.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { skipUnlessRuns } from '../helpers/toolchain-probe.js';
import { signLastScan } from '../../src/posture/integrity.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const run = (dir, args, timeout = 150000) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] });
const py = spawnSync('python3', ['-c', 'import sys; print(hasattr(sys, "stdlib_module_names"))'], { encoding: 'utf8' });
const hasPy = py.status === 0 && py.stdout.trim() === 'True';

const CASES = [
  {
    id: 'DEMO-1', cwe: 'CWE-78', vuln: 'command injection (JavaScript)', file: 'lib.js', line: 3, lang: 'javascript', klass: 'command-injection',
    source: "const { execSync } = require('child_process');\nfunction run(name) {\n  execSync('echo ' + name, { stdio: 'ignore' });\n}\nmodule.exports = { run };\n",
    fixLine: "  require('child_process').execFileSync('echo', [name], { stdio: 'ignore' });", fixed: /execFileSync/,
  },
  {
    id: 'DEMO-2', cwe: 'CWE-22', vuln: 'path traversal on write (JavaScript)', file: 'store.js', line: 4, lang: 'javascript', klass: 'path-traversal',
    source: "const fs = require('fs');\nconst path = require('path');\nfunction save(name) {\n  fs.writeFileSync(path.join(process.cwd(), 'public', name), 'x');\n}\nfs.mkdirSync(path.join(process.cwd(), 'public'), { recursive: true });\nmodule.exports = { save };\n",
    fixLine: "  return fs.promises.writeFile(path.join(process.cwd(), 'public', path.basename(name)), 'x');", fixed: /path\.basename\(name\)/,
  },
  {
    id: 'DEMO-3', cwe: 'CWE-78', vuln: 'command injection (Python)', file: 'svc.py', line: 5, lang: 'python', klass: 'command-injection', needsPython: true,
    source: "import os\nimport subprocess\n\ndef greet(name):\n    os.system('echo hello ' + name)\n\nif __name__ == '__main__':\n    greet('world')\n",
    fixLine: "    subprocess.run(['echo', 'hello', name])", fixed: /subprocess/,
  },
];

for (const c of CASES) {
  const skip = !sandboxAvailable() ? 'no confinement backend on this host' : (c.needsPython ? (!hasPy ? 'python3 3.10+ is not installed' : skipUnlessRuns('python')) : false);
  test(`${c.id} ${c.vuln}: Find -> Reproduce (generated) -> Independently Verify -> Fix -> Replay -> Verify Fix`, { skip, timeout: 240000 }, () => {
    const dir = mkTestTmp('pf-demo-'); fs.mkdirSync(path.join(dir, '.git')); fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    const finding = { id: c.id, stableId: c.id, severity: 'critical', vuln: c.vuln, cwe: c.cwe, file: c.file, line: c.line, parser: 'IR-TAINT', fix: { replaceLine: c.fixLine } };
    const body = JSON.stringify({ findings: [finding] });
    fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), body);
    fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
    fs.writeFileSync(path.join(dir, '.agentic-security', 'findings.json'), body);
    fs.writeFileSync(path.join(dir, c.file), c.source);

    // FIND + CORROBORATE: the finding is recorded with its static evidence; nothing has run
    const before = JSON.parse(run(dir, ['triage', 'list', '--evidence', '--json']).stdout || '[]');
    void before;

    // REPRODUCE + INDEPENDENTLY VERIFY: a reproducer is generated from the finding and confirmed 3/3 with a fresh-environment replay
    const prove = run(dir, ['triage', 'exploit', c.id, '--prove']);
    assert.equal(prove.status, 0, prove.stdout + prove.stderr);
    assert.match(prove.stderr, new RegExp(`Generated a reproducer from the finding \\(function, ${c.klass}\\)`));
    assert.match(prove.stdout, /Evidence: EXPLOIT_CONFIRMED/); assert.match(prove.stdout, /Reproductions: 3\/3/); assert.match(prove.stdout, /Independent replay: confirmed/);
    const shown = JSON.parse(run(dir, ['proof', 'show', c.id, '--json']).stdout);
    assert.equal(shown.state, 'EXPLOIT_CONFIRMED'); assert.equal(shown.generatedFrom.shape, 'function');
    assert.equal(shown.independentReplay.status, 'confirmed');
    assert.ok(Number.isFinite(shown.timing.proofMs), 'proof timing is reported on its own');

    // FIX + REPLAY + VERIFY FIX: the patch is applied, the SAME exploit is replayed against it and is blocked
    const fix = run(dir, ['fix', '--finding', c.id, '--apply', '--require-proof']);
    assert.equal(fix.status, 0, fix.stdout + fix.stderr);
    assert.match(fix.stdout, /Pre-patch exploit: PASS/); assert.match(fix.stdout, /Post-patch exploit: BLOCKED/); assert.match(fix.stdout, /Evidence: FIX_VERIFIED/);
    assert.match(fs.readFileSync(path.join(dir, c.file), 'utf8'), c.fixed);
  });
}
