// Python reproducer generation (PRD 1): what it builds, what it refuses by name, and, with the sandbox, that a generated reproducer
// is CONFIRMED on vulnerable code and NOT confirmed on the fixed twin by the unchanged proof machinery.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { generateReproducer } from '../../src/posture/proof-fabric/generate.js';
import { proveFinding } from '../../src/posture/proof-fabric/orchestrator.js';
import { validateReproducer } from '../../src/posture/proof-fabric/reproducer.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { skipUnlessRuns } from '../helpers/toolchain-probe.js';

const py = spawnSync('python3', ['-c', 'import sys; print(hasattr(sys, "stdlib_module_names"))'], { encoding: 'utf8' });
const hasPy = py.status === 0 && py.stdout.trim() === 'True';
const skipNoPy = hasPy ? false : 'python3 3.10+ is not installed';
const skipSandbox = !hasPy ? skipNoPy : !sandboxAvailable() ? 'no confinement backend on this host' : skipUnlessRuns('python');
const repo = (files) => { const d = mkTestTmp('gen-py-'); for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), c); } return d; };
const F = (over = {}) => ({ id: 'P1', stableId: 'P1', cwe: 'CWE-78', file: 'app.py', line: 4, parser: 'IR-TAINT', ...over });
const prove = (finding, dir, reproducer) => proveFinding({ finding, reproducer, sourceRoot: dir, policy: { timeoutMs: 20000 } });

const SCRIPT_VULN = "import os\nimport sys\nname = sys.argv[1] if len(sys.argv) > 1 else ''\nos.system('echo hello ' + name)\n";
const SCRIPT_SAFE = "import subprocess\nimport sys\nname = sys.argv[1] if len(sys.argv) > 1 else ''\nsubprocess.run(['echo', 'hello', name])\n";
const FN_VULN = "import os\n\ndef greet(name):\n    os.system('echo hello ' + name)\n\nif __name__ == '__main__':\n    greet('world')\n";
const FN_SAFE = "import subprocess\n\ndef greet(name):\n    subprocess.run(['echo', 'hello', name])\n\nif __name__ == '__main__':\n    greet('world')\n";

test('script shape: a program that reads sys.argv[1] is run with the payload', { skip: skipNoPy }, () => {
  const dir = repo({ 'app.py': "import os\nimport sys\n\ndef main():\n    os.system('echo ' + sys.argv[1])\n\nif __name__ == '__main__':\n    main()\n" });
  const r = generateReproducer({ finding: F({ line: 5 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'script'); assert.equal(r.reproducer.lang, 'python');
  assert.deepEqual(validateReproducer(r.reproducer), []);
  assert.deepEqual(r.reproducer.run, ['{{PYTHON}}', 'target.py', 'x; touch {{CANARY:command}}']);
});

test('function shape: a module-level function is imported (not as __main__) and called with the payload', { skip: skipNoPy }, () => {
  const dir = repo({ 'app.py': FN_VULN });
  const r = generateReproducer({ finding: F({ line: 4 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.basis.shape, 'function'); assert.equal(r.basis.function, 'greet(name)');
  const h = r.reproducer.files['harness.py'];
  assert.match(h, /spec_from_file_location\("target", "target\.py"\)/); assert.match(h, /fn\(payload\)/);
  assert.ok(r.basis.assumptions.some((a) => /every parameter/.test(a)));
  assert.deepEqual(validateReproducer(r.reproducer), []);
});

test('refusals name the reason: third-party import, decorated function, no parameters, not in a function, wrong class, bad syntax', { skip: skipNoPy }, () => {
  const refuse = (files, finding, re) => { const r = generateReproducer({ finding: F(finding), root: repo(files) }); assert.equal(r.ok, false); assert.match(r.reason, re); };
  refuse({ 'app.py': "import flask\nimport os\n\ndef f(x):\n    os.system(x)\n" }, { line: 5 }, /needs flask/);
  refuse({ 'app.py': "import os\n\n@app.route('/x')\ndef f(x):\n    os.system(x)\n" }, { line: 5 }, /decorated/);
  refuse({ 'app.py': "import os\n\ndef f():\n    os.system('ls')\n" }, { line: 4 }, /no parameters/);
  refuse({ 'app.py': "import os\nos.system('ls')\n" }, { line: 2 }, /not inside a module-level function/);
  refuse({ 'app.py': "def f(\n" }, { line: 1 }, /could not be parsed by Python/);
  refuse({ 'app.py': FN_VULN }, { cwe: 'CWE-89' }, /no payload and oracle exist for CWE-89/);
  refuse({ 'app.py': "import os\n\ndef f(p):\n    return open(p).read()\n" }, { cwe: 'CWE-22', line: 4 }, /not a write/);
  refuse({ 'app.rb': 'x' }, { file: 'app.rb' }, /JavaScript and Python only/);
});

test('a sibling module in the same directory is carried into the workspace; its path cannot escape the repository', { skip: skipNoPy }, () => {
  const dir = repo({ 'pkg/app.py': "import helper\nimport os\n\ndef f(x):\n    os.system(helper.wrap(x))\n", 'pkg/helper.py': 'def wrap(s):\n    return s\n' });
  const r = generateReproducer({ finding: F({ file: 'pkg/app.py', line: 5 }), root: dir });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.reproducer.sources['helper.py'], 'pkg/helper.py'); assert.equal(r.reproducer.sources['target.py'], 'pkg/app.py');
  assert.equal(generateReproducer({ finding: F({ file: '../../etc/passwd.py' }), root: dir }).ok, false);
});

test('end to end: the generated Python reproducer is confirmed on vulnerable code and NOT on the fixed twin', { skip: skipSandbox, timeout: 120000 }, async () => {
  for (const [vuln, safe, line] of [[SCRIPT_VULN, SCRIPT_SAFE, 4], [FN_VULN, FN_SAFE, 4]]) {
    const v = repo({ 'app.py': vuln });
    const gen = generateReproducer({ finding: F({ line }), root: v });
    assert.equal(gen.ok, true, gen.reason);
    const proof = await prove(F({ line }), v, gen.reproducer);
    assert.equal(proof.state, 'EXPLOIT_CONFIRMED', `${proof.outcome}: ${proof.degradation}`);
    const s = repo({ 'app.py': safe });
    const gen2 = generateReproducer({ finding: F({ line }), root: s });
    assert.equal(gen2.ok, true, gen2.reason);
    const proof2 = await prove(F({ line }), s, gen2.reproducer);
    assert.notEqual(proof2.state, 'EXPLOIT_CONFIRMED', 'the fixed twin must not be confirmed');
  }
});
