// Python SAST sink-side tests (FR-PY-SAST — Phase-2 G3 blocker).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scanPythonSinks, _ruleCount } from '../src/sast/python-sinks.js';

const FIXTURE_DIR = join(import.meta.url.replace('file://', '').replace('/python-sinks.test.js', ''), 'fixtures', 'python-sinks');

test('scanPythonSinks returns empty for non-Python files', () => {
  assert.deepEqual(scanPythonSinks('foo.js', 'os.system("ls")'), []);
});

test('scanPythonSinks fires on the vulnerable fixture across all families', () => {
  const raw = readFileSync(join(FIXTURE_DIR, 'vulnerable', 'app.py'), 'utf8');
  const findings = scanPythonSinks('vulnerable/app.py', raw);
  const fams = new Set(findings.map(f => f.family));
  assert.ok(fams.has('sql-injection'),            'SQL injection should fire');
  assert.ok(fams.has('command-injection'),        'command injection should fire');
  assert.ok(fams.has('insecure-deserialization'), 'pickle/yaml should fire');
  assert.ok(fams.has('code-injection'),           'eval should fire');
  assert.ok(fams.has('path-traversal'),           'send_file should fire');
  assert.ok(fams.has('ssrf'),                     'requests with user url should fire');
  assert.ok(fams.has('insecure-http'),            'requests verify=False should fire');
});

test('scanPythonSinks does NOT fire on the clean fixture', () => {
  const raw = readFileSync(join(FIXTURE_DIR, 'clean', 'app.py'), 'utf8');
  const findings = scanPythonSinks('clean/app.py', raw);
  // Allow incidental "open" / generic findings from the regex catalogue,
  // but the family-set should not contain anything that signals a sink-side
  // vuln we've explicitly written-clean.
  const fams = new Set(findings.map(f => f.family));
  for (const banned of ['sql-injection', 'command-injection', 'insecure-deserialization', 'code-injection']) {
    assert.ok(!fams.has(banned),
      `clean fixture must not produce ${banned} findings (got: ${[...fams].join(', ')})`);
  }
});

test('scanPythonSinks parameterized query is not flagged', () => {
  const raw = `
from sqlalchemy import text
result = conn.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
`;
  const findings = scanPythonSinks('a.py', raw);
  assert.equal(findings.filter(f => f.family === 'sql-injection').length, 0);
});

test('scanPythonSinks f-string SQL assignment is flagged', () => {
  const raw = `name = request.json['name']\nq = f"SELECT * FROM users WHERE name = '{name}'"\nconn.execute(text(q))`;
  const findings = scanPythonSinks('a.py', raw);
  assert.ok(findings.some(f => f.family === 'sql-injection'));
});

// Real customer false positives (both reproduced independently): the old
// regex required only a SQL-keyword-shaped substring (case-insensitive, no
// word boundary) co-occurring with a `{...}` interpolation ANYWHERE in an
// f-string — so it matched "Select" inside "Selected" and "select" inside
// the ordinary variable name "selected", regardless of whether the f-string
// was ever assigned to a variable or reached a SQL sink.
test('scanPythonSinks: "Selected" in an exception message is not SQL', () => {
  const raw = 'raise RuntimeError(\n    f"Selected TAR members exceed {MAX_ARCHIVE_TOTAL_BYTES:,} expanded bytes"\n)';
  const findings = scanPythonSinks('a.py', raw);
  assert.equal(findings.filter(f => f.family === 'sql-injection').length, 0,
    'an exception message is not a SQL statement');
});

test('scanPythonSinks: "selected" as an ordinary variable name in a console print is not SQL', () => {
  const raw = [
    'selected = bundles[:MAX_CANDIDATES]',
    'print(',
    '    f"  [{position}/{len(selected)}] {bundle.title[:72]} -- "',
    '    f"{len(successful_pages)} readable page(s)"',
    ')',
  ].join('\n');
  const findings = scanPythonSinks('a.py', raw);
  assert.equal(findings.filter(f => f.family === 'sql-injection').length, 0,
    'a list slice printed to the console is not a SQL statement, and the value is never assigned');
});

test('scanPythonSinks: the reported regression corpus negative/positive pair', () => {
  // From the customer's own suggested minimal regression.
  const negatives = [
    'selected = items[:10]\nprint(f"{len(selected)} items")',
    'raise RuntimeError("Selected items exceed the limit")',
  ];
  for (const raw of negatives) {
    assert.equal(scanPythonSinks('a.py', raw).filter(f => f.family === 'sql-injection').length, 0,
      `must not fire: ${raw}`);
  }
  const positive = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
  assert.ok(scanPythonSinks('a.py', positive).some(f => f.family === 'sql-injection'),
    'a real inline f-string passed straight to cursor.execute must still fire');
});

test('scanPythonSinks os.system + var is flagged; os.system + literal is not', () => {
  const bad  = 'os.system("ls " + user_input)';
  const good = 'os.system("ls /tmp")';
  assert.ok(scanPythonSinks('a.py', bad).some(f => f.family === 'command-injection'));
  assert.equal(scanPythonSinks('b.py', good).filter(f => f.family === 'command-injection').length, 0);
});

test('scanPythonSinks subprocess shell=True is flagged', () => {
  const raw = `subprocess.run(f"nslookup {host}", shell=True)`;
  const findings = scanPythonSinks('a.py', raw);
  assert.ok(findings.some(f => f.family === 'command-injection'));
});

test('scanPythonSinks pickle.loads is flagged', () => {
  const raw = `data = pickle.loads(request.data)`;
  assert.ok(scanPythonSinks('a.py', raw).some(f => f.family === 'insecure-deserialization'));
});

test('scanPythonSinks yaml.safe_load is NOT flagged; yaml.load IS', () => {
  assert.ok(scanPythonSinks('a.py', `yaml.load(request.data)`).some(f => f.family === 'insecure-deserialization'));
  assert.equal(scanPythonSinks('b.py', `yaml.safe_load(request.data)`).filter(f => f.family === 'insecure-deserialization').length, 0);
});

test('scanPythonSinks eval/exec on request data is flagged', () => {
  assert.ok(scanPythonSinks('a.py', `eval(request.json['expr'])`).some(f => f.family === 'code-injection'));
  assert.ok(scanPythonSinks('b.py', `exec(request.data)`).some(f => f.family === 'code-injection'));
});

test('scanPythonSinks send_file with user-controlled path is flagged', () => {
  const raw = `send_file(request.args.get('path'))`;
  assert.ok(scanPythonSinks('a.py', raw).some(f => f.family === 'path-traversal'));
});

test('scanPythonSinks requests verify=False is flagged', () => {
  const raw = `requests.get(url, verify=False)`;
  assert.ok(scanPythonSinks('a.py', raw).some(f => f.family === 'insecure-http'));
});

test('scanPythonSinks skips test files', () => {
  const raw = `os.system("rm -rf /tmp/" + user)`;
  assert.deepEqual(scanPythonSinks('tests/test_foo.py', raw), []);
  assert.deepEqual(scanPythonSinks('app/test_bar.py', raw), []);
});

test('rules registered count matches expectations', () => {
  assert.ok(_ruleCount >= 15, `expected ≥ 15 Python detector rules, got ${_ruleCount}`);
});
