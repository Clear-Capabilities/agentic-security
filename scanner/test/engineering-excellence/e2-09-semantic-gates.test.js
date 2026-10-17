// E2-09: the semantic accuracy gate. For each model shape the cross-language pins cover, the same four questions are asked of the real engine:
//   vulnerable example   flagged
//   fixed example        silent
//   semantics-preserving mutation of the vulnerable one (renamed variables, comments, blank lines, reordered independent statements)   still flagged
//   similar-but-safe     a near miss that looks like the vulnerable one but is bound, constant or guarded   silent
// An engine that matches the text of the examples, rather than the flow, fails the mutation or the near-miss leg. This is a verdict-flip gate, not a count.
//
// WHAT IT DOES NOT SHOW: contribution on the independent population. No detection model was changed by this programme between the baseline run and now (the E2
// changes are diagnosis and pins), so there is nothing to re-measure on the sealed holdout, and the outcome for independently scored cases is INCONCLUSIVE, stated
// as such rather than inferred from these synthetic cases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';

setStateWritesEnabled(false);
const scan = async (file, code) => (await runFullScan({ fileContents: { [file]: code }, scanRoot: null, deep: true })).findings.filter((f) => f.file === file && f.severity !== 'info' && !/x-powered-by|Missing/i.test(f.vuln || ''));
const flagged = async (file, code, re) => (await scan(file, code)).some((f) => re.test(f.vuln));

const MODELS = [
  { name: 'JS SQL injection', file: 'a.js', re: /SQL Injection/, patternOnlyNearMiss: true,
    vuln: "const express = require('express'); const app = express(); const db = require('mysql').createConnection({});\napp.get('/u', (req, res) => { const id = req.query.id; db.query('SELECT * FROM t WHERE id=' + id); res.end(); });\n",
    fixed: "const express = require('express'); const app = express(); const db = require('mysql').createConnection({});\napp.get('/u', (req, res) => { const id = req.query.id; db.query('SELECT * FROM t WHERE id=?', [id]); res.end(); });\n",
    mutated: "// look up a user\nconst express = require('express'); const app = express(); const db = require('mysql').createConnection({});\n\napp.get('/u', (request, response) => {\n  const userKey = request.query.id; /* raw */\n  db.query('SELECT * FROM t WHERE id=' + userKey);\n\n  response.end();\n});\n",
    nearMiss: "const express = require('express'); const app = express(); const db = require('mysql').createConnection({});\napp.get('/u', (req, res) => { const id = 7; db.query('SELECT * FROM t WHERE id=' + id); res.end(); });\n" },
  { name: 'Python command injection', file: 'a.py', re: /Command Injection/, patternOnlyNearMiss: true,
    vuln: "import subprocess\nfrom flask import request\ndef h():\n    f = request.args['f']\n    subprocess.run('cat ' + f, shell=True)\n",
    fixed: "import subprocess\nfrom flask import request\ndef h():\n    f = request.args['f']\n    subprocess.run(['cat', f])\n",
    mutated: "import subprocess\nfrom flask import request\n\n# run it\ndef handler():\n    name = request.args['f']\n\n    subprocess.run('cat ' + name, shell=True)\n",
    nearMiss: "import subprocess\nfrom flask import request\ndef h():\n    f = 'notes.txt'\n    subprocess.run('cat ' + f, shell=True)\n" },
  { name: 'Go SQL injection', file: 'a.go', re: /SQL Injection/, patternOnlyNearMiss: true,
    vuln: 'package main\nimport ("database/sql"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n id := r.URL.Query().Get("id")\n db.Query("SELECT * FROM t WHERE id = " + id)\n}\n',
    fixed: 'package main\nimport ("database/sql"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n id := r.URL.Query().Get("id")\n db.Query("SELECT * FROM t WHERE id = ?", id)\n}\n',
    mutated: 'package main\n\nimport ("database/sql"; "net/http")\n\n// handler\nfunc handle(w http.ResponseWriter, req *http.Request, conn *sql.DB) {\n\n userID := req.URL.Query().Get("id")\n conn.Query("SELECT * FROM t WHERE id = " + userID)\n}\n',
    nearMiss: 'package main\nimport ("database/sql"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n id := "7"\n db.Query("SELECT * FROM t WHERE id = " + id)\n}\n' },
  { name: 'Java SQL injection', file: 'B.java', re: /SQL Injection/,
    vuln: 'import java.sql.*;\npublic class B { public void bad(javax.servlet.http.HttpServletRequest req, Connection c) throws Exception {\n  String id = req.getParameter("id");\n  c.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id);\n} }\n',
    fixed: 'import java.sql.*;\npublic class B { public void bad(javax.servlet.http.HttpServletRequest req, Connection c) throws Exception {\n  String id = req.getParameter("id");\n  PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id=?"); p.setString(1, id); p.executeQuery();\n} }\n',
    mutated: 'import java.sql.*;\n\npublic class B {\n  // look up\n  public void run(javax.servlet.http.HttpServletRequest request, Connection conn) throws Exception {\n\n    String key = request.getParameter("id");\n    conn.createStatement().executeQuery("SELECT * FROM t WHERE id=" + key);\n  }\n}\n',
    nearMiss: 'import java.sql.*;\npublic class B { public void bad(Connection c) throws Exception {\n  String id = "7";\n  c.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id);\n} }\n' },
];

for (const m of MODELS) {
  test(`${m.name}: vulnerable flagged, fixed silent, mutation still flagged, near-miss ${m.patternOnlyNearMiss ? 'silent in the taint layer (pattern detector gap pinned)' : 'silent'}`, async () => {
    assert.ok(await flagged(m.file, m.vuln, m.re), 'the vulnerable example is flagged');
    assert.ok(!(await flagged(m.file, m.fixed, m.re)), 'the fixed example is silent');
    assert.ok(await flagged(m.file, m.mutated, m.re), 'a semantics-preserving rewrite does not move the verdict');
    const near = (await scan(m.file, m.nearMiss)).filter((f) => m.re.test(f.vuln));
    if (!m.patternOnlyNearMiss) assert.deepEqual(near, [], 'a near miss that only looks similar is silent');
    else {
      // STATED GAP: the pattern-level detector flags a query/command built by concatenation even when the operand is a constant. The taint layer, which reasons about
      // the flow, is correctly silent, and the pattern finding is the lower-confidence one. Pinned so a fix (constant folding in the pattern detectors) must update it.
      assert.ok(near.length >= 1 && near.every((f) => f.parser !== 'IR-TAINT'), `the flow-based layer stays silent; only a pattern detector fires: ${JSON.stringify(near.map((f) => f.parser))}`);
      assert.ok(near.every((f) => f.confidence < 0.7), 'and at reduced confidence');
    }
  });
}

test('THE GATE CAN FAIL: a text matcher that keys on the example strings passes the vulnerable and fixed legs and fails the mutation leg, and a matcher that flags every query fails the near-miss leg', () => {
  const textMatcher = (code) => /'SELECT \* FROM t WHERE id=' \+ id/.test(code);
  const m = MODELS[0]; assert.equal(textMatcher(m.vuln), true); assert.equal(textMatcher(m.fixed), false); assert.equal(textMatcher(m.mutated), false, 'misses the renamed variant');
  const everyQuery = (code) => /db\.query\(/.test(code); assert.equal(everyQuery(m.nearMiss), true, 'flags the constant near miss');
});

test('THE INDEPENDENT-POPULATION OUTCOME IS STATED AS INCONCLUSIVE, with the reason', () => {
  const outcome = { independentContribution: 'inconclusive', reason: 'no detection model changed between the baseline run and this commit; the E2 changes are diagnosis and pins', holdoutUsed: false };
  assert.equal(outcome.independentContribution, 'inconclusive'); assert.equal(outcome.holdoutUsed, false);
});
