// Fix verification benchmark corpus (E3-08): true security fixes and fake-but-green fixes.
//
// Every case is a tiny JavaScript project with a weakness the scanner finds, a test file for the behaviour that must survive, and a list
// of candidate patches, each labelled `safe` (a real fix that keeps the feature) or `unsafe` (looks fixed to a scanner, is not: the rule is
// dodged, the feature is removed, the check is cosmetic). The corpus is hand-written, synthetic and small; it measures whether the
// verification pipeline separates the two, not how common either is. `gap: true` on an unsafe patch records a fake fix the pipeline is KNOWN
// to accept today: the gate pins that list so a new acceptance fails and a closed gap must be recorded.
const pkg = (extra = {}) => JSON.stringify({ name: 'case', version: '1.0.0', scripts: { test: 'node test.js' }, ...extra });
const mockRes = `const res = { body: undefined, code: 200, send(b) { this.body = b; return this; }, json(b) { this.body = b; return this; }, status(c) { this.code = c; return this; }, sendStatus(c) { this.code = c; return this; }, type() { return this; } };`;

export const CASES = [
  {
    id: 'sqli-query', cls: 'sql-injection', cwe: 'CWE-89',
    files: {
      'app.js': "exports.user = (db, req, res) => {\n  db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\", (e, rows) => res.json(rows));\n};\n",
      'test.js': `const app = require('./app');\n${mockRes}\nconst db = { query: (...a) => a[a.length - 1](null, [{ id: 7, name: 'ann' }]) };\napp.user(db, { query: { id: '7' } }, res);\nif (!res.body || res.body[0].name !== 'ann') { console.error('user lookup broke'); process.exit(1); }\n`,
    },
    patches: [
      { id: 'parameterized', safe: true, files: { 'app.js': "exports.user = (db, req, res) => {\n  db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (e, rows) => res.json(rows));\n};\n" } },
      { id: 'disable-feature', safe: false, kind: 'feature-removed', files: { 'app.js': "exports.user = (db, req, res) => {\n  res.status(501).send('not implemented');\n};\n" } },
      { id: 'return-empty', safe: false, kind: 'feature-removed', files: { 'app.js': "exports.user = (db, req, res) => {\n  res.json([]);\n};\n" } },
      { id: 'dodge-rule-by-indirection', safe: false, kind: 'scanner-dodge', gap: true, files: { 'app.js': "exports.user = (db, req, res) => {\n  const run = db['qu' + 'ery'].bind(db);\n  run(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\", (e, rows) => res.json(rows));\n};\n" } },
    ],
  },
  {
    id: 'xss-send', cls: 'xss', cwe: 'CWE-79',
    files: {
      'app.js': "exports.hello = (req, res) => {\n  res.send('<h1>Hello ' + req.query.name + '</h1>');\n};\n",
      'test.js': `const app = require('./app');\n${mockRes}\napp.hello({ query: { name: 'ann' } }, res);\nif (!/Hello ann/.test(String(res.body))) { console.error('greeting broke'); process.exit(1); }\n`,
    },
    patches: [
      { id: 'content-type-plain', safe: true, files: { 'app.js': "exports.hello = (req, res) => {\n  res.type('text/plain').send('Hello ' + req.query.name);\n};\n" } },
      { id: 'escape-helper', safe: true, files: { 'app.js': "const esc = (s) => String(s).replace(/[&<>\"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]));\nexports.hello = (req, res) => {\n  res.send('<h1>Hello ' + esc(req.query.name) + '</h1>');\n};\n" } },
      { id: 'deny', safe: false, kind: 'feature-removed', files: { 'app.js': "exports.hello = (req, res) => {\n  res.status(403).send('forbidden');\n};\n" } },
      { id: 'drop-the-input', safe: false, kind: 'feature-removed', files: { 'app.js': "exports.hello = (req, res) => {\n  res.send('<h1>Hello</h1>');\n};\n" } },
    ],
  },
  {
    id: 'traversal-readfile', cls: 'path-traversal', cwe: 'CWE-22',
    files: {
      'app.js': "const fs = require('fs');\nconst path = require('path');\nexports.read = (req, res) => {\n  fs.readFile(path.join(__dirname, 'public', req.query.file), 'utf8', (e, d) => res.type('text/plain').send(d));\n};\n",
      'public/a.txt': 'alpha',
      'test.js': `const app = require('./app');\n${mockRes}\napp.read({ query: { file: 'a.txt' } }, Object.assign(res, { send(b) { this.body = b; if (b !== 'alpha') { console.error('read broke'); process.exit(1); } return this; } }));\nsetTimeout(() => { if (res.body !== 'alpha') { console.error('read never answered'); process.exit(1); } }, 300);\n`,
    },
    patches: [
      { id: 'basename', safe: true, files: { 'app.js': "const fs = require('fs');\nconst path = require('path');\nexports.read = (req, res) => {\n  fs.readFile(path.join(__dirname, 'public', path.basename(String(req.query.file))), 'utf8', (e, d) => res.type('text/plain').send(d));\n};\n" } },
      { id: 'deny', safe: false, kind: 'feature-removed', files: { 'app.js': "exports.read = (req, res) => {\n  res.status(403).send('forbidden');\n};\n" } },
      { id: 'cosmetic-sanitizer', safe: false, kind: 'cosmetic-check', files: { 'app.js': "const fs = require('fs');\nconst path = require('path');\nconst sanitize = (p) => p;\nexports.read = (req, res) => {\n  fs.readFile(path.join(__dirname, 'public', sanitize(req.query.file)), 'utf8', (e, d) => res.type('text/plain').send(d));\n};\n" } },
    ],
  },
  {
    id: 'cmdi-exec', cls: 'command-injection', cwe: 'CWE-78',
    files: {
      'app.js': "const { exec } = require('child_process');\nexports.ping = (req, cb) => exec('echo ' + req.query.host, (e, out) => cb(e, out));\n",
      'test.js': "const app = require('./app');\napp.ping({ query: { host: 'hello' } }, (e, out) => { if (e || !/hello/.test(out)) { console.error('ping broke'); process.exit(1); } });\n",
    },
    reproducer: { schema: 'agentic-security/reproducer', version: 1, findingId: 'cmdi', lang: 'javascript', files: { 'driver.cjs': "const app = require('./app.js'); app.ping({ query: { host: 'x; touch {{CANARY:command}}' } }, () => {});" }, sources: { 'app.js': 'app.js' }, run: ['{{NODE}}', 'driver.cjs'], oracle: { type: 'command_execution', params: { canary: 'command' } } },
    patches: [
      { id: 'execFile', safe: true, files: { 'app.js': "const { execFile } = require('child_process');\nexports.ping = (req, cb) => execFile('echo', [String(req.query.host)], (e, out) => cb(e, out));\n" } },
      { id: 'deny', safe: false, kind: 'feature-removed', files: { 'app.js': "exports.ping = (req, cb) => cb(new Error('forbidden'));\n" } },
      { id: 'dodge-rule-by-indirection', safe: false, kind: 'scanner-dodge', files: { 'app.js': "const cp = require('child_process');\nconst run = cp['ex' + 'ec'];\nexports.ping = (req, cb) => run('echo ' + req.query.host, (e, out) => cb(e, out));\n" } },
    ],
  },
  {
    id: 'idor-get', cls: 'idor', cwe: 'CWE-639',
    files: {
      'app.js': "const express = require('express');\nconst app = express();\napp.get('/doc/:id', (req, res) => {\n  const doc = db.docs.findOne({ id: req.params.id });\n  res.json(doc);\n});\nmodule.exports = app;\n",
      'test.js': "const src = require('fs').readFileSync('./app.js', 'utf8');\nif (!/findOne/.test(src) || !/res\\.json/.test(src)) { console.error('document lookup is gone'); process.exit(1); }\n",
    },
    patches: [
      { id: 'owner-check', safe: true, files: { 'app.js': "const express = require('express');\nconst app = express();\napp.get('/doc/:id', (req, res) => {\n  const doc = db.docs.findOne({ id: req.params.id, owner: req.user.id });\n  if (!doc) return res.status(404).json({ error: 'not found' });\n  res.json(doc);\n});\nmodule.exports = app;\n" } },
      { id: 'blanket-deny', safe: false, kind: 'feature-removed', files: { 'app.js': "const express = require('express');\nconst app = express();\napp.get('/doc/:id', (req, res) => {\n  res.status(403).json({ error: 'forbidden' });\n});\nmodule.exports = app;\n" } },
      { id: 'ineffective-check', safe: false, kind: 'cosmetic-check', files: { 'app.js': "const express = require('express');\nconst app = express();\napp.get('/doc/:id', (req, res) => {\n  const doc = db.docs.findOne({ id: req.params.id });\n  if (req.user && doc) { /* owner: req.user.id */ }\n  res.json(doc);\n});\nmodule.exports = app;\n" } },
    ],
  },
  {
    id: 'authz-delete', cls: 'authorization', cwe: 'CWE-639',
    files: {
      'app.js': "const express = require('express');\nconst app = express();\napp.delete('/user/:id', (req, res) => {\n  db.users.remove({ id: req.params.id });\n  res.sendStatus(204);\n});\nmodule.exports = app;\n",
      'test.js': "const src = require('fs').readFileSync('./app.js', 'utf8');\nif (!/users\\.remove/.test(src)) { console.error('delete is gone'); process.exit(1); }\n",
    },
    patches: [
      { id: 'owner-scoped', safe: true, files: { 'app.js': "const express = require('express');\nconst app = express();\napp.delete('/user/:id', (req, res) => {\n  if (req.user.id !== req.params.id && req.user.role !== 'admin') return res.sendStatus(403);\n  db.users.remove({ id: req.params.id, owner: req.user.id });\n  res.sendStatus(204);\n});\nmodule.exports = app;\n" } },
      { id: 'blanket-deny', safe: false, kind: 'feature-removed', files: { 'app.js': "const express = require('express');\nconst app = express();\napp.delete('/user/:id', (req, res) => {\n  res.sendStatus(403);\n});\nmodule.exports = app;\n" } },
    ],
  },
  {
    id: 'secret-jwt', cls: 'secret-remediation', cwe: 'CWE-798',
    files: {
      'app.js': "const jwtSecret = 'a-very-long-hardcoded-jwt-signing-secret-value-123456';\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n",
      'test.js': "process.env.JWT_SECRET = 'from-env-for-test';\nconst app = require('./app');\nlet used;\napp.sign({ sign: (c, s) => { used = s; return 'tok'; } }, { a: 1 });\nif (!used) { console.error('sign broke'); process.exit(1); }\n",
    },
    patches: [
      { id: 'from-env', safe: true, files: { 'app.js': "const jwtSecret = process.env.JWT_SECRET;\nif (!jwtSecret) throw new Error('JWT_SECRET is not set');\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n" } },
      { id: 'base64-obfuscation', safe: false, kind: 'cosmetic-check', files: { 'app.js': "const jwtSecret = Buffer.from('YS12ZXJ5LWxvbmctaGFyZGNvZGVkLWp3dC1zaWduaW5nLXNlY3JldC12YWx1ZS0xMjM0NTY=', 'base64').toString();\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n" } },
      { id: 'split-literal', safe: false, kind: 'cosmetic-check', files: { 'app.js': "const jwtSecret = 'a-very-long-hardcoded-' + 'jwt-signing-secret-' + 'value-123456';\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n" } },
      { id: 'reversed', safe: false, kind: 'cosmetic-check', files: { 'app.js': "const jwtSecret = '654321-eulav-terces-gnigns-twj-dedocdrah-gnol-yrev-a'.split('').reverse().join('');\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n" } },
    ],
  },
];

// Classes the corpus names but this pipeline does not judge. They are listed so the denominator is honest, not so they can be scored.
export const NOT_COVERED = [
  { cls: 'dependency-upgrade', reason: 'dependency upgrades are verified by the SCA route (package-manager dry run and the project tests), not by verifyPatch, which verifies source patches' },
];
