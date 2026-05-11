// Rule-library shape: this file should produce ZERO findings. Every "danger"
// pattern below is a string literal — describing a vulnerability rule, not
// invoking one. Without string-literal awareness, dozens of self-detections fire.
'use strict';

const PATTERNS = [
  {
    name: 'command-injection',
    regex: /(?:exec|spawn)\s*\(/g,
    vuln: 'Command Injection',
    fix: "Replace exec(userInput) with execFile and an arg array. Never use child_process.exec(req.body.cmd).",
    example: "exec('rm -rf ' + req.body.path)  // BAD",
  },
  {
    name: 'sql-injection',
    regex: /(?:db|knex)\.query\(/g,
    vuln: 'SQL Injection',
    fix: "Use parameterized queries. db.query('SELECT * FROM users WHERE id = $1', [id]) instead of `SELECT * WHERE id=${id}`.",
    example: "db.query(`SELECT * FROM users WHERE id=${req.body.id}`)  // BAD",
  },
  {
    name: 'xss-domwrite',
    regex: /document\.write\s*\(/g,
    vuln: 'XSS via document.write',
    fix: "Never use document.write(); use safe DOM APIs (textContent, createElement).",
    example: "document.write(req.query.x)  // BAD",
  },
  {
    name: 'eval-rce',
    regex: /\beval\s*\(/g,
    vuln: 'Code Injection (eval)',
    fix: "Don't eval(req.body.expr). Use a safe expression parser.",
    example: "eval(req.body.calc)  // BAD",
  },
];

module.exports = { PATTERNS };
