// Seeded sibling sets for the root-cause sweep. Each case is one confirmed finding plus a small corpus in which every line is tagged by
// what a reader would say it is, written BEFORE looking at what the sweep does with it:
//
//   origin  the finding's own site (the sweep must never report it)
//   sib     the same call to the same callee, with the argument built the same way and different names and literals: a real sibling
//   form    the same call to the same callee that a reader would still call a sibling, but with the argument built another way (a
//           template where the origin concatenates, a bare variable where it builds a string). The matcher confirms argument
//           structure, so whether it reaches these is a measured design limit, reported as its own recall and never mixed into the
//           same-shape recall.
//   known   a same-shape sibling that already carries a finding of its own: the sweep must call it mitigated-or-known, not a new candidate
//   near    a different callee, or a different receiver, that merely looks alike: the sweep must not report it
//   lim     a case the matcher is documented not to separate (a mention inside a comment or a string). Its observed behavior is recorded and
//           gated for change, but it is not counted toward precision or recall.
//   plain   filler
//
// Lines are fixed text, so the bench is deterministic. The sink kinds are classes the scanner reports often. The corpus is small and written
// by the people who wrote the matcher: a result here is robustness over these shapes, not field recall.

const L = (t, s) => ({ t, s });

const CASES = [
  {
    id: 'js-sql-db-query', lang: 'js', vuln: 'SQL Injection', cwe: 'CWE-89', snippet: 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
    files: {
      'src/users.js': [L('plain', "const db = require('./db');"), L('origin', 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);'), L('plain', 'module.exports = {};')],
      'src/orders.js': [L('sib', 'const rows = await db.query(`SELECT * FROM orders WHERE user = ${userId}`);'), L('near', 'logger.query(`SELECT * FROM orders WHERE user = ${userId}`);'), L('form', "db.query('DELETE FROM carts WHERE id = ' + cartId);")],
      'src/admin.js': [L('known', 'db.query(`UPDATE users SET role = ${role} WHERE id = ${id}`);'), L('near', 'mydb.queryAll(`SELECT 1`);'), L('lim', '// previously: db.query(`SELECT * FROM users WHERE id = ${id}`)')],
    },
  },
  {
    id: 'js-command-exec', lang: 'js', vuln: 'Command Injection', cwe: 'CWE-78', snippet: 'exec(`convert ${req.query.file} out.png`)',
    files: {
      'lib/img.js': [L('origin', 'exec(`convert ${req.query.file} out.png`);'), L('form', "exec('ls ' + dir);"), L('near', 'regex.exec(input);')],
      'lib/zip.js': [L('sib', 'exec(`tar -xf ${archive}`);'), L('near', 'execFile(bin, args);'), L('plain', 'const x = 1;')],
      'lib/ops.js': [L('known', 'exec(`remove ${target}`);'), L('lim', 'const label = "call exec(x) carefully";')],
    },
  },
  {
    id: 'js-fs-read', lang: 'js', vuln: 'Path Traversal', cwe: 'CWE-22', snippet: 'fs.readFile(path.join(base, req.params.name), cb)',
    files: {
      'src/files.js': [L('origin', 'fs.readFile(path.join(base, req.params.name), cb);'), L('sib', 'fs.readFile(path.join(root, ctx.query.file), done);'), L('form', 'fs.readFile(userPath, cb);'), L('form', 'fs.readFile(path.join(root, name), done);'), L('near', 'fs.readFileSync(userPath);')],
      'src/docs.js': [L('sib', 'fs.readFile(path.join(dir, req.body.name), handler);'), L('near', 'cache.readFile(key, cb);'), L('known', 'fs.readFile(path.join(a, b.c.d), cb);')],
    },
  },
  {
    id: 'py-sql-execute', lang: 'py', vuln: 'SQL Injection', cwe: 'CWE-89', snippet: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    files: {
      'app/users.py': [L('origin', 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'), L('form', 'cursor.execute(f"DELETE FROM carts WHERE id = {cart_id}")'), L('near', 'cursor.executemany(sql, rows)')],
      'app/orders.py': [L('sib', 'cursor.execute("SELECT * FROM orders WHERE u = " + uid)'), L('near', 'session.execute(stmt)'), L('known', 'cursor.execute("SELECT 1 FROM " + name)'), L('lim', '# cursor.execute("SELECT 1 " + old_query)')],
    },
  },
  {
    id: 'py-os-system', lang: 'py', vuln: 'Command Injection', cwe: 'CWE-78', snippet: 'os.system("ping " + host)',
    files: {
      'tools/net.py': [L('origin', 'os.system("ping " + host)'), L('sib', 'os.system("traceroute " + target)'), L('near', 'os.getenv("HOME")'), L('near', 'subprocess.run(["ping", host])')],
      'tools/disk.py': [L('form', 'os.system(cmd)'), L('known', 'os.system("cleanup " + path)'), L('near', 'system.os(cmd)')],
    },
  },
  {
    id: 'py-pickle-loads', lang: 'py', vuln: 'Insecure Deserialization', cwe: 'CWE-502', snippet: 'pickle.loads(request.data)',
    files: {
      'srv/api.py': [L('origin', 'pickle.loads(request.data)'), L('sib', 'pickle.loads(blob.data)'), L('near', 'pickle.dumps(obj)'), L('near', 'json.loads(request.data)')],
      'srv/cache.py': [L('form', 'pickle.loads(redis.get(key))'), L('known', 'pickle.loads(payload.data)')],
    },
  },
  {
    id: 'java-statement-query', lang: 'java', vuln: 'SQL Injection', cwe: 'CWE-89', snippet: 'stmt.executeQuery("SELECT * FROM users WHERE id = " + id)',
    files: {
      'src/UserDao.java': [L('origin', '    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);'), L('sib', '    ResultSet r2 = stmt.executeQuery("SELECT * FROM orders WHERE u = " + uid);'), L('near', '    stmt.executeUpdate("DELETE FROM carts");')],
      'src/OrderDao.java': [L('form', '    return stmt.executeQuery(sql + filter + tail);'), L('known', '    stmt.executeQuery("SELECT 1 FROM t WHERE k = " + key);'), L('near', '    prepared.executeQuery();')],
    },
  },
  {
    id: 'java-runtime-exec', lang: 'java', vuln: 'Command Injection', cwe: 'CWE-78', snippet: 'Runtime.getRuntime().exec("ping " + host)',
    files: {
      'src/Net.java': [L('origin', '    Runtime.getRuntime().exec("ping " + host);'), L('sib', '    Runtime.getRuntime().exec("df " + mount);'), L('near', '    Runtime.getRuntime().availableProcessors();')],
      'src/Disk.java': [L('form', '    Runtime.getRuntime().exec(cmd);'), L('known', '    Runtime.getRuntime().exec("cleanup " + file);'), L('near', '    executor.submit(task);')],
    },
  },
];

// A large case: more siblings than the sweep will materialise, so the exact counts must survive the bound on the sample.
const BIG = { id: 'js-many-siblings', lang: 'js', vuln: 'SQL Injection', cwe: 'CWE-89', snippet: 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)', files: {} };
BIG.files['src/origin.js'] = [L('origin', 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);')];
for (let f = 0; f < 15; f++) {
  BIG.files[`src/gen${f}.js`] = Array.from({ length: 10 }, (_, i) => L('sib', `db.query(\`SELECT * FROM t${f} WHERE c = \${v${i}}\`);`));
}
CASES.push(BIG);

export { CASES };

/** Materialise a case: the finding, the file map, and the labelled line sets. */
export function build(c) {
  const files = new Map();
  const labels = { origin: null, sib: [], form: [], known: [], near: [], lim: [] };
  for (const [file, lines] of Object.entries(c.files)) {
    files.set(file, lines.map(l => l.s).join('\n'));
    lines.forEach((l, i) => {
      const loc = `${file}:${i + 1}`;
      if (l.t === 'origin') labels.origin = { file, line: i + 1, loc };
      else if (labels[l.t]) labels[l.t].push(loc);
    });
  }
  const o = labels.origin;
  const finding = {
    id: `${c.id}-origin`, confirmed: true, file: o.file, line: o.line, vuln: c.vuln, cwe: c.cwe,
    sink: { file: o.file, line: o.line, snippet: c.snippet },
  };
  // A line that already carries a finding of its own. The sweep must not call it a new candidate.
  const others = labels.known.map((loc, i) => {
    const cut = loc.lastIndexOf(':');
    return { id: `${c.id}-known-${i}`, confirmed: false, file: loc.slice(0, cut), line: Number(loc.slice(cut + 1)), vuln: c.vuln, cwe: c.cwe };
  });
  return { finding, findings: [finding, ...others], files, labels };
}
