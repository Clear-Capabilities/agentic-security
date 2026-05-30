---
name: agentic-security:security-sql-injection-warn
description: Refuse string-concat SQL. Activate before writing template-literal or +concat queries on user input.
---

# Skill — refuse SQL string-concat

Activates **before** you write SQL that interpolates user input into the
query string. This is CWE-89 — every year, the #1 or #2 OWASP entry. The
correct fix is parameterized queries; the wrong fix is "validate the
input first" (regex bypasses are a defining feature of this bug class).

## When to fire

You're about to call `Edit` / `Write` with a body that contains any of:

- **Template literals as the query**:
  `db.query(\`SELECT * FROM users WHERE id = ${id}\`)`,
  `connection.execute(f"SELECT * FROM x WHERE id = {id}")`,
  `cursor.execute("SELECT * FROM x WHERE id = '" + id + "'")`.
- **String concat into ORMs that allow raw SQL**:
  `prisma.$queryRaw\`…${user}…\`` (NOT `Prisma.sql\`…\``, which is safe),
  `User.objects.raw("SELECT … WHERE " + col + " = …")`,
  `sequelize.query(\`…${user}…\`)`.
- **NoSQL injection shape**:
  `db.users.find({ name: req.body.name })` where `req.body.name` is an
  object — `$where`, `$ne`, `$gt` operators leak through. Mongoose's
  `.find(req.body)` is the canonical version.
- **LDAP filter concat**: `ldap.search('(uid=' + user + ')')`.
- **XPath concat**: `xpath.evaluate("//user[@name='" + name + "']", …)`.
- **Order-by / column-name concat**:
  `SELECT * FROM x ORDER BY ${userColumn}` — even allow-listed columns
  need to be hard-coded, not string-built.

## What to do

**Stop. Refuse the edit. Propose the parameterized form.**

1. **Name the vuln class.** "CWE-89 / SQL Injection. The query string
   cannot contain user input. Even one `${x}` interpolation breaks it."

2. **Show the literal replacement** for the user's exact database
   driver. Three flavors:
   - **Node `pg`**: `db.query('SELECT … WHERE id = $1', [id])`
   - **Node `mysql2`**: `db.execute('SELECT … WHERE id = ?', [id])`
   - **Python `psycopg`**: `cur.execute("SELECT … WHERE id = %s", (id,))`
   - **Python SQLAlchemy**: `session.execute(text("SELECT … WHERE id = :id"), {"id": id})`
   - **Prisma**: `prisma.user.findUnique({ where: { id } })` — or use
     `Prisma.sql\`…\`` if you must use raw, NEVER `$queryRaw\`…\``.

3. **For ORDER BY / column-name parameters** (the one shape parameterized
   queries DON'T solve): show the allow-list pattern:
   ```js
   const ALLOWED = new Set(['id', 'name', 'created_at']);
   if (!ALLOWED.has(col)) throw new Error('invalid sort column');
   const sql = `SELECT * FROM x ORDER BY ${col}`;
   ```
   Hard-code the allow-list. Never derive it from user input.

4. **For NoSQL**: refuse object-shaped query inputs. Always cast
   `req.body.x` to a string with `String(req.body.x).slice(0, MAX)`
   before passing to the query.

## Don't

- Don't suggest "escape the input first." Escaping is the wrong defense;
  parameterized queries are the right one.
- Don't accept template literals "because the input is from our own
  authenticated frontend." Authentication doesn't sanitize input.
- Don't write the unsafe version and then recommend the safer pattern
  in a comment. The order matters.

## Canonical commands

- `/setup --bodyguard` — block sqli shapes at Edit time
- `/scan --all` — pick up unprotected concats already in the codebase
- `/triage --explain CWE-89` — full SQLi explanation, attacker scenarios
- `/fix --one <id>` — apply the parameterized-query fix
