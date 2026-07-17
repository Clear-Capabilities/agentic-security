---
name: agentic-security:secure-coding-guard
description: Guard risky writes. Activate before eval/exec, string-concat SQL, md5/sha1/DES/RC4 crypto, or auth/jwt/oauth/cipher.
---

# Skill — secure-coding guard (write-time bodyguard)

Activates **before** you write code that introduces an insecure construct.
This is a "stop before the damage" surface, not a post-hoc review — by the
time the scanner flags it, the code is already on disk. It merges four
write-time guards; fire the section that matches what you're about to
`Edit` / `Write`:

- **## SQL injection** — string-concat / template-literal queries.
- **## Weak crypto** — md5/sha1 for passwords, DES/RC4, static IVs.
- **## Runtime eval** — `eval()` / `Function()` / string→exec on input.
- **## Threat-model-first** — STRIDE before auth / secret / external-API code.

The refusal/warning behavior in each section is mandatory. Don't write the
unsafe version first and comment on it after — the order matters; you're a
bodyguard, not a code reviewer.

---

## SQL injection

Activates **before** you write SQL that interpolates user input into the
query string. This is CWE-89 — every year, the #1 or #2 OWASP entry. The
correct fix is parameterized queries; the wrong fix is "validate the
input first" (regex bypasses are a defining feature of this bug class).

### When to fire

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

### What to do

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

### Don't

- Don't suggest "escape the input first." Escaping is the wrong defense;
  parameterized queries are the right one.
- Don't accept template literals "because the input is from our own
  authenticated frontend." Authentication doesn't sanitize input.
- Don't write the unsafe version and then recommend the safer pattern
  in a comment. The order matters.

### Canonical commands

- `/setup --bodyguard` — block sqli shapes at Edit time
- `/scan --all` — pick up unprotected concats already in the codebase
- `/triage --explain CWE-89` — full SQLi explanation, attacker scenarios
- `/fix --one <id>` — apply the parameterized-query fix

---

## Weak crypto

Activates **before** you write code that uses a cryptographically broken
primitive. This is a "stop before the damage" section — not a post-hoc
warning. By the time the scanner flags it, the code is already on disk.

### When to fire

You're about to call `Edit` / `Write` with a body that contains any of:

- **Hashing passwords with MD5 / SHA-1 / SHA-256**:
  `crypto.createHash('md5'|'sha1'|'sha256')` followed by `update(password)`,
  `hashlib.md5(password)`, `MessageDigest.getInstance("MD5")`, etc.
- **DES / 3DES / RC4** as the cipher:
  `crypto.createCipheriv('des'|'des-ede3'|'rc4', …)`, `Cipher.getInstance("DES")`,
  `from Crypto.Cipher import DES`.
- **Static IV** in any AES mode: `Buffer.alloc(16)`, hardcoded `Buffer.from('00000…')`,
  `bytes(16)` in Python, etc.
- **Math.random / random.random()** for security-sensitive randomness
  (tokens, session ids, password reset links).
- **JWT with `none` algorithm** or no signature verification.

### What to do

**Stop. Refuse the edit. Propose the right primitive.**

1. **Name the bug class** in plain English. "MD5 is unsuitable for
   password hashing — it's GPU-brute-forceable at ~100 GH/s."
2. **Cite the right primitive** for what they're trying to do:
   - Passwords → `bcrypt`, `scrypt`, `argon2`. Show the import.
   - Symmetric encryption → AES-GCM with a per-message random IV.
   - Tokens → `crypto.randomBytes(32).toString('hex')` (Node),
     `secrets.token_urlsafe(32)` (Python).
   - JWT → explicit `algorithms: ['RS256']` (or `HS256` with a
     long secret), `jwt.verify(...)` not `jwt.decode(...)`.
3. **Show the literal replacement** as a 3-line code block. Not a
   description — the actual code.
4. **Offer `/fix` if the file is already saved.** If the user already
   pushed it, route to `/fix --one <id>` after a scan picks it up.
5. **Don't proceed with the original Edit.** Force the user (or the
   parent agent) to confirm before writing the weak version.

### Don't

- Don't write the weak version and *then* warn. The order matters —
  you're a bodyguard, not a code reviewer.
- Don't accept "it's just for X" / "the user said so" justifications.
  If MD5 is fine here (e.g., file-hash deduplication, not password
  storage), confirm the use case BEFORE writing.

### Canonical commands

- `/setup --bodyguard` — make this section mandatory on every Edit/Write
- `/scan --secrets` — pick up weak-crypto findings the bodyguard missed
- `/fix --one <id>` — close any md5/sha1-password finding already flagged

---

## Runtime eval

Activates **before** you write code that converts a string to executable
code at runtime, when that string can come from any input source (HTTP
body, query, header, file, third-party API, message queue).

### When to fire

You're about to call `Edit` / `Write` with a body that contains any of:

- **JS/TS**: `eval(x)`, `new Function(x)`, `setTimeout(stringArg, …)`,
  `setInterval(stringArg, …)`, `vm.runInNewContext(x)`, `vm.compileFunction(x)`,
  `vm.Script(x).runInThisContext()`.
- **Python**: `eval(x)`, `exec(x)`, `compile(x, …)`, `__import__(x)`,
  `getattr(obj, user_string)`, `globals()[user_string]`.
- **Ruby**: `eval(x)`, `class_eval(x)`, `instance_eval(x)`, `send(x, …)`,
  `public_send(x, …)`.
- **PHP**: `eval($x)`, `assert($x)`, `create_function($x, $y)`,
  `call_user_func($x, …)`.
- **Shell-from-JS**: `exec(userString)`, `execSync(userString)`,
  `child_process.exec(userString)` — the user-controlled-shell exec
  variant is also covered under **Threat-model-first** below (code-exec
  primitives); this section covers the literal code-eval families.
- **Templating-engine eval**: `Mustache.render(x, { __proto__: … })`,
  `Handlebars.compile(userInput)` (template injection).

### What to do

**Stop. Refuse the edit. Propose the structured alternative.**

1. **Name the vuln class.** "CWE-94 / Code Injection. Anything that
   reaches `eval()` at runtime is the same as letting the input source
   write your code directly."

2. **Diagnose what the user actually wants**:
   - Parse JSON? → `JSON.parse(x)` / `json.loads(x)`.
   - Dispatch on a string key? → a `dict`/`object` lookup table with
     an explicit allow-list of keys; throw on unknown.
   - Run user-supplied formulae? → A real expression language with a
     sandboxed evaluator (`mathjs.evaluate` in a worker, `simpleeval`
     in Python, `jsep` for AST-only). Or refuse — formulae from
     untrusted users is the same shape as eval.
   - Lazy-load a module? → Static `import` + a switch statement.
     Never `import(userString)`.
   - Run a deserialization? → A safe deserializer (`json`, not `pickle`).

3. **Show the literal replacement** as a 3-line code block.

4. **If the user insists eval is necessary** (a documented LISP/Lua-style
   feature, a build-time scripting hook), confirm the input source is
   trusted (developer-only file in the repo) AND the input goes through
   a separate validator BEFORE `eval`. Document the assumption in a
   `// agentic-security-ignore: code-injection` pragma with a one-line
   reason.

### Don't

- Don't write the eval call and *then* recommend the safer pattern.
  This section exists to prevent the write, not to comment on it after.
- Don't accept "the input is from MY frontend, so it's trusted." User-
  controlled clients are NEVER trusted.
- Don't suggest "validate the string first" as the only defense.
  Validation regexes for "is this valid JS" are themselves the bug
  class. Use the structured alternative.

### Canonical commands

- `/setup --bodyguard` — make this section mandatory on every Edit
- `/scan --uncommitted` — scan just-edited files for code-eval shapes
- `/triage --explain CWE-94` — full explanation of code-injection family

---

## Threat-model-first

Activates **before** you add or edit code that crosses a security
trust boundary. The cheapest place to fix a security bug is the moment
before you write it. This section front-loads the threat modeling so the
implementation that follows is informed.

### When to fire

You're about to call `Edit` / `Write` with a body that introduces or
modifies one of these touch-points:

- **Authentication / session**: `jwt.sign`, `jwt.verify`, `bcrypt.hash`,
  `bcrypt.compare`, `passport.use`, `next-auth`, `Clerk`, `Auth0`,
  any code that reads/writes a session cookie.
- **Authorization / RBAC**: any `if (user.role === …)`, `requireRole`,
  `@PreAuthorize`, `before_action :authorize`, middleware that
  decides who can see what.
- **Secret handling**: `process.env.X` reading something that looks
  like a key, any `crypto.createCipheriv`, key generation, KMS calls.
- **External API**: `fetch(<url-from-input>)`, `axios.get(<url>)`,
  `requests.get(<url>)`, any HTTP call where the URL is user-derived.
- **OAuth flows**: `redirect_uri`, `state` parameter, PKCE setup,
  token exchange handlers.
- **File upload**: `multer`, `busboy`, `req.files`, `flask.request.files`,
  anything that touches user-supplied files.
- **Code-exec primitives**: `exec`, `spawn`, `subprocess`, `os.system`,
  `Runtime.exec` — the user-input cases are covered under **Runtime eval**
  above; this section covers the threat-model angle.
- **Deserialization**: `pickle.loads`, `yaml.load`, `JSON.parse` of
  untrusted input, `xml.etree`.

### What to do

1. **Pause before the Edit.** Don't write the code yet. Tell the user
   you're going to threat-model first.

2. **Generate a session id** if one doesn't exist for this conversation.
   `tm-<YYYY-MM-DD>-<short hash of file path>` is fine.

3. **Walk STRIDE per touch-point.** For the specific construct the
   user is about to introduce, work through:

   | Letter | Category | Question to answer |
   |--------|----------|--------------------|
   | **S** | Spoofing | Who can claim to be a legitimate caller? What proves they are? Is the auth check before OR after the action? |
   | **T** | Tampering | Can the input be modified in transit? Is it signed / HMAC'd? Are the right fields integrity-protected? |
   | **R** | Repudiation | Is there an audit log? Does it survive deletion? Can the actor deny doing X? |
   | **I** | Information disclosure | What data does this code see / return / log? Is it the minimum? Are errors leaking schema / paths / secrets? |
   | **D** | Denial of service | What's the cost per request? Is there a rate limit? Can the input cause unbounded resource use (regex, JSON depth, image dimensions)? |
   | **E** | Elevation of privilege | Does the code path let a lower-privilege actor reach higher-privilege state? Is there a TOCTOU window? |

   For each letter, write ONE sentence. If a category doesn't apply
   for this specific touch-point, write "n/a — <one-line reason>".
   Don't skip categories; the skip itself is a decision worth recording.

4. **Write the result to the scratchpad via MCP**:

   ```
   append_scratchpad({
     path: ".agentic-security/agent-scratchpad/threat-model/<session>/TM.md",
     content: "<the STRIDE block + the construct + the file:line>"
   })
   ```

   Future turns in this session (and future agents) read this file
   to know what was already considered. Don't re-do the analysis.

5. **Propose the literal implementation** that satisfies every STRIDE
   row. Show the code. Highlight which row each defensive measure
   addresses (e.g. `// addresses S: signature verified before use`).

6. **Commit-as-you-go**: every time you add a defensive measure, cite
   the STRIDE row it addresses in a code comment. This is the
   compliance-cite-as-you-go pattern — auditors read your code as
   the threat-model artifact.

### What to write in TM.md

Structured. The file is meant to be greppable later:

```markdown
# TM.md — threat model for <feature/file>

## Touch-point: <jwt.verify in src/auth/middleware.ts>
Date:      2026-05-20T14:32:00Z
Agent:     <name of the agent that wrote this>
Construct: `jwt.verify(token, secret, { algorithms: ['RS256'] })`

### STRIDE
S: Token signature verifies via the project's public key. Caller's
   identity is established at this point; no other check trusts the
   `Authorization` header before this runs.
T: HMAC inside JWT signature covers the full payload. Custom claims
   ARE inside the signed envelope.
R: Audit log on auth events written to .audit_log (table); deletions
   require service-role; rotation in pg_audit weekly.
I: On verify failure, return 401 with NO detail string (don't leak
   "expired" vs "invalid signature"); both 401.
D: Rate-limit /auth/* to 10/sec/IP via Cloudflare; jwt verify itself
   is O(1) and bounded by signature math.
E: n/a — token only encodes user_id + role; role transitions go
   through a separate `POST /admin/promote` endpoint that requires admin.

### Decisions
- algorithms: ['RS256'] explicit (NOT 'none'; NOT the unverified
  jwt.decode())
- Cookie: httpOnly + Secure + SameSite=Lax
- TTL: 15 min access + 30 day refresh in separate http-only cookie

### Open questions
- Refresh-token rotation: still using sliding window; should switch
  to rotation-on-use before public launch.
```

### Don't

- Don't skip STRIDE rows. The skip is itself a decision; record it.
- Don't write the implementation without the TM.md first.
- Don't reuse a TM.md from a different touch-point. Each construct
  needs its own. The S row for `jwt.verify` is different from the
  S row for `bcrypt.compare`.
- Don't make the TM.md a wall of text. One sentence per row, max.
  If you can't say it in a sentence, you don't understand it yet.
- Don't bless the implementation if any STRIDE row is "I don't know."
  Stop and ask the user.

### Canonical commands

- `/posture --threat --view model` — auto-derived STRIDE from the last scan
- `/posture --threat --view personas` — per-attacker-persona prioritization
- `/posture --threat --view spof` — counterfactual: which control, if removed, exposes the most

### Why this is here

The `/posture --threat --view model` slash produces a STRIDE table from a completed scan.
This section produces one **before** the code is written. The two are
complementary — pre-write TM.md catches design flaws; post-scan STRIDE
catches what made it through.
