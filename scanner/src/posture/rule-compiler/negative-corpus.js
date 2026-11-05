// The shared negative corpus shipped with the scanner (GA-07 §3, 0.195.27): safe, idiomatic code that no promoted rule may fire
// on, the same on every machine and in every repository. `regression.js` puts it in front of the shared false-positive corpus, so
// `rules evaluate`, `rules promote` and `rules regress` all hold a rule to it; a rule that fires on any entry is refused at
// evaluation and reported as regressed later, wherever it runs.
//
// Each entry is the SAFE side of a pattern the compiler is likely to be asked to detect: a parameterised query beside the
// concatenated one, an argument-vector process spawn beside the shell string, a constant-time comparison beside the plain one.
// They are plain strings in a module (not files on disk) so the bundle carries them without a build step and the corpus is
// identical wherever the scanner runs. Keep every entry free of the unsafe form: a vulnerable snippet here would make a correct
// rule fail its gate.
export const SHIPPED_NEGATIVE_CORPUS = Object.freeze([
  { name: 'js-parameterised-query', language: 'javascript', code: 'const rows = await db.query("SELECT * FROM orders WHERE owner = $1", [ownerId]);\n' },
  { name: 'js-placeholder-query', language: 'javascript', code: 'const [row] = await conn.execute("SELECT id FROM users WHERE email = ?", [email]);\n' },
  { name: 'js-orm-where-object', language: 'javascript', code: 'const user = await User.findOne({ where: { id: req.params.id, tenantId: req.user.tenantId } });\n' },
  { name: 'js-execfile-argv', language: 'javascript', code: 'const out = execFileSync("git", ["log", "--format=%H", "-1", ref], { encoding: "utf8" });\n' },
  { name: 'js-spawn-argv', language: 'javascript', code: 'const child = spawn("convert", [inputPath, "-resize", "200x200", outputPath], { stdio: "ignore" });\n' },
  { name: 'js-path-confined', language: 'javascript', code: 'const target = path.resolve(root, name);\nif (!target.startsWith(root + path.sep)) throw new Error("outside root");\nconst text = fs.readFileSync(target, "utf8");\n' },
  { name: 'js-constant-time-compare', language: 'javascript', code: 'const ok = a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));\n' },
  { name: 'js-password-hash', language: 'javascript', code: 'const hash = await bcrypt.hash(password, 12);\nawait store.save({ email, hash });\n' },
  { name: 'js-random-token', language: 'javascript', code: 'const token = crypto.randomBytes(32).toString("hex");\n' },
  { name: 'js-json-parse-validated', language: 'javascript', code: 'const body = schema.parse(JSON.parse(raw));\nres.json({ id: body.id });\n' },
  { name: 'js-template-escaped', language: 'javascript', code: 'res.send(template.render({ name: escapeHtml(req.query.name) }));\n' },
  { name: 'js-fetch-allowlist', language: 'javascript', code: 'if (!ALLOWED_HOSTS.has(new URL(target).host)) return res.status(400).end();\nconst r = await fetch(target, { signal: AbortSignal.timeout(5000) });\n' },
  { name: 'ts-parameterised-query', language: 'typescript', code: 'const rows: Row[] = await db.query("SELECT * FROM t WHERE id = $1", [id]);\n' },
  { name: 'py-parameterised-query', language: 'python', code: 'cur.execute("SELECT * FROM users WHERE email = %s", (email,))\n' },
  { name: 'py-subprocess-argv', language: 'python', code: 'subprocess.run(["ls", "-l", directory], check=True, capture_output=True)\n' },
  { name: 'py-safe-yaml', language: 'python', code: 'config = yaml.safe_load(text)\n' },
  { name: 'py-path-confined', language: 'python', code: 'target = os.path.realpath(os.path.join(root, name))\nif not target.startswith(root + os.sep):\n    raise ValueError("outside root")\n' },
  { name: 'py-password-hash', language: 'python', code: 'digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)\n' },
  { name: 'go-parameterised-query', language: 'go', code: 'row := db.QueryRow("SELECT name FROM users WHERE id = $1", id)\n' },
  { name: 'go-exec-argv', language: 'go', code: 'out, err := exec.Command("git", "rev-parse", ref).Output()\n' },
  { name: 'rb-parameterised-query', language: 'ruby', code: 'User.where("email = ?", params[:email]).first\n' },
  { name: 'rb-system-argv', language: 'ruby', code: 'system("convert", input_path, "-resize", "200x200", output_path)\n' },
  { name: 'java-prepared-statement', language: 'java', code: 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\nps.setInt(1, id);\nResultSet rs = ps.executeQuery();\n' },
  { name: 'java-processbuilder-argv', language: 'java', code: 'Process p = new ProcessBuilder("git", "log", "-1", ref).start();\n' },
  { name: 'php-prepared-statement', language: 'php', code: '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute([":id" => $id]);\n' },
  { name: 'cs-parameterised-query', language: 'csharp', code: 'var cmd = new SqlCommand("SELECT * FROM t WHERE id = @id", conn);\ncmd.Parameters.AddWithValue("@id", id);\n' },
  { name: 'rs-parameterised-query', language: 'rust', code: 'let row = client.query_one("SELECT name FROM users WHERE id = $1", &[&id]).await?;\n' },
]);
