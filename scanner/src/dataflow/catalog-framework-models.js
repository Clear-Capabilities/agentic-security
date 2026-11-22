// Framework request sources and dangerous sinks, round five (API-semantic models).
//
// Every entry here models a documented, widely used framework or standard
// library API: where a web framework hands request data to application code,
// and the standard library or common client calls that are dangerous when
// that data reaches them. Nothing here is keyed on a project, a path, a file
// name or a published advisory; each entry is named after the API it models.
//
// The entries use the base catalog's shape (see catalog.js) and are merged
// into CATALOG there, after the base entries, so a base entry with the same
// id always wins. Precision rules followed throughout:
//   - A generic method name (`get`, `request`, `execute`, `open`) is always
//     scoped by `match.receiver`, so only the documented receiver matches.
//   - A sink whose danger depends on the invocation form (shell interpreter
//     versus argv, a template name versus template source) carries the same
//     gates the base catalog uses (`requireLiteralArg`, `requireKeyword`,
//     `requireStaticPrefix`) or the two gates added with this file
//     (`rejectKeyword`, `rejectOptionKey`, both in engine.js).
//   - `argIndex` names the argument that carries the dangerous value, so a
//     parameterized call (SQL text literal, value in a later argument) stays
//     silent.
//   - A parameter of an exported library function is caller input, not
//     request input; nothing here turns one into a source.

const SQL_REMEDIATION = 'Use the API\'s parameter binding (placeholders plus a separate values argument); never concatenate or interpolate request data into the SQL text.';
const PATH_REMEDIATION = 'Resolve the path against a fixed base directory and reject it unless the canonical result stays inside that base (or reduce the input to a bare file name).';
const SSRF_REMEDIATION = 'Do not let request data choose the destination. Map the input to an allow-listed host, or parse the URL and reject private, loopback and link-local addresses before the request.';
const REDIRECT_REMEDIATION = 'Redirect only to a relative path you validated (starts with "/" and not "//") or to a host on an allow-list.';
const CMD_REMEDIATION = 'Run a fixed program with an argument array and no shell; validate the arguments against an allow-list.';
const CODE_REMEDIATION = 'Never evaluate request data as code or as a template source; use a fixed template with the data passed as variables.';
const DESER_REMEDIATION = 'Do not deserialize request data with a format that can construct arbitrary objects; parse a data-only format (JSON) into a concrete type.';
const XSS_REMEDIATION = 'Escape the value for its HTML context, or return it through the framework\'s auto-escaping templates or a JSON response.';
const REDOS_REMEDIATION = 'Do not compile a regular expression from request data; escape it (re.escape, Pattern.quote, Regex.Escape, preg_quote, Regexp.escape) or match it as a literal string.';
const XXE_REMEDIATION = 'Disable DTDs and external entity resolution on the parser before parsing request data.';

function v(name, cwe, severity, remediation) {
  return { name, severity, cwe, remediation };
}

// Build one sink entry per method name.
function sinks(prefix, language, framework, methods, match, argIndex, vuln) {
  return methods.map((m) => ({
    kind: 'sink', id: `${prefix}-${m}`.replace(/[^A-Za-z0-9-]/g, '-').toLowerCase(), language, framework,
    match: { type: 'call', callee: m, ...match }, argIndex, vuln: { ...vuln, name: vuln.name.replace('%m', m) },
  }));
}
// Build one call-source entry per method name.
function callSources(prefix, language, framework, methods, match, provenance, label) {
  return methods.map((m) => ({
    kind: 'source', id: `${prefix}-${m}`.replace(/[^A-Za-z0-9-]/g, '-').toLowerCase(), language, framework,
    match: { type: 'call', callee: m, ...match }, label: label.replace('%m', m), provenance,
  }));
}
function memberSources(prefix, language, framework, objects, props, provenance) {
  const out = [];
  for (const o of objects) {
    for (const [p, prov] of Object.entries(props)) {
      out.push({ kind: 'source', id: `${prefix}-${o}-${p}`.replace(/[^A-Za-z0-9-]/g, '-').toLowerCase(), language, framework,
        match: { type: 'member', object: o, prop: p }, label: `${o}.${p}`, provenance: prov || provenance });
    }
  }
  return out;
}
function annotationSources(prefix, language, framework, names) {
  return Object.entries(names).map(([n, prov]) => ({
    kind: 'source', id: `${prefix}-${n}`.toLowerCase(), language, framework,
    match: { type: 'annotation', name: n }, label: `@${n} parameter (${framework})`, provenance: prov,
  }));
}

// A shell interpreter as a LITERAL first argument (quotes optional, since the
// frontends differ on whether a literal keeps them).
const SHELL_LITERAL = '^["\']?(?:/usr)?(?:/bin/)?(?:sh|bash|zsh|dash|ksh|cmd|cmd\\.exe|powershell|powershell\\.exe|pwsh)["\']?$';

// ─── JavaScript / TypeScript ─────────────────────────────────────────────
const JS = [
  // Fastify, Hapi, Next.js route handlers and any other framework that names
  // the request `request` (Express-style `req.*` and `request.body` are in the
  // base catalog; `request.params` is already a source there).
  ...memberSources('js-src', 'js', 'fastify/hapi/next', ['request'], {
    query: 'url-param', headers: 'header', cookies: 'cookie', payload: 'http-body', url: 'url-param', nextUrl: 'url-param',
  }),
  // Express request line. `req.url` is deliberately absent: outbound request
  // objects are named `req` too (`const req = buildRequest(); fetch(req.url)`).
  // (Multer's req.file/req.files are modelled by the lineage catalog only, by
  // design; see seeding-across-calls.test.js.)
  ...memberSources('js-src', 'js', 'express', ['req'], {
    originalUrl: 'url-param', path: 'path-param', payload: 'http-body',
  }),
  // Fetch-API Request bodies (Next.js route handlers, Remix, Hono's c.req).
  ...callSources('js-src-request-body', 'js', 'fetch-request', ['json', 'formData', 'text', 'arrayBuffer', 'blob'],
    { receiver: '^(?:req|request)$' }, 'http-body', 'request.%m() (Fetch API request body)'),
  // Express `req.get(name)` / `req.header(name)` / `req.param(name)`, Hono `c.req.query()/param()/header()/valid()/parseBody()`.
  ...callSources('js-src-req-accessor', 'js', 'express/hono', ['get', 'param', 'query', 'queries', 'valid', 'parseBody'],
    { receiver: '^req$' }, 'url-param', 'req.%m() (request accessor)'),
  ...callSources('js-src-req-header', 'js', 'express/hono', ['header', 'cookie'],
    { receiver: '^(?:req|request)$' }, 'header', 'req.%m() (request header)'),
  // Next.js `headers()` / `cookies()` from next/headers: a bare call (no receiver).
  ...callSources('js-src-next', 'js', 'next', ['headers', 'cookies'],
    { receiverExclude: '.' }, 'header', 'next/headers %m()'),
  // Next.js server actions: every parameter of a function exported from a
  // 'use server' module (or carrying the directive) is posted by the client.
  // parser-js.js emits the `js:server-action` parameter annotation.
  { kind: 'source', id: 'js-src-server-action-param', language: 'js', framework: 'next', match: { type: 'annotation', name: 'js:server-action' },
    label: 'server action parameter (Next.js "use server")', provenance: 'http-body' },

  // Path traversal / file write.
  // `operatorOriginNotReported`: a script reading or writing the file named on its own command line, or under a directory from the
  // environment, is the operator's own input (the rule `py-open` and `js-fs-readFile` follow).
  ...sinks('js-fs', 'js', 'node', ['readFileSync', 'createReadStream', 'readdirSync', 'unlinkSync', 'rmSync', 'rmdirSync', 'opendirSync'], { operatorOriginNotReported: true }, 0,
    v('Path Traversal (fs.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('js-fs-recv', 'js', 'node', ['readdir', 'unlink', 'rm', 'rmdir', 'opendir'], { receiver: '^(?:fs|fsp|fsPromises|promises|fse)$' }, 0,
    v('Path Traversal (fs.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('js-fs-write', 'js', 'node', ['writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream'], { operatorOriginNotReported: true }, 0,
    v('Arbitrary File Write (fs.%m)', 'CWE-73', 'critical', PATH_REMEDIATION)),
  // Express res.sendFile / res.download. With a `root` option the send module
  // confines the path to that root, so that form is not modelled as a sink.
  ...sinks('js-express-file', 'js', 'express', ['sendFile', 'download'], { receiver: '^(?:res|response)$', rejectOptionKey: 'root' }, 0,
    v('Path Traversal (res.%m)', 'CWE-22', 'high', 'Pass the file name with the `root` option (res.sendFile(name, { root: dir })) or reduce it to path.basename before resolving.')),

  // Command execution without a shell: request data choosing the program.
  ...sinks('js-cp-program', 'js', 'node', ['execFile', 'execFileSync', 'spawn', 'spawnSync', 'execa', 'execaSync', 'execaCommand', 'execaCommandSync'], {}, 0,
    v('Command Injection (%m with a request-chosen program)', 'CWE-78', 'critical', CMD_REMEDIATION)),
  // The same calls with a literal shell as the program: the argument array is a shell script.
  ...sinks('js-cp-shell', 'js', 'node', ['execFile', 'execFileSync', 'spawn', 'spawnSync'], { requireLiteralArg: { index: 0, pattern: SHELL_LITERAL }, shellScriptElement: true }, 1,
    v('Command Injection (%m through a shell interpreter)', 'CWE-78', 'critical', CMD_REMEDIATION)),

  // Code evaluation.
  ...sinks('js-vm', 'js', 'node', ['runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction'], {}, 0,
    v('Code Injection (vm.%m)', 'CWE-94', 'critical', CODE_REMEDIATION)),
  { kind: 'sink', id: 'js-vm-script', language: 'js', framework: 'node', match: { type: 'call', callee: 'Script', receiver: '^vm$' }, argIndex: 0,
    vuln: v('Code Injection (new vm.Script)', 'CWE-94', 'critical', CODE_REMEDIATION) },
  ...sinks('js-timer-string', 'js', 'node', ['setTimeout', 'setInterval'], {}, 0,
    v('Code Injection (%m with a string body)', 'CWE-95', 'critical', 'Pass a function to the timer, never a string built from request data.')),
  // Template source from the request (server-side template injection).
  ...sinks('js-template-source', 'js', 'templates', ['template'], { receiver: '^(?:_|lodash)$' }, 0,
    v('Server-Side Template Injection (_.%m)', 'CWE-1336', 'critical', CODE_REMEDIATION)),
  ...sinks('js-template-engine', 'js', 'templates', ['compile', 'render', 'renderString', 'compileTemplate'], { receiver: '^(?:ejs|pug|jade|nunjucks|Mustache|mustache|doT|dot|Eta|eta|Twig|twig|Liquid|liquid)$' }, 0,
    v('Server-Side Template Injection (%m with a request-built template)', 'CWE-1336', 'critical', CODE_REMEDIATION)),

  // SSRF: common HTTP clients.
  ...sinks('js-axios', 'js', 'axios', ['post', 'put', 'patch', 'delete', 'head', 'options', 'request'], { receiver: '^axios$', operatorOriginNotReported: true }, 0,
    v('SSRF (axios.%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'js-axios-call', language: 'js', framework: 'axios', match: { type: 'call', callee: 'axios', receiverExclude: '.' }, argIndex: 0,
    vuln: v('SSRF (axios(config))', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'js-got-call', language: 'js', framework: 'got', match: { type: 'call', callee: 'got', receiverExclude: '.' }, argIndex: 0,
    vuln: v('SSRF (got)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'js-ky-call', language: 'js', framework: 'ky', match: { type: 'call', callee: 'ky', receiverExclude: '.' }, argIndex: 0,
    vuln: v('SSRF (ky)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  ...sinks('js-http-client', 'js', 'http-clients', ['get', 'post', 'put', 'patch', 'delete', 'del', 'head', 'stream', 'request', 'fetch'],
    { receiver: '^(?:got|ky|undici|superagent|needle|https?)$', operatorOriginNotReported: true }, 0, v('SSRF (%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),

  // SQL: raw-query escape hatches of the common query builders and ORMs.
  ...sinks('js-sql-raw', 'js', 'knex/prisma/sequelize', ['$queryRawUnsafe', '$executeRawUnsafe', 'whereRaw', 'orWhereRaw', 'havingRaw', 'orderByRaw', 'groupByRaw', 'joinRaw', 'fromRaw', 'selectRaw'], {}, 0,
    v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('js-sql-raw-recv', 'js', 'knex/sequelize', ['raw', 'literal'], { receiver: '^(?:knex|db|trx|database|sequelize|Sequelize|connection|conn|pg|client)$' }, 0,
    v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),

  // Reflected XSS through raw response writes (same receiver rule as the base res.send entry).
  ...sinks('js-res-write', 'js', 'node-http/express', ['write', 'end'], { receiver: '^(?:res|response)$' }, 0,
    v('Reflected XSS (res.%m)', 'CWE-79', 'high', XSS_REMEDIATION)),
  // Open redirect through the Location header helper.
  { kind: 'sink', id: 'js-express-location', language: 'js', framework: 'express', match: { type: 'call', callee: 'location', receiver: '^(?:res|response)$' }, argIndex: 0,
    vuln: v('Open Redirect (res.location)', 'CWE-601', 'medium', REDIRECT_REMEDIATION) },
  // Deserialization that executes functions embedded in the payload.
  { kind: 'sink', id: 'js-node-serialize-unserialize', language: 'js', framework: 'node-serialize', match: { type: 'call', callee: 'unserialize' }, argIndex: 0,
    vuln: v('Insecure Deserialization (unserialize)', 'CWE-502', 'critical', DESER_REMEDIATION) },
];

// ─── Python ──────────────────────────────────────────────────────────────
const PY = [
  { kind: 'source', id: 'py-src-flask-get-json', language: 'py', framework: 'flask', match: { type: 'call', callee: 'get_json', receiver: '^request$' }, label: 'request.get_json() (Flask)', provenance: 'http-body' },
  // aiohttp / Starlette request objects.
  ...memberSources('py-src', 'py', 'aiohttp/starlette', ['request'], { match_info: 'path-param', query: 'url-param', rel_url: 'url-param', url: 'url-param', query_string: 'url-param' }),
  ...callSources('py-src-request-body', 'py', 'aiohttp', ['text', 'read', 'post'], { receiver: '^request$' }, 'http-body', 'await request.%m() (aiohttp)'),
  ...callSources('py-src-tornado', 'py', 'tornado', ['get_query_argument', 'get_query_arguments', 'get_body_arguments', 'get_cookie'], { receiver: '^self$' }, 'url-param', 'self.%m() (Tornado)'),
  // Route handler parameters (Flask/Quart/Bottle `@app.route`, FastAPI/Starlette
  // `@app.get(...)`): parser-py.helper.py emits `py:route-param` only for a
  // handler whose decorator carries a literal route path, and only for
  // parameters that are not numeric-typed, not dependency-injected and not
  // bound by a numeric route converter.
  { kind: 'source', id: 'py-src-route-param', language: 'py', framework: 'flask/fastapi', match: { type: 'annotation', name: 'py:route-param' },
    label: 'route handler parameter (path or query)', provenance: 'path-param' },

  // Command execution.
  ...sinks('py-subprocess-shell', 'py', 'subprocess', ['check_output', 'check_call'], { receiver: '^subprocess$', requireKeyword: { name: 'shell', pattern: '^(?:true|True|1)$' } }, 0,
    v('Command Injection (subprocess.%m with shell=True)', 'CWE-78', 'critical', CMD_REMEDIATION)),
  ...sinks('py-shell-always', 'py', 'subprocess/asyncio', ['getstatusoutput', 'create_subprocess_shell'], {}, 0,
    v('Command Injection (%m)', 'CWE-78', 'critical', CMD_REMEDIATION)),

  // SSRF.
  ...sinks('py-http-verb', 'py', 'requests/httpx', ['put', 'patch', 'delete', 'head', 'options'], { receiver: '^(?:requests|httpx|session|Session|client|Client|aiohttp|ClientSession|AsyncClient|PoolManager)$', receiverExclude: '^(?:db|database|orm|repo|repository|models?|objects|queryset|store|storage)$', receiverTypeExclude: ['Session$', 'SessionDep', 'AsyncSession', 'scoped_session', 'SQLAlchemy', 'Repository'] }, 0,
    v('SSRF (%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  ...sinks('py-http-async-client', 'py', 'httpx/aiohttp', ['get', 'post'], { receiver: '^(?:aiohttp|ClientSession|AsyncClient|PoolManager)$' }, 0,
    v('SSRF (%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'py-http-request-method', language: 'py', framework: 'requests/urllib3', match: { type: 'call', callee: 'request', receiver: '^(?:requests|httpx|session|Session|urllib3|PoolManager|AsyncClient|ClientSession|pool)$' }, argIndex: 1,
    vuln: v('SSRF (request(method, url))', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'py-urllib-request-ctor', language: 'py', framework: 'urllib', match: { type: 'call', callee: 'Request', receiver: '^(?:urllib|request)$' }, argIndex: 0,
    vuln: v('SSRF (urllib.request.Request)', 'CWE-918', 'high', SSRF_REMEDIATION) },

  // Open redirect.
  ...sinks('py-redirect-response', 'py', 'django/starlette', ['HttpResponseRedirect', 'HttpResponsePermanentRedirect', 'RedirectResponse'], {}, 0,
    v('Open Redirect (%m)', 'CWE-601', 'medium', REDIRECT_REMEDIATION)),

  // XSS: markup trusted without escaping, and raw HTML responses. Django's
  // HttpResponse defaults to text/html; an explicit non-HTML content type is
  // not a sink.
  ...sinks('py-xss-trust', 'py', 'django/markupsafe', ['mark_safe', 'Markup', 'HTMLResponse', 'SafeString'], {}, 0,
    v('XSS (%m on request data)', 'CWE-79', 'high', XSS_REMEDIATION)),
  { kind: 'sink', id: 'py-django-httpresponse', language: 'py', framework: 'django', match: { type: 'call', callee: 'HttpResponse', rejectKeyword: { name: 'content_type', pattern: 'json|text/plain|csv|xml|octet' } }, argIndex: 0,
    vuln: v('Reflected XSS (HttpResponse)', 'CWE-79', 'high', XSS_REMEDIATION) },

  // Path traversal.
  { kind: 'sink', id: 'py-starlette-fileresponse', language: 'py', framework: 'starlette/fastapi', match: { type: 'call', callee: 'FileResponse' }, argIndex: 0,
    vuln: v('Path Traversal (FileResponse)', 'CWE-22', 'high', PATH_REMEDIATION) },
  ...sinks('py-os-path', 'py', 'os', ['remove', 'unlink', 'rmdir', 'removedirs', 'listdir', 'scandir'], { receiver: '^os$' }, 0,
    v('Path Traversal (os.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('py-shutil', 'py', 'shutil', ['rmtree', 'copy', 'copyfile', 'copy2', 'move'], { receiver: '^shutil$' }, 0,
    v('Path Traversal (shutil.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  // `Path(x).read_text()` lowers to one chained call whose arguments are Path's.
  ...sinks('py-pathlib-read', 'py', 'pathlib', ['read_text', 'read_bytes', 'unlink', 'rmdir', 'iterdir'], { receiver: '^(?:Path|PurePath|PosixPath)$' }, 'all',
    v('Path Traversal (Path(...).%m)', 'CWE-22', 'high', PATH_REMEDIATION)),

  // ReDoS: a pattern compiled from request data. The chained `re.compile(p).match(s)`
  // form is excluded: there the receiver chain names `compile` and the first
  // argument is the subject string.
  ...sinks('py-re-pattern', 'py', 're', ['compile', 'match', 'search', 'fullmatch', 'findall', 'finditer', 'sub', 'subn', 'split'], { receiver: '^(?:re|regex)$', receiverExclude: '^compile$' }, 0,
    v('ReDoS (re.%m with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION)),

  // Deserialization.
  ...sinks('py-yaml-unsafe', 'py', 'pyyaml', ['unsafe_load', 'unsafe_load_all'], { receiver: '^(?:yaml|ruamel)$' }, 0,
    v('Insecure Deserialization (yaml.%m)', 'CWE-502', 'critical', DESER_REMEDIATION)),
  ...sinks('py-marshal', 'py', 'marshal', ['loads', 'load'], { receiver: '^marshal$' }, 0,
    v('Insecure Deserialization (marshal.%m)', 'CWE-502', 'critical', DESER_REMEDIATION)),
  { kind: 'sink', id: 'py-jsonpickle-decode', language: 'py', framework: 'jsonpickle', match: { type: 'call', callee: 'decode', receiver: '^jsonpickle$' }, argIndex: 0,
    vuln: v('Insecure Deserialization (jsonpickle.decode)', 'CWE-502', 'critical', DESER_REMEDIATION) },
  { kind: 'sink', id: 'py-torch-load', language: 'py', framework: 'torch', match: { type: 'call', callee: 'load', receiver: '^torch$', rejectKeyword: { name: 'weights_only', pattern: '^(?:true|True|1)$' } }, argIndex: 0,
    vuln: v('Insecure Deserialization (torch.load of a request-chosen file)', 'CWE-502', 'critical', 'Load only files you produced, and pass weights_only=True.') },
  { kind: 'sink', id: 'py-numpy-load-pickle', language: 'py', framework: 'numpy', match: { type: 'call', callee: 'load', receiver: '^(?:np|numpy)$', requireKeyword: { name: 'allow_pickle', pattern: '^(?:true|True|1)$' } }, argIndex: 0,
    vuln: v('Insecure Deserialization (numpy.load with allow_pickle=True)', 'CWE-502', 'critical', DESER_REMEDIATION) },

  // SQL.
  { kind: 'sink', id: 'py-django-rawsql', language: 'py', framework: 'django', match: { type: 'call', callee: 'RawSQL' }, argIndex: 0,
    vuln: v('SQL Injection (RawSQL)', 'CWE-89', 'critical', SQL_REMEDIATION) },
  { kind: 'sink', id: 'py-sqlite-executescript', language: 'py', framework: 'sqlite3', match: { type: 'call', callee: 'executescript' }, argIndex: 0,
    vuln: v('SQL Injection (executescript)', 'CWE-89', 'critical', SQL_REMEDIATION) },
];

// ─── Java (and Kotlin, which shares the JVM family) ───────────────────────
const JAVA = [
  // JAX-RS / Jakarta REST, Quarkus REST, Micronaut and the Spring annotations the base catalog lacks.
  ...annotationSources('java-src-ann', 'java', 'jax-rs/spring/quarkus/micronaut', {
    QueryParam: 'url-param', PathParam: 'path-param', FormParam: 'http-body', HeaderParam: 'header', CookieParam: 'cookie', MatrixParam: 'path-param',
    CookieValue: 'cookie', MatrixVariable: 'path-param', RequestPart: 'http-body',
    RestQuery: 'url-param', RestPath: 'path-param', RestForm: 'http-body', RestHeader: 'header', RestCookie: 'cookie',
    QueryValue: 'url-param',
  }),
  // Servlet request accessors the base catalog lacks.
  ...callSources('java-src-servlet', 'java', 'servlet', ['getParameterValues', 'getParameterMap', 'getHeaders', 'getRequestURI', 'getRequestURL', 'getPathInfo', 'getPart', 'getParts'],
    {}, 'url-param', 'HttpServletRequest.%m()'),
  // Ktor request (application call): every accessor on `call.request` is client-controlled.
  { kind: 'source', id: 'kt-src-ktor-call-request', language: 'kt', framework: 'ktor', match: { type: 'member', object: 'call', prop: 'request' }, label: 'call.request (Ktor)', provenance: 'url-param' },
  ...callSources('kt-src-ktor-receive', 'kt', 'ktor', ['receiveText', 'receiveParameters', 'receiveMultipart', 'receiveNullable', 'receiveStream', 'receiveChannel'],
    {}, 'http-body', 'call.%m() (Ktor)'),

  // Command execution: ProcessBuilder. Program chosen by the request, or a literal shell running request data.
  ...sinks('java-processbuilder', 'java', 'stdlib', ['ProcessBuilder'], {}, 0,
    v('Command Injection (ProcessBuilder with a request-chosen command)', 'CWE-78', 'critical', CMD_REMEDIATION)),
  ...sinks('java-processbuilder-shell', 'java', 'stdlib', ['ProcessBuilder'], { requireLiteralArg: { index: 0, pattern: SHELL_LITERAL } }, 'all',
    v('Command Injection (ProcessBuilder through a shell interpreter)', 'CWE-78', 'critical', CMD_REMEDIATION)),
  // `new ProcessBuilder(...).start()` lowers to one chained call named `start`.
  { kind: 'sink', id: 'java-processbuilder-start', language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'start', receiver: '^ProcessBuilder$' }, argIndex: 0,
    vuln: v('Command Injection (ProcessBuilder(...).start)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  { kind: 'sink', id: 'java-processbuilder-start-shell', language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'start', receiver: '^ProcessBuilder$', requireLiteralArg: { index: 0, pattern: SHELL_LITERAL } }, argIndex: 'all',
    vuln: v('Command Injection (ProcessBuilder(...).start through a shell interpreter)', 'CWE-78', 'critical', CMD_REMEDIATION) },

  // SSRF: Spring RestTemplate / WebClient / RestClient, Java HttpClient, Apache HttpClient, OkHttp, Jsoup.
  ...sinks('java-resttemplate', 'java', 'spring', ['getForObject', 'getForEntity', 'postForObject', 'postForEntity', 'postForLocation', 'patchForObject', 'headForHeaders', 'optionsForAllow'], {}, 0,
    v('SSRF (RestTemplate.%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  ...sinks('java-resttemplate-generic', 'java', 'spring', ['exchange', 'execute', 'put', 'delete'], { receiver: '[Rr]est(?:Template|Operations)' }, 0,
    v('SSRF (RestTemplate.%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'java-http-uri', language: 'java', framework: 'spring/java.net.http', match: { type: 'call', callee: 'uri', receiver: '[Ww]eb[Cc]lient|[Rr]est[Cc]lient|^newBuilder$|^HttpRequest$' }, argIndex: 0,
    vuln: v('SSRF (request builder .uri)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'java-httprequest-newbuilder', language: 'java', framework: 'java.net.http', match: { type: 'call', callee: 'newBuilder', receiver: '^HttpRequest$' }, argIndex: 0,
    vuln: v('SSRF (HttpRequest.newBuilder)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'java-webclient-create', language: 'java', framework: 'spring', match: { type: 'call', callee: 'create', receiver: '^(?:WebClient|RestClient)$' }, argIndex: 0,
    vuln: v('SSRF (WebClient.create)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  ...sinks('java-apache-http', 'java', 'apache-httpclient', ['HttpGet', 'HttpPost', 'HttpPut', 'HttpDelete', 'HttpHead', 'HttpPatch'], {}, 0,
    v('SSRF (new %m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'java-okhttp-url', language: 'java', framework: 'okhttp', match: { type: 'call', callee: 'url', receiver: '^Builder$' }, argIndex: 0,
    vuln: v('SSRF (OkHttp Request.Builder.url)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'java-url-openconnection', language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'openConnection', receiver: '^URL$' }, argIndex: 'all',
    vuln: v('SSRF (new URL(...).openConnection)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'java-jsoup-connect', language: 'java', framework: 'jsoup', match: { type: 'call', callee: 'connect', receiver: '^Jsoup$' }, argIndex: 0,
    vuln: v('SSRF (Jsoup.connect)', 'CWE-918', 'high', SSRF_REMEDIATION) },

  // Path traversal: java.nio.file.Files and Spring resources.
  ...sinks('java-nio-files', 'java', 'nio', ['readString', 'readAllLines', 'lines', 'newInputStream', 'newBufferedReader', 'newOutputStream', 'newBufferedWriter', 'write', 'writeString', 'delete', 'deleteIfExists', 'copy', 'move', 'list', 'walk'], { receiver: '^Files$' }, 0,
    v('Path Traversal (Files.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  { kind: 'sink', id: 'java-spring-filesystemresource', language: 'java', framework: 'spring', match: { type: 'call', callee: 'FileSystemResource' }, argIndex: 0,
    vuln: v('Path Traversal (new FileSystemResource)', 'CWE-22', 'high', PATH_REMEDIATION) },
  ...sinks('kt-file-read', 'kt', 'stdlib', ['readBytes', 'readLines', 'forEachLine', 'inputStream', 'bufferedReader', 'delete', 'deleteRecursively', 'listFiles'], { receiver: '^File$' }, 'all',
    v('Path Traversal (File(...).%m)', 'CWE-22', 'high', PATH_REMEDIATION)),

  // Open redirect.
  { kind: 'sink', id: 'java-spring-redirectview', language: 'java', framework: 'spring', match: { type: 'call', callee: 'RedirectView' }, argIndex: 0,
    vuln: v('Open Redirect (new RedirectView)', 'CWE-601', 'medium', REDIRECT_REMEDIATION) },
  { kind: 'sink', id: 'java-spring-modelandview-redirect', language: 'java', framework: 'spring', match: { type: 'call', callee: 'ModelAndView', requireStaticPrefix: { index: 0, pattern: '^redirect:' } }, argIndex: 0,
    vuln: v('Open Redirect (ModelAndView("redirect:" + ...))', 'CWE-601', 'medium', REDIRECT_REMEDIATION) },
  { kind: 'sink', id: 'kt-ktor-respondredirect', language: 'kt', framework: 'ktor', match: { type: 'call', callee: 'respondRedirect' }, argIndex: 0,
    vuln: v('Open Redirect (call.respondRedirect)', 'CWE-601', 'medium', REDIRECT_REMEDIATION) },

  // ReDoS.
  ...sinks('java-pattern', 'java', 'java.util.regex', ['compile', 'matches'], { receiver: '^Pattern$' }, 0,
    v('ReDoS (Pattern.%m with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION)),
  { kind: 'sink', id: 'kt-regex-ctor', language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'Regex', receiverExclude: '.' }, argIndex: 0,
    vuln: v('ReDoS (Regex(...) with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION) },

  // Deserialization.
  ...sinks('java-deser-ctor', 'java', 'stdlib', ['ObjectInputStream', 'XMLDecoder'], {}, 0,
    v('Insecure Deserialization (new %m over request data)', 'CWE-502', 'critical', DESER_REMEDIATION)),
  { kind: 'sink', id: 'java-xstream-fromxml', language: 'java', framework: 'xstream', match: { type: 'call', callee: 'fromXML' }, argIndex: 0,
    vuln: v('Insecure Deserialization (XStream.fromXML)', 'CWE-502', 'critical', DESER_REMEDIATION) },

  // XXE: StAX readers.
  ...sinks('java-stax', 'java', 'stax', ['createXMLStreamReader', 'createXMLEventReader'], {}, 'all',
    v('XXE (XMLInputFactory.%m)', 'CWE-611', 'high', XXE_REMEDIATION)),

  // SQL: Spring JdbcTemplate.
  ...sinks('java-jdbctemplate', 'java', 'spring-jdbc', ['queryForList', 'queryForObject', 'queryForMap', 'queryForRowSet', 'queryForStream', 'batchUpdate'], {}, 0,
    v('SQL Injection (JdbcTemplate.%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('java-jdbctemplate-generic', 'java', 'spring-jdbc', ['query', 'update'], { receiver: '[Jj]dbc' }, 0,
    v('SQL Injection (JdbcTemplate.%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),

  // Expression and script evaluation.
  ...sinks('java-groovy', 'java', 'groovy', ['evaluate', 'run'], { receiver: '[Gg]roovy[Ss]hell' }, 0,
    v('Code Injection (GroovyShell.%m)', 'CWE-94', 'critical', CODE_REMEDIATION)),
  ...sinks('java-ognl', 'java', 'ognl', ['getValue', 'parseExpression'], { receiver: '^Ognl$' }, 0,
    v('Expression Language Injection (Ognl.%m)', 'CWE-94', 'critical', CODE_REMEDIATION)),
  ...sinks('java-mvel', 'java', 'mvel', ['eval', 'compileExpression', 'executeExpression'], { receiver: '^MVEL$' }, 0,
    v('Expression Language Injection (MVEL.%m)', 'CWE-94', 'critical', CODE_REMEDIATION)),
];

// ─── Go ──────────────────────────────────────────────────────────────────
const GO_REQ = '^(?:r|req|request)$';
const GO = [
  ...memberSources('go-src', 'go', 'net/http', ['r', 'req', 'request'], { URL: 'url-param', Header: 'header', RequestURI: 'url-param', MultipartForm: 'http-body' }),
  ...memberSources('go-src', 'go', 'net/http', ['req', 'request'], { Body: 'http-body', Form: 'http-body', PostForm: 'http-body' }),
  ...callSources('go-src-req', 'go', 'net/http', ['PathValue', 'Cookie', 'Cookies', 'FormFile', 'Referer', 'UserAgent', 'MultipartReader'], { receiver: GO_REQ }, 'url-param', 'r.%m() (net/http)'),
  ...callSources('go-src-req-header', 'go', 'net/http', ['Get', 'Values'], { receiver: '^Header$', receiverBase: GO_REQ }, 'header', 'r.Header.%m() (net/http)'),
  // Gin / Echo / Fiber accessors the base catalog lacks (names specific to those frameworks).
  ...callSources('go-src-gin', 'go', 'gin', ['GetHeader', 'DefaultQuery', 'DefaultPostForm', 'GetQuery', 'GetQueryArray', 'QueryArray', 'QueryMap', 'GetPostForm', 'GetPostFormArray', 'PostFormArray', 'PostFormMap', 'GetRawData'],
    {}, 'url-param', 'c.%m() (gin)'),
  ...callSources('go-src-echo-fiber', 'go', 'echo/fiber', ['QueryParams', 'FormParams', 'QueryString', 'ParamValues', 'GetReqHeaders', 'Queries', 'AllParams', 'OriginalURL'],
    {}, 'url-param', 'c.%m() (echo/fiber)'),

  // Path traversal.
  { kind: 'sink', id: 'go-ioutil-readfile', language: 'go', framework: 'io/ioutil', match: { type: 'call', callee: 'ReadFile', receiver: '^ioutil$' }, argIndex: 0,
    vuln: v('Path Traversal (ioutil.ReadFile)', 'CWE-22', 'high', PATH_REMEDIATION) },
  ...sinks('go-os-path', 'go', 'os', ['OpenFile', 'Create', 'Remove', 'RemoveAll', 'WriteFile', 'ReadDir', 'Mkdir', 'MkdirAll', 'Rename'], { receiver: '^(?:os|ioutil)$' }, 0,
    v('Path Traversal (os.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  { kind: 'sink', id: 'go-http-servefile', language: 'go', framework: 'net/http', match: { type: 'call', callee: 'ServeFile', receiver: '^http$' }, argIndex: 2,
    vuln: v('Path Traversal (http.ServeFile)', 'CWE-22', 'high', PATH_REMEDIATION) },
  ...sinks('go-ctx-file', 'go', 'gin/echo/fiber', ['File', 'FileAttachment', 'Attachment', 'Inline', 'SendFile', 'Download'], { receiver: '^(?:c|ctx|context)$' }, 0,
    v('Path Traversal (c.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),

  // SSRF.
  ...sinks('go-http-client', 'go', 'net/http', ['Post', 'PostForm', 'Head'], { receiver: '^http$' }, 0,
    v('SSRF (http.%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'go-http-newrequest', language: 'go', framework: 'net/http', match: { type: 'call', callee: 'NewRequest' }, argIndex: 1,
    vuln: v('SSRF (http.NewRequest)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'go-http-newrequestwithcontext', language: 'go', framework: 'net/http', match: { type: 'call', callee: 'NewRequestWithContext' }, argIndex: 2,
    vuln: v('SSRF (http.NewRequestWithContext)', 'CWE-918', 'high', SSRF_REMEDIATION) },

  // Reflected XSS through raw response writes, and template.HTML/JS/URL conversions that bypass html/template escaping.
  { kind: 'sink', id: 'go-responsewriter-write', language: 'go', framework: 'net/http', match: { type: 'call', callee: 'Write', receiver: '^(?:w|rw|writer|resp|res|response)$' }, argIndex: 0,
    vuln: v('Reflected XSS (ResponseWriter.Write)', 'CWE-79', 'high', XSS_REMEDIATION) },
  { kind: 'sink', id: 'go-io-writestring', language: 'go', framework: 'io', match: { type: 'call', callee: 'WriteString', receiver: '^io$' }, argIndex: 1,
    vuln: v('Reflected XSS (io.WriteString to the response)', 'CWE-79', 'high', XSS_REMEDIATION) },
  ...sinks('go-fmt-fprint', 'go', 'fmt', ['Fprint', 'Fprintln'], { receiver: '^fmt$' }, 'all',
    v('Reflected XSS (fmt.%m to the response)', 'CWE-79', 'high', XSS_REMEDIATION)),
  ...sinks('go-template-trusted', 'go', 'html/template', ['HTML', 'JS', 'HTMLAttr', 'URL', 'CSS', 'JSStr', 'Srcset'], { receiver: '^template$' }, 0,
    v('XSS (template.%m marks request data as trusted)', 'CWE-79', 'high', 'Pass the value as a plain string so html/template escapes it; never convert request data to template.HTML/JS/URL.')),
  { kind: 'sink', id: 'go-echo-html', language: 'go', framework: 'echo', match: { type: 'call', callee: 'HTML', receiver: '^(?:c|ctx)$' }, argIndex: 1,
    vuln: v('Reflected XSS (echo c.HTML with a raw HTML string)', 'CWE-79', 'high', XSS_REMEDIATION) },

  // SQL: context-taking database/sql methods and sqlx.
  ...sinks('go-sql-ctx', 'go', 'database/sql', ['ExecContext', 'QueryContext', 'QueryRowContext', 'PrepareContext'], {}, 1,
    v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('go-sql-prepare', 'go', 'database/sql/sqlx', ['Prepare', 'Queryx', 'QueryRowx', 'MustExec', 'NamedExec', 'NamedQuery'], {}, 0,
    v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('go-sqlx-dest', 'go', 'sqlx', ['Select', 'Get'], { receiver: '^(?:db|tx|sqlx|conn|DB|dbx)$' }, 1,
    v('SQL Injection (sqlx %m)', 'CWE-89', 'critical', SQL_REMEDIATION)),

  // Command execution: request data choosing the program.
  { kind: 'sink', id: 'go-exec-command-program', language: 'go', framework: 'os/exec', match: { type: 'call', callee: 'Command' }, argIndex: 0,
    vuln: v('Command Injection (exec.Command with a request-chosen program)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  ...['Output', 'Run', 'CombinedOutput', 'Start'].map((m) => ({ kind: 'sink', id: `go-exec-command-program-${m.toLowerCase()}`, language: 'go', framework: 'os/exec',
    match: { type: 'call', callee: m, receiver: '^Command$' }, argIndex: 0,
    vuln: v('Command Injection (exec.Command with a request-chosen program)', 'CWE-78', 'critical', CMD_REMEDIATION) })),
  { kind: 'sink', id: 'go-exec-commandcontext-shell', language: 'go', framework: 'os/exec', match: { type: 'call', callee: 'CommandContext', requireLiteralArg: { index: 1, pattern: SHELL_LITERAL } }, argIndex: 'all',
    vuln: v('Command Injection (exec.CommandContext through a shell interpreter)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  { kind: 'sink', id: 'go-exec-commandcontext-program', language: 'go', framework: 'os/exec', match: { type: 'call', callee: 'CommandContext' }, argIndex: 1,
    vuln: v('Command Injection (exec.CommandContext with a request-chosen program)', 'CWE-78', 'critical', CMD_REMEDIATION) },
];

// ─── PHP ─────────────────────────────────────────────────────────────────
const PHP_REQ_METHODS = ['input', 'query', 'post', 'all', 'cookie', 'header', 'file', 'json', 'string', 'str', 'only', 'except', 'collect', 'getContent'];
const PHP = [
  // Laravel Request facade (Request::input()) and CodeIgniter accessors.
  ...callSources('php-src-request-facade', 'php', 'laravel', PHP_REQ_METHODS, { receiver: '^Request$' }, 'url-param', 'Request::%m() (Laravel facade)'),
  ...callSources('php-src-ci4', 'php', 'codeigniter', ['getGet', 'getPost', 'getVar', 'getJSON', 'getRawInput', 'getGetPost', 'getPostGet', 'getCookie'], {}, 'url-param', '$this->request->%m() (CodeIgniter 4)'),
  ...callSources('php-src-ci3', 'php', 'codeigniter', ['get', 'post', 'get_post', 'cookie', 'server', 'input_stream'], { receiver: '^input$' }, 'url-param', '$this->input->%m() (CodeIgniter 3)'),

  // Path traversal / file write.
  ...sinks('php-file', 'php', 'core', ['fopen', 'file', 'file_get_contents', 'unlink', 'rmdir', 'opendir', 'scandir', 'show_source', 'highlight_file', 'parse_ini_file', 'mkdir'], {}, 0,
    v('Path Traversal (%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('php-file-write', 'php', 'core', ['file_put_contents'], {}, 0, v('Arbitrary File Write (%m)', 'CWE-73', 'critical', PATH_REMEDIATION)),
  ...sinks('php-file-two', 'php', 'core', ['copy', 'rename'], {}, 'all', v('Path Traversal (%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  { kind: 'sink', id: 'php-move-uploaded-file', language: 'php', framework: 'core', match: { type: 'call', callee: 'move_uploaded_file' }, argIndex: 1,
    vuln: v('Arbitrary File Write (move_uploaded_file to a request-chosen path)', 'CWE-73', 'critical', 'Generate the destination file name server-side; never use the client file name.') },
  ...sinks('php-laravel-storage', 'php', 'laravel', ['get', 'download', 'delete', 'put', 'readStream'], { receiver: '^Storage$' }, 0,
    v('Path Traversal (Storage::%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('php-laravel-response-file', 'php', 'laravel', ['download', 'file'], { receiver: '^response$' }, 0,
    v('Path Traversal (response()->%m)', 'CWE-22', 'high', PATH_REMEDIATION)),

  // SSRF.
  ...sinks('php-laravel-http', 'php', 'laravel', ['get', 'post', 'put', 'patch', 'delete', 'head'], { receiver: '^Http$' }, 0,
    v('SSRF (Http::%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  ...sinks('php-guzzle', 'php', 'guzzle', ['get', 'post', 'put', 'patch', 'delete', 'head', 'getAsync', 'postAsync'], { receiver: '^\\$?(?:client|guzzle|http|httpClient|httpclient)$' }, 0,
    v('SSRF (Guzzle %m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  ...sinks('php-guzzle-request', 'php', 'guzzle', ['request', 'requestAsync'], { receiver: '^\\$?(?:client|guzzle|http|httpClient|httpclient)$' }, 1,
    v('SSRF (Guzzle %m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'php-fsockopen', language: 'php', framework: 'core', match: { type: 'call', callee: 'fsockopen' }, argIndex: 0,
    vuln: v('SSRF (fsockopen)', 'CWE-918', 'high', SSRF_REMEDIATION) },

  // Open redirect.
  { kind: 'sink', id: 'php-laravel-redirect', language: 'php', framework: 'laravel', match: { type: 'call', callee: 'redirect', receiverExclude: '.' }, argIndex: 0,
    vuln: v('Open Redirect (redirect($url))', 'CWE-601', 'medium', REDIRECT_REMEDIATION) },
  ...sinks('php-laravel-redirect-to', 'php', 'laravel', ['to', 'away'], { receiver: '^(?:redirect|Redirect)$' }, 0,
    v('Open Redirect (redirect()->%m)', 'CWE-601', 'medium', REDIRECT_REMEDIATION)),
  { kind: 'sink', id: 'php-symfony-redirectresponse', language: 'php', framework: 'symfony', match: { type: 'call', callee: 'RedirectResponse' }, argIndex: 0,
    vuln: v('Open Redirect (new RedirectResponse)', 'CWE-601', 'medium', REDIRECT_REMEDIATION) },

  // XSS.
  ...sinks('php-print', 'php', 'core', ['print', 'printf', 'vprintf'], {}, 'all', v('Reflected XSS (%m)', 'CWE-79', 'high', XSS_REMEDIATION)),
  { kind: 'sink', id: 'php-symfony-response', language: 'php', framework: 'symfony', match: { type: 'call', callee: 'Response' }, argIndex: 0,
    vuln: v('Reflected XSS (new Response)', 'CWE-79', 'high', XSS_REMEDIATION) },
  { kind: 'sink', id: 'php-laravel-response', language: 'php', framework: 'laravel', match: { type: 'call', callee: 'response', receiverExclude: '.' }, argIndex: 0,
    vuln: v('Reflected XSS (response($content))', 'CWE-79', 'high', XSS_REMEDIATION) },

  // Command and code execution.
  ...sinks('php-cmd', 'php', 'core', ['popen', 'pcntl_exec'], {}, 0, v('Command Injection (%m)', 'CWE-78', 'critical', CMD_REMEDIATION)),
  ...sinks('php-code', 'php', 'core', ['assert', 'create_function'], {}, 'all', v('Code Injection (%m)', 'CWE-95', 'critical', CODE_REMEDIATION)),

  // SQL.
  ...sinks('php-sql-any', 'php', 'pgsql', ['pg_query', 'pg_send_query'], {}, 'all', v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  { kind: 'sink', id: 'php-mysqli-multi-query', language: 'php', framework: 'mysqli', match: { type: 'call', callee: 'mysqli_multi_query' }, argIndex: 1,
    vuln: v('SQL Injection (mysqli_multi_query)', 'CWE-89', 'critical', SQL_REMEDIATION) },
  ...sinks('php-sql-first', 'php', 'pdo/mysqli/sqlite/laravel', ['multi_query', 'prepare', 'querySingle', 'whereRaw', 'orWhereRaw', 'selectRaw', 'orderByRaw', 'havingRaw', 'groupByRaw', 'fromRaw'], {}, 0,
    v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('php-laravel-db', 'php', 'laravel', ['select', 'statement', 'unprepared', 'insert', 'update', 'delete', 'affectingStatement', 'scalar', 'selectOne'], { receiver: '^DB$' }, 0,
    v('SQL Injection (DB::%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),

  // ReDoS.
  ...sinks('php-preg', 'php', 'pcre', ['preg_match', 'preg_match_all', 'preg_replace', 'preg_replace_callback', 'preg_split', 'preg_grep'], {}, 0,
    v('ReDoS (%m with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION)),
];

// ─── Ruby ────────────────────────────────────────────────────────────────
const HTTP_CLIENTS_RB = '^(?:HTTParty|Faraday|RestClient|Excon|Typhoeus|HTTP)$';
const RB = [
  ...memberSources('rb-src', 'rb', 'rails/rack', ['request'], { raw_post: 'http-body', query_string: 'url-param', fullpath: 'url-param', url: 'url-param', referer: 'header', path: 'path-param', query_parameters: 'url-param', request_parameters: 'http-body', headers: 'header', cookies: 'cookie' }),

  // Path traversal.
  { kind: 'sink', id: 'rb-send-file', language: 'rb', framework: 'rails/sinatra', match: { type: 'call', callee: 'send_file' }, argIndex: 0,
    vuln: v('Path Traversal (send_file)', 'CWE-22', 'high', PATH_REMEDIATION) },
  ...sinks('rb-file', 'rb', 'stdlib', ['open', 'readlines', 'binread', 'new', 'foreach', 'delete', 'unlink', 'write', 'binwrite'], { receiver: '^(?:File|IO)$' }, 0,
    v('Path Traversal (File.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  { kind: 'sink', id: 'rb-io-read', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'read', receiver: '^IO$' }, argIndex: 0,
    vuln: v('Path Traversal (IO.read)', 'CWE-22', 'high', PATH_REMEDIATION) },
  ...sinks('rb-fileutils', 'rb', 'stdlib', ['rm', 'rm_f', 'rm_r', 'rm_rf', 'cp', 'mv', 'remove', 'remove_dir'], { receiver: '^FileUtils$' }, 0,
    v('Path Traversal (FileUtils.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),

  // Command execution. Kernel#open runs a command when the path starts with "|".
  { kind: 'sink', id: 'rb-kernel-open', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'open', receiverExclude: '.' }, argIndex: 0,
    vuln: v('Command Injection (Kernel#open with a request-chosen path)', 'CWE-78', 'critical', 'Use File.open (never Kernel#open) for files and URI.open only with a validated URL.') },
  { kind: 'sink', id: 'rb-spawn', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'spawn' }, argIndex: 0,
    vuln: v('Command Injection (spawn)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  { kind: 'sink', id: 'rb-io-popen', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'popen', receiver: '^IO$' }, argIndex: 0,
    vuln: v('Command Injection (IO.popen)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  ...sinks('rb-open3', 'rb', 'open3', ['capture2', 'capture2e', 'capture3', 'popen2', 'popen2e', 'popen3', 'pipeline', 'pipeline_r'], { receiver: '^Open3$' }, 0,
    v('Command Injection (Open3.%m)', 'CWE-78', 'critical', CMD_REMEDIATION)),

  // SSRF.
  ...sinks('rb-http-client', 'rb', 'net-http/httparty/faraday', ['get', 'get_response', 'post', 'post_form', 'put', 'patch', 'delete', 'head', 'start', 'new'], { receiver: HTTP_CLIENTS_RB }, 0,
    v('SSRF (%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),

  // Code execution and unsafe reflection.
  ...sinks('rb-eval-family', 'rb', 'stdlib', ['instance_eval', 'class_eval', 'module_eval'], {}, 0,
    v('Code Injection (%m)', 'CWE-95', 'critical', CODE_REMEDIATION)),
  ...sinks('rb-send', 'rb', 'stdlib', ['send', 'public_send', '__send__'], {}, 0,
    v('Unsafe Reflection (%m with a request-chosen method)', 'CWE-470', 'high', 'Map the input to an allow-listed method name before calling it.')),

  // XSS, SQL, ReDoS, deserialization.
  { kind: 'sink', id: 'rb-raw', language: 'rb', framework: 'rails', match: { type: 'call', callee: 'raw' }, argIndex: 0,
    vuln: v('XSS (raw on request data)', 'CWE-79', 'high', XSS_REMEDIATION) },
  ...sinks('rb-ar-fragment', 'rb', 'rails', ['joins', 'group', 'having', 'count_by_sql'], {}, 0,
    v('SQL Injection (%m with a SQL fragment)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('rb-ar-connection', 'rb', 'rails', ['execute', 'exec_query', 'select_all', 'select_value', 'select_values', 'select_rows', 'select_one'], { receiver: '^(?:connection|conn|db|ActiveRecord|Base)$' }, 0,
    v('SQL Injection (connection.%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('rb-regexp', 'rb', 'stdlib', ['new', 'compile'], { receiver: '^Regexp$' }, 0,
    v('ReDoS (Regexp.%m with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION)),
  ...sinks('rb-unsafe-load', 'rb', 'stdlib', ['unsafe_load', 'restore'], { receiver: '^(?:YAML|Psych|Marshal)$' }, 0,
    v('Insecure Deserialization (%m)', 'CWE-502', 'critical', DESER_REMEDIATION)),
];

// ─── C# ──────────────────────────────────────────────────────────────────
const CS = [
  ...memberSources('cs-src', 'cs', 'aspnetcore', ['Request', 'req'], { Query: 'url-param', RouteValues: 'path-param', Path: 'path-param' }),
  ...memberSources('cs-src-lc', 'cs', 'aspnetcore', ['request'], { Query: 'url-param', RouteValues: 'path-param', Path: 'path-param' }),
  // The whole request off an HttpContext (`HttpContext.Request.Query["x"]`, middleware `context.Request`).
  ...memberSources('cs-src-httpcontext', 'cs', 'aspnetcore', ['HttpContext', 'context'], { Request: 'url-param' }),
  ...memberSources('cs-src-httpcontext-lc', 'cs', 'aspnetcore', ['httpContext'], { Request: 'url-param' }),

  // SQL: EF Core raw SQL and Dapper.
  ...sinks('cs-efcore-raw', 'cs', 'efcore', ['FromSqlRaw', 'ExecuteSqlRaw', 'ExecuteSqlRawAsync', 'SqlQueryRaw', 'ExecuteSqlCommand', 'ExecuteSqlCommandAsync', 'SqlQuery'], {}, 0,
    v('SQL Injection (%m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  // `ctx.Users.FromSqlRaw(sql).ToList()` lowers to one chained call named after
  // the LINQ operator that materializes it; the raw SQL is still its argument.
  ...sinks('cs-efcore-raw-chain', 'cs', 'efcore', ['ToList', 'ToListAsync', 'ToArray', 'ToArrayAsync', 'First', 'FirstAsync', 'FirstOrDefault', 'FirstOrDefaultAsync', 'Single', 'SingleOrDefault', 'SingleOrDefaultAsync', 'AsNoTracking', 'AsEnumerable', 'AsAsyncEnumerable', 'Count', 'CountAsync', 'AnyAsync', 'Where', 'Select', 'OrderBy'],
    { receiver: '^(?:FromSqlRaw|SqlQueryRaw)$' }, 'all', v('SQL Injection (FromSqlRaw)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('cs-dapper', 'cs', 'dapper', ['QueryAsync', 'QueryFirst', 'QueryFirstOrDefault', 'QuerySingle', 'QuerySingleOrDefault', 'QueryFirstAsync', 'QueryFirstOrDefaultAsync', 'QuerySingleAsync', 'QuerySingleOrDefaultAsync', 'QueryMultiple', 'QueryMultipleAsync', 'ExecuteScalarAsync'], {}, 0,
    v('SQL Injection (Dapper %m)', 'CWE-89', 'critical', SQL_REMEDIATION)),
  ...sinks('cs-dapper-execute', 'cs', 'dapper', ['Execute', 'ExecuteAsync', 'ExecuteScalar', 'ExecuteReader'], { receiver: '(?:[Cc]onn(?:ection)?|[Dd]b|[Cc]n)$' }, 0,
    v('SQL Injection (Dapper %m)', 'CWE-89', 'critical', SQL_REMEDIATION)),

  // Path traversal.
  ...sinks('cs-file', 'cs', 'System.IO', ['ReadAllBytes', 'ReadAllLines', 'ReadLines', 'OpenRead', 'OpenText', 'OpenWrite', 'Open', 'Delete', 'WriteAllBytes', 'WriteAllLines', 'AppendAllText', 'Create', 'Copy', 'Move', 'ReadAllTextAsync', 'ReadAllBytesAsync', 'WriteAllTextAsync', 'WriteAllBytesAsync'], { receiver: '^File$' }, 0,
    v('Path Traversal (File.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('cs-directory', 'cs', 'System.IO', ['GetFiles', 'EnumerateFiles', 'GetDirectories', 'Delete', 'CreateDirectory'], { receiver: '^Directory$' }, 0,
    v('Path Traversal (Directory.%m)', 'CWE-22', 'high', PATH_REMEDIATION)),
  ...sinks('cs-file-ctor', 'cs', 'System.IO', ['FileStream', 'FileInfo', 'PhysicalFile', 'PhysicalFileResult'], {}, 0,
    v('Path Traversal (%m)', 'CWE-22', 'high', PATH_REMEDIATION)),

  // SSRF.
  ...sinks('cs-httpclient', 'cs', 'System.Net.Http', ['GetAsync', 'PostAsync', 'PutAsync', 'DeleteAsync', 'PatchAsync', 'GetByteArrayAsync', 'GetStreamAsync', 'GetFromJsonAsync', 'PostAsJsonAsync', 'PutAsJsonAsync'], { receiver: '[Hh]ttp|^_?[Cc]lient$', receiverTypeIn: ['^HttpClient$'] }, 0,
    v('SSRF (HttpClient.%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),
  { kind: 'sink', id: 'cs-webrequest-create', language: 'cs', framework: 'System.Net', match: { type: 'call', callee: 'Create', receiver: 'WebRequest$' }, argIndex: 0,
    vuln: v('SSRF (WebRequest.Create)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  { kind: 'sink', id: 'cs-httprequestmessage', language: 'cs', framework: 'System.Net.Http', match: { type: 'call', callee: 'HttpRequestMessage' }, argIndex: 1,
    vuln: v('SSRF (new HttpRequestMessage)', 'CWE-918', 'high', SSRF_REMEDIATION) },
  ...sinks('cs-webclient', 'cs', 'System.Net', ['DownloadData', 'DownloadFile', 'DownloadDataTaskAsync', 'DownloadStringTaskAsync', 'UploadString', 'UploadData', 'RestClient'], {}, 0,
    v('SSRF (%m)', 'CWE-918', 'high', SSRF_REMEDIATION)),

  // XSS.
  { kind: 'sink', id: 'cs-html-raw', language: 'cs', framework: 'aspnet', match: { type: 'call', callee: 'Raw', receiver: '^Html$' }, argIndex: 0,
    vuln: v('XSS (Html.Raw on request data)', 'CWE-79', 'high', XSS_REMEDIATION) },
  ...sinks('cs-html-trusted', 'cs', 'aspnet/blazor', ['HtmlString', 'MarkupString'], {}, 0,
    v('XSS (new %m on request data)', 'CWE-79', 'high', XSS_REMEDIATION)),
  { kind: 'sink', id: 'cs-content-html', language: 'cs', framework: 'aspnet', match: { type: 'call', callee: 'Content', requireLiteralArg: { index: 1, pattern: 'text/html' } }, argIndex: 0,
    vuln: v('Reflected XSS (Content(..., "text/html"))', 'CWE-79', 'high', XSS_REMEDIATION) },
  { kind: 'sink', id: 'cs-response-writeasync', language: 'cs', framework: 'aspnetcore', match: { type: 'call', callee: 'WriteAsync', receiver: '^Response$' }, argIndex: 0,
    vuln: v('Reflected XSS (Response.WriteAsync)', 'CWE-79', 'high', XSS_REMEDIATION) },

  // Command and code execution.
  { kind: 'sink', id: 'cs-processstartinfo', language: 'cs', framework: 'System.Diagnostics', match: { type: 'call', callee: 'ProcessStartInfo' }, argIndex: 0,
    vuln: v('Command Injection (ProcessStartInfo with a request-chosen program)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  { kind: 'sink', id: 'cs-processstartinfo-shell', language: 'cs', framework: 'System.Diagnostics', match: { type: 'call', callee: 'ProcessStartInfo', requireLiteralArg: { index: 0, pattern: SHELL_LITERAL } }, argIndex: 1,
    vuln: v('Command Injection (ProcessStartInfo through a shell interpreter)', 'CWE-78', 'critical', CMD_REMEDIATION) },
  ...sinks('cs-csharpscript', 'cs', 'roslyn', ['EvaluateAsync', 'RunAsync', 'Create'], { receiver: '^CSharpScript$' }, 0,
    v('Code Injection (CSharpScript.%m)', 'CWE-94', 'critical', CODE_REMEDIATION)),

  // ReDoS: `new Regex(p)` and the static helpers, whose pattern is the second argument.
  { kind: 'sink', id: 'cs-regex-ctor', language: 'cs', framework: 'System.Text.RegularExpressions', match: { type: 'call', callee: 'Regex' }, argIndex: 0,
    vuln: v('ReDoS (new Regex with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION) },
  ...sinks('cs-regex-static', 'cs', 'System.Text.RegularExpressions', ['IsMatch', 'Match', 'Matches', 'Replace', 'Split', 'Count'], { receiver: '^Regex$' }, 1,
    v('ReDoS (Regex.%m with a request-built pattern)', 'CWE-1333', 'medium', REDOS_REMEDIATION)),
];

// ─── Cross-site scripting, round six ─────────────────────────────────────
// Where request data reaches HTML output unescaped, written from the
// frameworks' documented APIs. Two precision rules apply throughout:
//   - A generic text writer (Fastify `reply.send`, jQuery `.append`, Flask
//     `make_response`, `fmt.Fprintf`) is an XSS sink only when the static text
//     around the value is markup: `match.htmlSkeleton` (the tainted argument
//     must carry a `<tag` literal) or `requireLiteralArg` on the format string.
//     A value passed whole (an object, a `jsonify(...)` body, a node built with
//     `.text()`) is not read as HTML.
//   - An API that always produces HTML (Hono `c.html`, Django `format_html`'s
//     format string, Rails `content_tag(..., false)`) needs no markup gate, but
//     only the non-escaping argument is the sink.
// The escapers these flows go through are at the end, as sanitizers.
const HTML_LITERAL = '<[A-Za-z!/]';
const JQUERY_RECEIVER = '^(?:\\$[\\w$]*|jQuery)$';
const XSS = [
  // Hono: `c.html(s)` sends `s` as text/html. Its `html` tagged-template helper escapes interpolations; a
  // plain string concatenation does not.
  { kind: 'sink', id: 'js-hono-html', language: 'js', framework: 'hono', match: { type: 'call', callee: 'html', receiver: '^(?:c|ctx|context)$' }, argIndex: 0,
    vuln: v('Reflected XSS (Hono c.html with a raw HTML string)', 'CWE-79', 'high', 'Build the body with Hono\'s html`` tagged template (it escapes interpolations), or escape the value before concatenating it.') },
  // Fastify: `reply.send(string)` defaults to text/plain; it is HTML only when the handler set an HTML type,
  // which the markup in the body stands in for (the `.type(...)` call is not tied to the send).
  { kind: 'sink', id: 'js-fastify-reply-send-html', language: 'js', framework: 'fastify', match: { type: 'call', callee: 'send', receiver: '^reply$', htmlSkeleton: true }, argIndex: 0,
    vuln: v('Reflected XSS (Fastify reply.send with markup)', 'CWE-79', 'high', XSS_REMEDIATION) },
  // jQuery: `.html(s)` parses `s` as HTML whatever it holds. (`framework: 'dom'`: the destination is the browser
  // DOM, which is how the lineage sink registry classifies it.) The insertion methods parse a STRING argument
  // as HTML too, but they are also passed elements (`$('<li>').text(q)`), so they require markup text.
  { kind: 'sink', id: 'js-jquery-html', language: 'js', framework: 'dom', match: { type: 'call', callee: 'html', receiver: JQUERY_RECEIVER }, argIndex: 0,
    vuln: v('DOM XSS (jQuery .html)', 'CWE-79', 'high', 'Use .text() for text, or sanitize the markup before .html().') },
  ...sinks('js-jquery-insert', 'js', 'dom', ['append', 'prepend', 'after', 'before', 'replaceWith', 'wrap', 'wrapAll', 'wrapInner'], { receiver: JQUERY_RECEIVER, htmlSkeleton: true }, 0,
    v('DOM XSS (jQuery .%m with markup)', 'CWE-79', 'high', 'Build the element with $("<tag>").text(value) and insert that, or sanitize the markup first.')),
  { kind: 'sink', id: 'js-jquery-construct', language: 'js', framework: 'dom', match: { type: 'call', callee: '$', receiverExclude: '.', htmlSkeleton: true }, argIndex: 0,
    vuln: v('DOM XSS ($(markup) builds elements from request data)', 'CWE-79', 'high', 'Create the element from a literal tag and set the value with .text() or .attr().') },
  // `document.writeln` is `document.write` plus a newline (same receiver rule as the base js-document-write).
  { kind: 'sink', id: 'js-document-writeln', language: 'js', framework: 'dom',
    match: { type: 'call', callee: 'writeln', receiver: '^(?:[A-Za-z_$][\\w$]*[Dd]ocument|document|doc|window|win|top|parent|self|frames|iframe|frame)$' }, argIndex: 0,
    vuln: v('XSS (document.writeln)', 'CWE-79', 'high', 'Build the content with DOM APIs and textContent; never write request data as markup.') },

  // Django `format_html(format_string, *args)` escapes the ARGUMENTS; a format string built from request data
  // is emitted as markup (the base catalogs list format_html as a sanitizer, which is right for the arguments).
  { kind: 'sink', id: 'py-django-format-html-format', language: 'py', framework: 'django', match: { type: 'call', callee: 'format_html' }, argIndex: 0,
    vuln: v('XSS (format_html with a request-built format string)', 'CWE-79', 'high', 'Keep the format string literal and pass the value as an argument: format_html("<p>{}</p>", value).') },
  // Flask `make_response(body)`: a str body is sent as text/html. Usually its argument is `jsonify(...)` or a
  // rendered template, so only a body that carries markup text is read as HTML.
  { kind: 'sink', id: 'py-flask-make-response-html', language: 'py', framework: 'flask', match: { type: 'call', callee: 'make_response', htmlSkeleton: true }, argIndex: 0,
    vuln: v('Reflected XSS (make_response with markup)', 'CWE-79', 'high', XSS_REMEDIATION) },

  // A Flask `@app.route` view's returned str, and a Spring `@ResponseBody` String handler's return value, is the
  // response body (text/html). The frontends mark those returns (`routeReturn`, parser-py.helper.py and
  // parser-java.js) and the engine checks them as this synthetic call; markup text is required.
  { kind: 'sink', id: 'py-flask-view-return-html', language: 'py', framework: 'flask', match: { type: 'call', callee: '__route_return__', htmlSkeleton: true }, argIndex: 0,
    vuln: v('Reflected XSS (Flask view returns markup built from request data)', 'CWE-79', 'high', 'Render a template (Jinja escapes by default) or escape the value with markupsafe.escape before building the markup.') },
  { kind: 'sink', id: 'java-spring-responsebody-html', language: 'java', framework: 'spring', match: { type: 'call', callee: '__route_return__', htmlSkeleton: true }, argIndex: 0,
    vuln: v('Reflected XSS (@ResponseBody String with markup built from request data)', 'CWE-79', 'high', 'Return a view rendered by an escaping template engine, or escape the value with HtmlUtils.htmlEscape before building the markup.') },

  // Rails `content_tag(name, content, options, escape)`: `escape = false` emits `content` unescaped.
  { kind: 'sink', id: 'rb-content-tag-unescaped', language: 'rb', framework: 'rails', match: { type: 'call', callee: 'content_tag', requireLiteralArg: { index: 3, pattern: '^false$' } }, argIndex: 1,
    vuln: v('XSS (content_tag with escape = false)', 'CWE-79', 'high', 'Drop the `false` escape argument so content_tag escapes the content.') },

  // Go `fmt.Fprintf(w, "<p>%s</p>", v)`: the base go-fmt-fprintf entry covers a request-built FORMAT string
  // (argument 1); this one covers a value formatted into a literal markup format string.
  { kind: 'sink', id: 'go-fmt-fprintf-markup', language: 'go', framework: 'fmt', match: { type: 'call', callee: 'Fprintf', receiver: '^fmt$', requireLiteralArg: { index: 1, pattern: HTML_LITERAL } }, argIndex: 'all',
    vuln: v('Reflected XSS (fmt.Fprintf into an HTML format string)', 'CWE-79', 'high', 'Render HTML with html/template, or escape the value with html.EscapeString / template.HTMLEscapeString.') },

  // Escapers missing from the base and expanded catalogs. Scoped by receiver where the method name is generic.
  { kind: 'sanitizer', id: 'py-django-conditional-escape', language: 'py', match: { type: 'call', callee: 'conditional_escape' }, effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'php-laravel-e', language: 'php', match: { type: 'call', callee: 'e', receiverExclude: '.' }, effect: 'strip', appliesTo: ['xss'] },
  ...['esc_html', 'esc_attr', 'esc_textarea'].map((c) => ({ kind: 'sanitizer', id: `php-wp-${c.replace(/_/g, '-')}`, language: 'php', match: { type: 'call', callee: c }, effect: 'strip', appliesTo: ['xss'] })),
  { kind: 'sanitizer', id: 'cs-htmlencoder-encode', language: 'cs', match: { type: 'call', callee: 'Encode', receiver: '^_?[Hh]tmlEncoder$' }, effect: 'strip', appliesTo: ['xss'] },
  ...['HTMLEscapeString', 'HTMLEscaper'].map((c) => ({ kind: 'sanitizer', id: `go-template-${c.toLowerCase()}`, language: 'go', match: { type: 'call', callee: c, receiver: '^template$' }, effect: 'strip', appliesTo: ['xss'] })),
];

// Filesystem and program-selection sinks that command-line and library code
// routinely feed from its own environment, arguments and configuration. They
// carry `match.requireRequestSource`: engine.js reports them only when a
// recorded origin is not operator input (environment, command line, console,
// local file), so `readFileSync(join(process.env.HOME, ".rc"))` stays silent
// while the same call on a request value is reported.
const OPERATOR_FED_PREFIXES = [
  'js-fs-', 'js-cp-',
  'py-os-path-', 'py-shutil-', 'py-pathlib-read-', 'py-shell-always-',
  'java-nio-files-', 'java-processbuilder', 'kt-file-read-',
  'go-ioutil-readfile', 'go-os-path-', 'go-exec-command', 'go-exec-commandcontext',
  'php-file-', 'php-cmd-',
  'rb-file-', 'rb-io-read', 'rb-fileutils-', 'rb-kernel-open', 'rb-spawn', 'rb-io-popen', 'rb-open3-',
  'cs-file-', 'cs-directory-', 'cs-file-ctor-', 'cs-processstartinfo',
];

// The SSRF and ReDoS sinks carry the same gate: a command-line tool that
// fetches the URL or compiles the pattern its operator passed is doing its job.
const OPERATOR_FED_CWES = new Set(['CWE-918', 'CWE-1333']);

// Reducing a request value to its last path component removes every directory
// separator, so `..` can no longer climb out of the base directory. Recorded,
// never trusted to kill taint: sanitizer-gate.js labels a path finding whose
// value went through one of these, and the proof gate demotes it.
const BASENAME = [
  { kind: 'sanitizer', id: 'rb-file-basename', language: 'rb', match: { type: 'call', callee: 'basename', receiver: '^File$' }, effect: 'strip', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'js-path-basename', language: 'js', match: { type: 'call', callee: 'basename', receiver: '^(?:path|posix|win32)$' }, effect: 'strip', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'py-os-path-basename', language: 'py', match: { type: 'call', callee: 'basename', receiver: '^(?:os\\.path|path|posixpath|ntpath)$' }, effect: 'strip', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'py-secure-filename', language: 'py', match: { type: 'call', callee: 'secure_filename' }, effect: 'strip', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'php-basename', language: 'php', match: { type: 'call', callee: 'basename' }, effect: 'strip', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'go-filepath-base', language: 'go', match: { type: 'call', callee: 'Base', receiver: '^(?:filepath|path)$' }, effect: 'strip', appliesTo: ['path'] },
];

export const FRAMEWORK_MODELS = [...JS, ...PY, ...JAVA, ...GO, ...PHP, ...RB, ...CS, ...XSS, ...BASENAME].map((e) => (
  e.kind === 'sink' && (OPERATOR_FED_PREFIXES.some((p) => e.id.startsWith(p)) || OPERATOR_FED_CWES.has(e.vuln && e.vuln.cwe))
    ? { ...e, match: { ...e.match, requireRequestSource: true } } : e
));
