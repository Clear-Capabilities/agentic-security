// Sources / sinks / sanitizers catalog.
//
// Each entry describes a callable or member-access pattern. The taint engine
// consults this catalog when it sees a call site or a property read.
//
// Shape:
//   { kind: 'source' | 'sink' | 'sanitizer',
//     id:    '<short-id>',
//     language: 'js' | 'java' | 'py' | '*',
//     framework: '<name>' | null,
//     match: { type: 'call', callee: 'name'           // match by callee name (last segment)
//                              | 'name.foo'           // match by full path 'name.foo'
//                              | '*' }                // any call
//             | { type: 'member', object, prop }      // match member read 'object.prop'
//             | { type: 'global', name },             // free-var reference, e.g. `process.env`
//     // For sources/sinks: which arguments matter?
//     argIndex: number | 'all' | null,
//     // For sinks: the vuln to emit when reached.
//     vuln: { name, severity, cwe, remediation } | null,
//     // For sanitizers: how the sanitizer behaves.
//     effect: 'strip' | 'taintNever' | 'taintIf-not-pinned',
//   }
//
// The catalog is intentionally narrow — it's a curated starter set. Adding
// entries here directly raises recall. Custom rules in .agentic-security/rules
// can extend it per-project.

export const CATALOG = [
  // ─── SOURCES (JS/TS) ───────────────────────────────────────────────────────
  // P4.6 — every source carries a `provenance` label so findings can be
  // severity-scaled by where the input actually came from.
  // Express / common Node HTTP shapes.
  { kind: 'source', id: 'js-req-body',     language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'body'    }, label: 'req.body',     provenance: 'http-body' },
  { kind: 'source', id: 'js-req-query',    language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'query'   }, label: 'req.query',    provenance: 'url-param' },
  { kind: 'source', id: 'js-req-params',   language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'params'  }, label: 'req.params',   provenance: 'path-param' },
  { kind: 'source', id: 'js-req-headers',  language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'headers' }, label: 'req.headers',  provenance: 'header' },
  { kind: 'source', id: 'js-req-cookies',  language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'cookies' }, label: 'req.cookies',  provenance: 'cookie' },
  { kind: 'source', id: 'js-request-body', language: 'js', framework: 'express', match: { type: 'member', object: 'request', prop: 'body'    }, label: 'request.body', provenance: 'http-body' },
  { kind: 'source', id: 'js-ctx-request',  language: 'js', framework: 'koa',     match: { type: 'member', object: 'ctx',     prop: 'request' }, label: 'ctx.request',  provenance: 'http-body' },
  // Browser DOM-derived (XSS sources).
  { kind: 'source', id: 'js-location',     language: 'js', framework: 'dom', match: { type: 'global', name: 'location' },                       label: 'window.location', provenance: 'url-fragment' },
  { kind: 'source', id: 'js-doc-cookie',   language: 'js', framework: 'dom', match: { type: 'member', object: 'document', prop: 'cookie' },     label: 'document.cookie', provenance: 'cookie' },
  { kind: 'source', id: 'js-loc-search',   language: 'js', framework: 'dom', match: { type: 'member', object: 'location', prop: 'search' },     label: 'location.search', provenance: 'url-param' },
  { kind: 'source', id: 'js-loc-hash',     language: 'js', framework: 'dom', match: { type: 'member', object: 'location', prop: 'hash'   },     label: 'location.hash',   provenance: 'url-fragment' },
  // process.env is a fixed but partially attacker-controllable surface for some apps.
  { kind: 'source', id: 'js-process-env',  language: 'js', framework: 'node', match: { type: 'member', object: 'process', prop: 'env' }, label: 'process.env', provenance: 'env' },

  // ─── SINKS (JS/TS) ─────────────────────────────────────────────────────────
  // SQL.
  { kind: 'sink', id: 'js-sql-query',  language: 'js', framework: 'sql', match: { type: 'call', callee: 'query'    }, argIndex: 0,
    vuln: { name: 'SQL Injection (db.query)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.query("SELECT * FROM t WHERE id = ?", [id]). Never interpolate untrusted strings into SQL.' } },
  { kind: 'sink', id: 'js-sql-execute', language: 'js', framework: 'sql', match: { type: 'call', callee: 'execute' }, argIndex: 0,
    vuln: { name: 'SQL Injection (db.execute)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.execute("SELECT * FROM t WHERE id = ?", [id]).' } },
  // OS command.
  { kind: 'sink', id: 'js-exec',     language: 'js', framework: 'node', match: { type: 'call', callee: 'exec'     }, argIndex: 0,
    vuln: { name: 'Command Injection (child_process.exec)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use execFile or spawn with an argv array instead of exec — exec invokes the shell. If shell features are required, escape with shell-escape, never string-concat user input.' } },
  { kind: 'sink', id: 'js-execSync', language: 'js', framework: 'node', match: { type: 'call', callee: 'execSync' }, argIndex: 0,
    vuln: { name: 'Command Injection (execSync)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use spawnSync with an argv array.' } },
  // Code evaluation.
  { kind: 'sink', id: 'js-eval', language: 'js', framework: 'node', match: { type: 'call', callee: 'eval' }, argIndex: 0,
    vuln: { name: 'Code Injection (eval)', severity: 'critical', cwe: 'CWE-95',
            remediation: 'Never eval user input. Use JSON.parse for structured data; for dispatch, use an explicit map.' } },
  { kind: 'sink', id: 'js-Function', language: 'js', framework: 'node', match: { type: 'call', callee: 'Function' }, argIndex: 'all',
    vuln: { name: 'Code Injection (Function constructor)', severity: 'critical', cwe: 'CWE-95',
            remediation: 'The Function constructor is equivalent to eval — never feed user input into it.' } },
  // XSS / DOM sinks (assignment-form, not match).
  // innerHTML and outerHTML are handled in the engine via assignment LHS matching.
  // DOM sinks.
  { kind: 'sink', id: 'js-document-write', language: 'js', framework: 'dom', match: { type: 'call', callee: 'write' }, argIndex: 0,
    vuln: { name: 'XSS (document.write)', severity: 'high', cwe: 'CWE-79',
            remediation: 'document.write is universally unsafe — use textContent or a typed templating engine.' } },
  // SSRF / HTTP-client sinks: matched by callee; rich-CWE classification in engine.
  { kind: 'sink', id: 'js-fetch',     language: 'js', framework: 'browser', match: { type: 'call', callee: 'fetch'   }, argIndex: 0,
    vuln: { name: 'SSRF (fetch)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the target host first and reject RFC1918 / metadata-endpoint addresses before fetching.' } },
  // File system sinks.
  { kind: 'sink', id: 'js-fs-readFile',  language: 'js', framework: 'node', match: { type: 'call', callee: 'readFile'  }, argIndex: 0,
    vuln: { name: 'Path Traversal (fs.readFile)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the path and assert it stays within an allow-listed base directory before reading.' } },
  { kind: 'sink', id: 'js-fs-writeFile', language: 'js', framework: 'node', match: { type: 'call', callee: 'writeFile' }, argIndex: 0,
    vuln: { name: 'Arbitrary File Write (fs.writeFile)', severity: 'critical', cwe: 'CWE-73',
            remediation: 'Never write to a path derived from untrusted input. Generate filenames server-side from content hashes.' } },
  // Redirects.
  { kind: 'sink', id: 'js-res-redirect', language: 'js', framework: 'express', match: { type: 'call', callee: 'redirect' }, argIndex: 0,
    vuln: { name: 'Open Redirect', severity: 'medium', cwe: 'CWE-601',
            remediation: 'Whitelist destination URLs; never pass req-derived strings straight into res.redirect.' } },

  // ─── SANITIZERS (JS/TS) ────────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'js-encodeURIComponent', language: 'js', match: { type: 'call', callee: 'encodeURIComponent' }, effect: 'strip', appliesTo: ['url'] },
  { kind: 'sanitizer', id: 'js-html-escape',        language: 'js', match: { type: 'call', callee: 'escapeHtml'         }, effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'js-dompurify',           language: 'js', match: { type: 'call', callee: 'sanitize'            }, effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'js-shell-escape',        language: 'js', match: { type: 'call', callee: 'shellEscape'         }, effect: 'strip', appliesTo: ['cmd'] },
  { kind: 'sanitizer', id: 'js-parseInt',            language: 'js', match: { type: 'call', callee: 'parseInt'            }, effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'js-Number',              language: 'js', match: { type: 'call', callee: 'Number'              }, effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'js-String-coerce',       language: 'js', match: { type: 'call', callee: 'String'              }, effect: 'strip', appliesTo: ['mongo-operator'] },
  { kind: 'sanitizer', id: 'js-validator-escape',    language: 'js', match: { type: 'call', callee: 'escape'              }, effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'js-strip_tags',          language: 'js', match: { type: 'call', callee: 'stripTags'            }, effect: 'strip', appliesTo: ['xss'] },
  // Schema-validation libraries (#7). Scoped to NoSQL/operator injection ONLY:
  // validating that input matches a typed shape defeats operator injection
  // (a `{$gt:''}` object can't satisfy `z.string()`). It does NOT sanitize the
  // value for XSS/SQL/cmd — a validated string is still a payload — so these
  // are deliberately NOT tagged for those families (doing so would cause false
  // negatives). Only distinctive callees, to avoid colliding with JSON.parse.
  { kind: 'sanitizer', id: 'js-zod-safeParse',     language: 'js', match: { type: 'call', callee: 'safeParse'         }, effect: 'strip', appliesTo: ['mongo-operator'] },
  { kind: 'sanitizer', id: 'js-zod-parseAsync',    language: 'js', match: { type: 'call', callee: 'parseAsync'        }, effect: 'strip', appliesTo: ['mongo-operator'] },
  { kind: 'sanitizer', id: 'js-class-validator',   language: 'js', match: { type: 'call', callee: 'validateOrReject'  }, effect: 'strip', appliesTo: ['mongo-operator'] },

  // ─── SOURCES (Python — Flask / FastAPI / Django) ──────────────────────────
  { kind: 'source', id: 'py-flask-request-args',   language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'args'    }, label: 'request.args' },
  { kind: 'source', id: 'py-flask-request-form',   language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'form'    }, label: 'request.form' },
  { kind: 'source', id: 'py-flask-request-json',   language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'json'    }, label: 'request.json' },
  { kind: 'source', id: 'py-flask-request-values', language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'values'  }, label: 'request.values' },
  { kind: 'source', id: 'py-flask-request-cookies',language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'cookies' }, label: 'request.cookies' },
  { kind: 'source', id: 'py-flask-request-headers',language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'headers' }, label: 'request.headers' },
  { kind: 'source', id: 'py-flask-request-data',   language: 'py', framework: 'flask',   match: { type: 'member', object: 'request', prop: 'data'    }, label: 'request.data' },
  { kind: 'source', id: 'py-fastapi-request-query',language: 'py', framework: 'fastapi', match: { type: 'call',   callee: 'Query'                  }, label: 'fastapi.Query()' },
  { kind: 'source', id: 'py-fastapi-request-body', language: 'py', framework: 'fastapi', match: { type: 'call',   callee: 'Body'                   }, label: 'fastapi.Body()' },
  { kind: 'source', id: 'py-fastapi-form',         language: 'py', framework: 'fastapi', match: { type: 'call',   callee: 'Form'                   }, label: 'fastapi.Form()' },
  { kind: 'source', id: 'py-django-request-GET',   language: 'py', framework: 'django',  match: { type: 'member', object: 'request', prop: 'GET'     }, label: 'request.GET' },
  { kind: 'source', id: 'py-django-request-POST',  language: 'py', framework: 'django',  match: { type: 'member', object: 'request', prop: 'POST'    }, label: 'request.POST' },
  { kind: 'source', id: 'py-django-request-FILES', language: 'py', framework: 'django',  match: { type: 'member', object: 'request', prop: 'FILES'   }, label: 'request.FILES' },
  { kind: 'source', id: 'py-django-request-META',  language: 'py', framework: 'django',  match: { type: 'member', object: 'request', prop: 'META'    }, label: 'request.META' },
  { kind: 'source', id: 'py-os-getenv',            language: 'py', framework: 'stdlib',  match: { type: 'call',   callee: 'getenv'                 }, label: 'os.getenv' },
  { kind: 'source', id: 'py-os-environ',           language: 'py', framework: 'stdlib',  match: { type: 'member', object: 'os', prop: 'environ'    }, label: 'os.environ' },
  { kind: 'source', id: 'py-input',                language: 'py', framework: 'stdlib',  match: { type: 'call',   callee: 'input'                  }, label: 'input()' },

  // ─── SOURCES (Java — Spring / Servlet) ────────────────────────────────────
  { kind: 'source', id: 'java-request-getParameter',   language: 'java', framework: 'servlet', match: { type: 'call', callee: 'getParameter' },   label: 'request.getParameter' },
  { kind: 'source', id: 'java-request-getHeader',      language: 'java', framework: 'servlet', match: { type: 'call', callee: 'getHeader' },      label: 'request.getHeader' },
  { kind: 'source', id: 'java-request-getCookies',     language: 'java', framework: 'servlet', match: { type: 'call', callee: 'getCookies' },     label: 'request.getCookies' },
  { kind: 'source', id: 'java-request-getInputStream', language: 'java', framework: 'servlet', match: { type: 'call', callee: 'getInputStream' }, label: 'request.getInputStream' },
  { kind: 'source', id: 'java-request-getReader',      language: 'java', framework: 'servlet', match: { type: 'call', callee: 'getReader' },      label: 'request.getReader' },
  { kind: 'source', id: 'java-system-getenv',          language: 'java', framework: 'stdlib',  match: { type: 'call', callee: 'getenv' },         label: 'System.getenv' },
  { kind: 'source', id: 'java-system-getProperty',     language: 'java', framework: 'stdlib',  match: { type: 'call', callee: 'getProperty' },    label: 'System.getProperty' },
  // Spring annotation-style sources are detected per-rule, not as catalog
  // members (they're parameter decorators rather than callable shapes).

  // ─── SOURCES (Go) ─────────────────────────────────────────────────────────
  { kind: 'source', id: 'go-r-form',     language: 'go', framework: 'net/http', match: { type: 'member', object: 'r', prop: 'Form' },     label: 'r.Form' },
  { kind: 'source', id: 'go-r-postform', language: 'go', framework: 'net/http', match: { type: 'member', object: 'r', prop: 'PostForm' }, label: 'r.PostForm' },
  { kind: 'source', id: 'go-r-body',     language: 'go', framework: 'net/http', match: { type: 'member', object: 'r', prop: 'Body' },     label: 'r.Body' },
  { kind: 'source', id: 'go-r-formvalue',language: 'go', framework: 'net/http', match: { type: 'call',   callee: 'FormValue' },           label: 'r.FormValue' },
  { kind: 'source', id: 'go-r-uquery',   language: 'go', framework: 'net/http', match: { type: 'call',   callee: 'Query' },               label: 'r.URL.Query' },
  { kind: 'source', id: 'go-gin-query',  language: 'go', framework: 'gin',      match: { type: 'call',   callee: 'Query' },               label: 'c.Query (gin)' },
  { kind: 'source', id: 'go-gin-bindjson',language:'go', framework: 'gin',      match: { type: 'call',   callee: 'BindJSON' },            label: 'c.BindJSON (gin)' },
  { kind: 'source', id: 'go-echo-param', language: 'go', framework: 'echo',     match: { type: 'call',   callee: 'Param' },               label: 'c.Param (echo)' },
  { kind: 'source', id: 'go-gin-postform',  language: 'go', framework: 'gin',  match: { type: 'call', callee: 'PostForm' },     label: 'c.PostForm (gin)' },
  { kind: 'source', id: 'go-gin-shouldbind',language: 'go', framework: 'gin',  match: { type: 'call', callee: 'ShouldBind' },   label: 'c.ShouldBind (gin)' },
  { kind: 'source', id: 'go-gin-shouldbindjson',language:'go',framework:'gin', match: { type: 'call', callee: 'ShouldBindJSON' },label: 'c.ShouldBindJSON (gin)' },
  { kind: 'source', id: 'go-echo-formvalue',language: 'go', framework: 'echo', match: { type: 'call', callee: 'FormValue' },    label: 'c.FormValue (echo)' },
  { kind: 'source', id: 'go-echo-queryparam',language:'go', framework: 'echo', match: { type: 'call', callee: 'QueryParam' },   label: 'c.QueryParam (echo)' },
  { kind: 'source', id: 'go-echo-bind',     language: 'go', framework: 'echo', match: { type: 'call', callee: 'Bind' },         label: 'c.Bind (echo)' },
  { kind: 'source', id: 'go-chi-urlparam',  language: 'go', framework: 'chi',  match: { type: 'call', callee: 'URLParam' },     label: 'chi.URLParam' },
  { kind: 'source', id: 'go-r-postformvalue',language:'go', framework:'net/http',match:{type:'call',callee:'PostFormValue'},     label: 'r.PostFormValue' },
  { kind: 'source', id: 'go-fiber-body',    language: 'go', framework: 'fiber', match: { type: 'call', callee: 'Body' },         label: 'c.Body (fiber)' },
  { kind: 'source', id: 'go-fiber-query',   language: 'go', framework: 'fiber', match: { type: 'call', callee: 'Query' },        label: 'c.Query (fiber)' },
  { kind: 'source', id: 'go-fiber-params',  language: 'go', framework: 'fiber', match: { type: 'call', callee: 'Params' },       label: 'c.Params (fiber)' },
  { kind: 'source', id: 'go-fiber-formvalue',language:'go', framework: 'fiber', match: { type: 'call', callee: 'FormValue' },    label: 'c.FormValue (fiber)' },
  { kind: 'source', id: 'go-fiber-cookies', language: 'go', framework: 'fiber', match: { type: 'call', callee: 'Cookies' },      label: 'c.Cookies (fiber)' },
  { kind: 'source', id: 'go-fiber-bodyparser',language:'go',framework:'fiber', match: { type: 'call', callee: 'BodyParser' },    label: 'c.BodyParser (fiber)' },
  { kind: 'source', id: 'go-buffalo-param', language: 'go', framework: 'buffalo',match: { type: 'call', callee: 'Param' },       label: 'c.Param (buffalo)' },
  { kind: 'source', id: 'go-buffalo-request',language:'go', framework:'buffalo',match: { type: 'member', object: 'c', prop: 'Request' }, label: 'c.Request (buffalo)' },
  { kind: 'source', id: 'go-gorilla-vars',  language: 'go', framework: 'gorilla',match: { type: 'call', callee: 'Vars' },        label: 'mux.Vars (gorilla)' },

  // ─── SINKS (Go — database/sql) — R3 (PRD §5) ──────────────────────────────
  // callee 'Query' is also a net/http SOURCE (r.URL.Query). The engine
  // disambiguates by position — source at the assignment RHS, sink at a call
  // with a tainted query argument — so coexistence is benign (a source call
  // like r.URL.Query() has no tainted arg, so it never fires the sink).
  { kind: 'sink', id: 'go-sql-query',    language: 'go', framework: 'database/sql', match: { type: 'call', callee: 'Query' },    argIndex: 0,
    vuln: { name: 'SQL Injection (db.Query — Go)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.Query("SELECT … WHERE id = $1", id). Never concatenate untrusted input into the SQL string.' } },
  { kind: 'sink', id: 'go-sql-queryrow', language: 'go', framework: 'database/sql', match: { type: 'call', callee: 'QueryRow' }, argIndex: 0,
    vuln: { name: 'SQL Injection (db.QueryRow — Go)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use placeholders ($1 / ?) and pass args separately.' } },
  { kind: 'sink', id: 'go-sql-exec',     language: 'go', framework: 'database/sql', match: { type: 'call', callee: 'Exec' },     argIndex: 0,
    vuln: { name: 'SQL Injection (db.Exec — Go)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized statements: db.Exec("UPDATE t SET x=$1 WHERE id=$2", x, id).' } },

  // ─── SOURCES (Ruby — Rails / Sinatra) ─────────────────────────────────────
  { kind: 'source', id: 'rb-rails-params',  language: 'rb', framework: 'rails', match: { type: 'global', name: 'params' }, label: 'params (Rails)' },
  { kind: 'source', id: 'rb-rails-cookies', language: 'rb', framework: 'rails', match: { type: 'global', name: 'cookies' }, label: 'cookies (Rails)' },
  { kind: 'source', id: 'rb-rails-session', language: 'rb', framework: 'rails', match: { type: 'global', name: 'session' }, label: 'session (Rails)' },
  { kind: 'source', id: 'rb-env',           language: 'rb', framework: 'stdlib',match: { type: 'global', name: 'ENV' },     label: 'ENV (Ruby)' },
  { kind: 'source', id: 'rb-sinatra-request-body',language:'rb',framework:'sinatra',match:{type:'member',object:'request',prop:'body'},    label: 'request.body (Sinatra)' },
  { kind: 'source', id: 'rb-sinatra-request-env', language:'rb',framework:'sinatra',match:{type:'member',object:'request',prop:'env'},     label: 'request.env (Sinatra)' },
  { kind: 'source', id: 'rb-sinatra-request-params',language:'rb',framework:'sinatra',match:{type:'member',object:'request',prop:'params'},label: 'request.params (Sinatra)' },

  // ─── SOURCES (PHP) ────────────────────────────────────────────────────────
  { kind: 'source', id: 'php-request',  language: 'php', framework: 'core', match: { type: 'global', name: '_REQUEST' }, label: '$_REQUEST' },
  { kind: 'source', id: 'php-get',      language: 'php', framework: 'core', match: { type: 'global', name: '_GET' },     label: '$_GET' },
  { kind: 'source', id: 'php-post',     language: 'php', framework: 'core', match: { type: 'global', name: '_POST' },    label: '$_POST' },
  { kind: 'source', id: 'php-cookie',   language: 'php', framework: 'core', match: { type: 'global', name: '_COOKIE' },  label: '$_COOKIE' },
  { kind: 'source', id: 'php-server',   language: 'php', framework: 'core', match: { type: 'global', name: '_SERVER' },  label: '$_SERVER' },
  { kind: 'source', id: 'php-symfony-query',   language: 'php', framework: 'symfony', match: { type: 'member', object: '$request', prop: 'query' },   label: '$request->query (Symfony)' },
  { kind: 'source', id: 'php-symfony-request', language: 'php', framework: 'symfony', match: { type: 'member', object: '$request', prop: 'request' }, label: '$request->request (Symfony)' },
  { kind: 'source', id: 'php-symfony-cookies', language: 'php', framework: 'symfony', match: { type: 'member', object: '$request', prop: 'cookies' }, label: '$request->cookies (Symfony)' },
  { kind: 'source', id: 'php-symfony-headers', language: 'php', framework: 'symfony', match: { type: 'member', object: '$request', prop: 'headers' }, label: '$request->headers (Symfony)' },
  { kind: 'source', id: 'php-symfony-files',   language: 'php', framework: 'symfony', match: { type: 'member', object: '$request', prop: 'files' },   label: '$request->files (Symfony)' },
  { kind: 'source', id: 'php-symfony-content', language: 'php', framework: 'symfony', match: { type: 'call', callee: 'getContent' },                  label: '$request->getContent() (Symfony)' },
  { kind: 'source', id: 'php-symfony-get',     language: 'php', framework: 'symfony', match: { type: 'call', callee: 'get' },                         label: '$request->get() (Symfony)' },

  // ─── SINKS (SQL — Python) ─────────────────────────────────────────────────
  { kind: 'sink', id: 'py-cursor-execute',     language: 'py', framework: 'dbapi',      match: { type: 'call', callee: 'execute' }, argIndex: 0,
    vuln: { name: 'SQL Injection (cursor.execute)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterised execute: `cur.execute("SELECT * FROM t WHERE id = %s", (id,))`.' } },
  { kind: 'sink', id: 'py-cursor-executemany', language: 'py', framework: 'dbapi',      match: { type: 'call', callee: 'executemany' }, argIndex: 0,
    vuln: { name: 'SQL Injection (cursor.executemany)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterised executemany with a list of tuples.' } },
  { kind: 'sink', id: 'py-sa-text',            language: 'py', framework: 'sqlalchemy', match: { type: 'call', callee: 'text' }, argIndex: 0,
    vuln: { name: 'SQL Injection (sqlalchemy.text)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use sqlalchemy.text with bound parameters: `text("SELECT :x").bindparams(x=v)`.' } },

  // ─── SINKS (SQL — Java) ───────────────────────────────────────────────────
  { kind: 'sink', id: 'java-stmt-executeQuery',  language: 'java', framework: 'jdbc',     match: { type: 'call', callee: 'executeQuery' },  argIndex: 0,
    vuln: { name: 'SQL Injection (Statement.executeQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use PreparedStatement + setX(N, value). Never concatenate user input into the SQL string.' } },
  { kind: 'sink', id: 'java-stmt-executeUpdate', language: 'java', framework: 'jdbc',     match: { type: 'call', callee: 'executeUpdate' }, argIndex: 0,
    vuln: { name: 'SQL Injection (Statement.executeUpdate)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use PreparedStatement + setX(N, value).' } },
  { kind: 'sink', id: 'java-stmt-execute',       language: 'java', framework: 'jdbc',     match: { type: 'call', callee: 'execute' },       argIndex: 0,
    vuln: { name: 'SQL Injection (Statement.execute)', severity: 'critical', cwe: 'CWE-89', remediation: 'Use PreparedStatement.' } },
  { kind: 'sink', id: 'java-jdbc-prepareStatement', language: 'java', framework: 'jdbc', match: { type: 'call', callee: 'prepareStatement' }, argIndex: 0,
    vuln: { name: 'SQL Injection (PreparedStatement built via concat)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use placeholders (?) in the SQL string; bind values via setX(N, value).' } },
  { kind: 'sink', id: 'java-stmt-addBatch',      language: 'java', framework: 'jdbc',     match: { type: 'call', callee: 'addBatch' },      argIndex: 0,
    vuln: { name: 'SQL Injection (Statement.addBatch)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use PreparedStatement.addBatch — bind parameters per-batch.' } },
  { kind: 'sink', id: 'java-hibernate-createQuery', language: 'java', framework: 'hibernate', match: { type: 'call', callee: 'createQuery' }, argIndex: 0,
    vuln: { name: 'HQL Injection (Hibernate.createQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use setParameter / named parameters instead of HQL string concat.' } },
  { kind: 'sink', id: 'java-hibernate-createSqlQuery', language: 'java', framework: 'hibernate', match: { type: 'call', callee: 'createSQLQuery' }, argIndex: 0,
    vuln: { name: 'Native SQL Injection (Hibernate.createSQLQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use setParameter on the resulting query.' } },
  { kind: 'sink', id: 'java-jpa-createNativeQuery', language: 'java', framework: 'jpa', match: { type: 'call', callee: 'createNativeQuery' }, argIndex: 0,
    vuln: { name: 'Native SQL Injection (EntityManager.createNativeQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use setParameter on the resulting Query.' } },

  // ─── SINKS (SQL — Go) ──────────────────────────────────────────────────────
  { kind: 'sink', id: 'go-db-query',    language: 'go', framework: 'database/sql', match: { type: 'call', callee: 'Query' },    argIndex: 0,
    vuln: { name: 'SQL Injection (db.Query)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.Query("SELECT * FROM t WHERE id = $1", id).' } },
  { kind: 'sink', id: 'go-db-queryrow', language: 'go', framework: 'database/sql', match: { type: 'call', callee: 'QueryRow' }, argIndex: 0,
    vuln: { name: 'SQL Injection (db.QueryRow)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.QueryRow("... WHERE id = $1", id).' } },
  { kind: 'sink', id: 'go-db-exec',     language: 'go', framework: 'database/sql', match: { type: 'call', callee: 'Exec' },     argIndex: 0,
    vuln: { name: 'SQL Injection (db.Exec)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries with placeholder args.' } },
  { kind: 'sink', id: 'go-gorm-raw',    language: 'go', framework: 'gorm',         match: { type: 'call', callee: 'Raw' },      argIndex: 0,
    vuln: { name: 'SQL Injection (gorm.Raw)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use gorm.Where with parameterized placeholders: db.Where("name = ?", name).' } },
  { kind: 'sink', id: 'go-gorm-exec',   language: 'go', framework: 'gorm',         match: { type: 'call', callee: 'Exec' },     argIndex: 0,
    vuln: { name: 'SQL Injection (gorm.Exec)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.Exec("UPDATE t SET x = ?", val).' } },
  { kind: 'sink', id: 'go-fmt-fprintf',  language: 'go', framework: 'fmt',          match: { type: 'call', callee: 'Fprintf' },  argIndex: 1,
    vuln: { name: 'XSS (fmt.Fprintf to ResponseWriter)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Use html/template for HTML output, not fmt.Fprintf with user input.' } },

  // ─── SINKS (SQL — PHP) ─────────────────────────────────────────────────────
  { kind: 'sink', id: 'php-mysqli-query',   language: 'php', framework: 'mysqli',  match: { type: 'call', callee: 'mysqli_query' },  argIndex: 1,
    vuln: { name: 'SQL Injection (mysqli_query)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use prepared statements: $stmt = $conn->prepare("SELECT * WHERE id = ?"); $stmt->bind_param("i", $id);' } },
  { kind: 'sink', id: 'php-pdo-query',     language: 'php', framework: 'pdo',     match: { type: 'call', callee: 'query' },         argIndex: 0,
    vuln: { name: 'SQL Injection (PDO::query)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use PDO::prepare with bound parameters.' } },
  { kind: 'sink', id: 'php-pdo-exec',      language: 'php', framework: 'pdo',     match: { type: 'call', callee: 'exec' },          argIndex: 0,
    vuln: { name: 'SQL Injection (PDO::exec)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use PDO::prepare with bound parameters.' } },
  { kind: 'sink', id: 'php-laravel-db-raw', language: 'php', framework: 'laravel', match: { type: 'call', callee: 'raw' },          argIndex: 0,
    vuln: { name: 'SQL Injection (DB::raw)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized bindings: DB::select("SELECT * WHERE id = ?", [$id]).' } },
  { kind: 'sink', id: 'php-exec',          language: 'php', framework: 'core',    match: { type: 'call', callee: 'exec' },          argIndex: 0,
    vuln: { name: 'Command Injection (exec)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use escapeshellarg() on each argument and avoid shell metacharacters.' } },
  { kind: 'sink', id: 'php-system',        language: 'php', framework: 'core',    match: { type: 'call', callee: 'system' },        argIndex: 0,
    vuln: { name: 'Command Injection (system)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Avoid system(); use proc_open with an argv array instead.' } },
  { kind: 'sink', id: 'php-shell-exec',    language: 'php', framework: 'core',    match: { type: 'call', callee: 'shell_exec' },    argIndex: 0,
    vuln: { name: 'Command Injection (shell_exec)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Avoid shell_exec(); sanitize with escapeshellarg() if unavoidable.' } },

  // ─── SINKS (SQL/CMD — Ruby) ───────────────────────────────────────────────
  { kind: 'sink', id: 'rb-ar-where-string', language: 'rb', framework: 'rails',   match: { type: 'call', callee: 'where' },         argIndex: 0,
    vuln: { name: 'SQL Injection (ActiveRecord where string)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use hash conditions: User.where(name: params[:name]).' } },
  { kind: 'sink', id: 'rb-ar-find-by-sql', language: 'rb', framework: 'rails',    match: { type: 'call', callee: 'find_by_sql' },   argIndex: 0,
    vuln: { name: 'SQL Injection (find_by_sql)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized SQL: find_by_sql(["SELECT * WHERE id = ?", id]).' } },
  { kind: 'sink', id: 'rb-system',         language: 'rb', framework: 'stdlib',   match: { type: 'call', callee: 'system' },        argIndex: 0,
    vuln: { name: 'Command Injection (Kernel.system)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use the array form: system("cmd", arg1, arg2).' } },
  { kind: 'sink', id: 'rb-exec',           language: 'rb', framework: 'stdlib',   match: { type: 'call', callee: 'exec' },          argIndex: 0,
    vuln: { name: 'Command Injection (Kernel.exec)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use the array form: exec("cmd", arg1, arg2).' } },
  { kind: 'sink', id: 'rb-sinatra-erb',    language: 'rb', framework: 'sinatra',  match: { type: 'call', callee: 'erb' },           argIndex: 0,
    vuln: { name: 'Server-Side Template Injection (Sinatra ERB)', severity: 'high', cwe: 'CWE-1336',
            remediation: 'Use ERB auto-escaping. Never pass user input as the template name.' } },

  // ─── SINKS (SQL — PHP / Symfony / Doctrine) ───────────────────────────────
  { kind: 'sink', id: 'php-symfony-createquery',language:'php',framework:'symfony',match:{type:'call',callee:'createQuery'},   argIndex: 0,
    vuln: { name: 'DQL Injection (Doctrine createQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use DQL parameters: $em->createQuery("... WHERE e.id = :id")->setParameter("id", $id).' } },
  { kind: 'sink', id: 'php-doctrine-nativequery',language:'php',framework:'doctrine',match:{type:'call',callee:'createNativeQuery'},argIndex:0,
    vuln: { name: 'SQL Injection (Doctrine createNativeQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use bound parameters with createNativeQuery.' } },

  // ─── SINKS (XSS / template — JS/TS / browser) ─────────────────────────────
  { kind: 'sink', id: 'js-innerHTML-assign', language: 'js', framework: 'dom', match: { type: 'member', object: '_any_', prop: 'innerHTML' }, argIndex: 'rhs',
    vuln: { name: 'DOM XSS (innerHTML)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Use textContent or a trusted-types sanitizer; never assign user-derived strings to innerHTML.' } },
  { kind: 'sink', id: 'js-outerHTML-assign', language: 'js', framework: 'dom', match: { type: 'member', object: '_any_', prop: 'outerHTML' }, argIndex: 'rhs',
    vuln: { name: 'DOM XSS (outerHTML)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Use textContent or a trusted-types sanitizer.' } },
  { kind: 'sink', id: 'js-insertAdjacentHTML', language: 'js', framework: 'dom', match: { type: 'call', callee: 'insertAdjacentHTML' }, argIndex: 1,
    vuln: { name: 'DOM XSS (insertAdjacentHTML)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Use insertAdjacentText, or sanitize the HTML with DOMPurify first.' } },
  { kind: 'sink', id: 'react-dangerouslySetInnerHTML', language: 'js', framework: 'react', match: { type: 'member', object: '_any_', prop: 'dangerouslySetInnerHTML' }, argIndex: 'rhs',
    vuln: { name: 'XSS via dangerouslySetInnerHTML', severity: 'high', cwe: 'CWE-79',
            remediation: 'Sanitize the __html field via DOMPurify before passing it to dangerouslySetInnerHTML — better, render text via children.' } },

  // ─── SINKS (HTTP outbound / SSRF) ─────────────────────────────────────────
  { kind: 'sink', id: 'py-requests-get',   language: 'py', framework: 'requests', match: { type: 'call', callee: 'get' },   argIndex: 0,
    vuln: { name: 'SSRF (requests.get)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the URL host and reject RFC1918 + metadata endpoints before fetching. Use an allow-list.' } },
  { kind: 'sink', id: 'py-requests-post',  language: 'py', framework: 'requests', match: { type: 'call', callee: 'post' },  argIndex: 0,
    vuln: { name: 'SSRF (requests.post)', severity: 'high', cwe: 'CWE-918', remediation: 'Validate the URL host before posting.' } },
  { kind: 'sink', id: 'py-urlopen',        language: 'py', framework: 'urllib',   match: { type: 'call', callee: 'urlopen' }, argIndex: 0,
    vuln: { name: 'SSRF (urllib.request.urlopen)', severity: 'high', cwe: 'CWE-918', remediation: 'Validate the URL host before opening.' } },
  { kind: 'sink', id: 'go-http-get',       language: 'go', framework: 'net/http', match: { type: 'call', callee: 'Get' },   argIndex: 0,
    vuln: { name: 'SSRF (http.Get)', severity: 'high', cwe: 'CWE-918', remediation: 'Validate the URL host before fetching; reject RFC1918 + metadata endpoints.' } },

  // ─── SINKS (command exec) ─────────────────────────────────────────────────
  { kind: 'sink', id: 'py-subprocess-run',      language: 'py', framework: 'subprocess', match: { type: 'call', callee: 'run' }, argIndex: 0,
    vuln: { name: 'Command Injection (subprocess.run shell=True)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Pass argv as a list; never pass a single string with shell=True.' } },
  { kind: 'sink', id: 'py-os-system',           language: 'py', framework: 'os',         match: { type: 'call', callee: 'system' }, argIndex: 0,
    vuln: { name: 'Command Injection (os.system)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'os.system invokes /bin/sh -c; use subprocess.run([...]) with an argv list.' } },
  { kind: 'sink', id: 'java-runtime-exec',      language: 'java', framework: 'stdlib',   match: { type: 'call', callee: 'exec' }, argIndex: 0,
    vuln: { name: 'Command Injection (Runtime.exec string-form)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use Runtime.exec(String[]) or ProcessBuilder(String[]).' } },
  { kind: 'sink', id: 'go-os-exec-command',     language: 'go', framework: 'os/exec',    match: { type: 'call', callee: 'Command' }, argIndex: 0,
    vuln: { name: 'Command Injection (exec.Command via /bin/sh -c)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'When the first arg is "/bin/sh" or "bash" with a -c string built from user input, the shell parses it. Pass argv array values directly to exec.Command.' } },

  // ─── SINKS (deserialization) ──────────────────────────────────────────────
  { kind: 'sink', id: 'py-pickle-loads',  language: 'py', framework: 'pickle', match: { type: 'call', callee: 'loads' },     argIndex: 0,
    vuln: { name: 'Insecure Deserialization (pickle.loads)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Never pickle-load attacker-controlled data. Use JSON / msgpack with an explicit schema.' } },
  { kind: 'sink', id: 'py-yaml-load',     language: 'py', framework: 'pyyaml', match: { type: 'call', callee: 'load' },      argIndex: 0,
    vuln: { name: 'Insecure Deserialization (yaml.load)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Use yaml.safe_load.' } },
  { kind: 'sink', id: 'java-ois-readObject', language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'readObject' }, argIndex: 'all',
    vuln: { name: 'Insecure Deserialization (ObjectInputStream.readObject)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Use a typed format (Jackson with explicit class allow-list, protobuf).' } },
  { kind: 'sink', id: 'rb-marshal-load',  language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'load' },      argIndex: 0,
    vuln: { name: 'Insecure Deserialization (Marshal.load)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Marshal is unsafe by design — use JSON.' } },
  { kind: 'sink', id: 'php-unserialize',  language: 'php', framework: 'stdlib', match: { type: 'call', callee: 'unserialize' }, argIndex: 0,
    vuln: { name: 'Insecure Deserialization (unserialize)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Use json_decode instead — unserialize triggers __destruct on gadget classes.' } },

  // ─── SINKS (template / SSTI) ──────────────────────────────────────────────
  { kind: 'sink', id: 'py-jinja-from-string', language: 'py', framework: 'jinja2', match: { type: 'call', callee: 'from_string' }, argIndex: 0,
    vuln: { name: 'SSTI (Jinja2.from_string)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never feed a user-supplied string into a template engine. Use pre-registered templates and pass values as variables.' } },
  { kind: 'sink', id: 'rb-erb-new',           language: 'rb', framework: 'erb',    match: { type: 'call', callee: 'new' }, argIndex: 0,
    vuln: { name: 'SSTI (ERB.new)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Use pre-existing templates with binding/locals — never construct a template from user input.' } },
  { kind: 'sink', id: 'js-handlebars-compile',language: 'js', framework: 'handlebars', match: { type: 'call', callee: 'compile' }, argIndex: 0,
    vuln: { name: 'SSTI (Handlebars.compile)', severity: 'high', cwe: 'CWE-94', remediation: 'Compile only known templates; never compile a user-supplied string.' } },

  // ─── SINKS (file paths / traversal) ───────────────────────────────────────
  { kind: 'sink', id: 'py-open',          language: 'py', framework: 'stdlib', match: { type: 'call', callee: 'open' }, argIndex: 0,
    vuln: { name: 'Path Traversal (open)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the path with os.path.realpath + verify it stays within an allow-list of base directories.' } },
  { kind: 'sink', id: 'java-new-File',    language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'File' }, argIndex: 0,
    vuln: { name: 'Path Traversal (new File)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize with Path.normalize + startsWith(base).' } },
  { kind: 'sink', id: 'go-os-open',       language: 'go', framework: 'os',      match: { type: 'call', callee: 'Open' }, argIndex: 0,
    vuln: { name: 'Path Traversal (os.Open)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Use filepath.Clean + verify the path is rooted in your allow-list dir.' } },

  // ─── SINKS (LDAP / XPath) ─────────────────────────────────────────────────
  { kind: 'sink', id: 'java-ldap-search', language: 'java', framework: 'jndi',  match: { type: 'call', callee: 'search' }, argIndex: 1,
    vuln: { name: 'LDAP Injection (DirContext.search)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters with Rdn.escapeValue or use a parameterised filter.' } },
  { kind: 'sink', id: 'java-xpath-compile', language: 'java', framework: 'xpath', match: { type: 'call', callee: 'compile' }, argIndex: 0,
    vuln: { name: 'XPath Injection (XPath.compile)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Use XPathVariableResolver or setXPathVariableResolver; never concat user input into the expression.' } },

  // ─── SINKS (regex DoS / ReDoS) ────────────────────────────────────────────
  { kind: 'sink', id: 'js-RegExp-new', language: 'js', framework: 'core', match: { type: 'call', callee: 'RegExp' }, argIndex: 0,
    vuln: { name: 'ReDoS via user-controlled RegExp', severity: 'medium', cwe: 'CWE-1333',
            remediation: 'Treat user-supplied patterns as untrusted: limit length, reject nested quantifiers, time-bound the match with a watchdog. Better: don\'t accept regex from users at all.' } },

  // ─── SINKS (redirect) ─────────────────────────────────────────────────────
  { kind: 'sink', id: 'py-redirect',   language: 'py', framework: 'flask',  match: { type: 'call', callee: 'redirect' }, argIndex: 0,
    vuln: { name: 'Open Redirect (flask.redirect)', severity: 'medium', cwe: 'CWE-601',
            remediation: 'Validate the target URL against an allow-list of internal paths.' } },
  { kind: 'sink', id: 'java-sendRedirect', language: 'java', framework: 'servlet', match: { type: 'call', callee: 'sendRedirect' }, argIndex: 0,
    vuln: { name: 'Open Redirect (response.sendRedirect)', severity: 'medium', cwe: 'CWE-601',
            remediation: 'Validate the target URL against an allow-list.' } },

  // ─── SINKS (XXE) ──────────────────────────────────────────────────────────
  { kind: 'sink', id: 'java-DocumentBuilder-parse', language: 'java', framework: 'jaxp', match: { type: 'call', callee: 'parse' }, argIndex: 'all',
    vuln: { name: 'XXE (DocumentBuilder.parse)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Disable DTDs: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).' } },
  { kind: 'sink', id: 'py-etree-parse', language: 'py', framework: 'lxml', match: { type: 'call', callee: 'parse' }, argIndex: 0,
    vuln: { name: 'XXE (lxml.etree.parse)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Use defusedxml.ElementTree or pass resolve_entities=False.' } },

  // ─── SINKS (NoSQL) ────────────────────────────────────────────────────────
  { kind: 'sink', id: 'js-mongo-where', language: 'js', framework: 'mongo', match: { type: 'call', callee: '$where' }, argIndex: 0,
    vuln: { name: 'NoSQL Injection ($where)', severity: 'critical', cwe: 'CWE-943',
            remediation: 'Never build a $where string from user input — it runs server-side JavaScript.' } },

  // ─── SANITIZERS (Python) ──────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'py-bleach-clean',     language: 'py', match: { type: 'call', callee: 'clean' },     effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'py-html-escape',      language: 'py', match: { type: 'call', callee: 'escape' },    effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'py-markupsafe-escape',language: 'py', match: { type: 'call', callee: 'Markup' },    effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'py-shlex-quote',      language: 'py', match: { type: 'call', callee: 'quote' },     effect: 'strip', appliesTo: ['cmd'] },
  { kind: 'sanitizer', id: 'py-int',              language: 'py', match: { type: 'call', callee: 'int' },       effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'py-float',            language: 'py', match: { type: 'call', callee: 'float' },     effect: 'strip', appliesTo: ['*'] },

  // ─── SANITIZERS (Java) ────────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'java-esapi-encoder-htmlEncode',  language: 'java', match: { type: 'call', callee: 'encodeForHTML' },        effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'java-esapi-encoder-sqlEncode',   language: 'java', match: { type: 'call', callee: 'encodeForSQL' },         effect: 'strip', appliesTo: ['sql'] },
  { kind: 'sanitizer', id: 'java-esapi-encoder-ldapEncode',  language: 'java', match: { type: 'call', callee: 'encodeForLDAP' },        effect: 'strip', appliesTo: ['ldap'] },
  { kind: 'sanitizer', id: 'java-esapi-encoder-xpathEncode', language: 'java', match: { type: 'call', callee: 'encodeForXPath' },       effect: 'strip', appliesTo: ['xpath'] },
  { kind: 'sanitizer', id: 'java-stringutils-escapeHtml',    language: 'java', match: { type: 'call', callee: 'escapeHtml4' },          effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'java-stringutils-escapeXml',     language: 'java', match: { type: 'call', callee: 'escapeXml' },            effect: 'strip', appliesTo: ['xml','xss'] },
  { kind: 'sanitizer', id: 'java-html-utils',                language: 'java', match: { type: 'call', callee: 'htmlEscape' },           effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'java-integer-parseInt',          language: 'java', match: { type: 'call', callee: 'parseInt' },             effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'java-long-parseLong',            language: 'java', match: { type: 'call', callee: 'parseLong' },            effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'java-uuid-fromString',           language: 'java', match: { type: 'call', callee: 'fromString' },           effect: 'strip', appliesTo: ['*'] },

  // ─── SANITIZERS (PHP) ─────────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'php-htmlspecialchars', language: 'php', match: { type: 'call', callee: 'htmlspecialchars' }, effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'php-htmlentities',     language: 'php', match: { type: 'call', callee: 'htmlentities' },     effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'php-escapeshellarg',   language: 'php', match: { type: 'call', callee: 'escapeshellarg' },   effect: 'strip', appliesTo: ['cmd'] },
  { kind: 'sanitizer', id: 'php-escapeshellcmd',   language: 'php', match: { type: 'call', callee: 'escapeshellcmd' },   effect: 'strip', appliesTo: ['cmd'] },
  { kind: 'sanitizer', id: 'php-intval',           language: 'php', match: { type: 'call', callee: 'intval' },           effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'php-filter-var',       language: 'php', match: { type: 'call', callee: 'filter_var' },       effect: 'strip', appliesTo: ['*'] },

  // ─── SANITIZERS (Ruby) ────────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'rb-rails-html-escape', language: 'rb', match: { type: 'call', callee: 'h' },          effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'rb-erb-util-html',     language: 'rb', match: { type: 'call', callee: 'html_escape' },effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'rb-shellwords-escape', language: 'rb', match: { type: 'call', callee: 'shellescape' },effect: 'strip', appliesTo: ['cmd'] },
  { kind: 'sanitizer', id: 'rb-cgi-escape',        language: 'rb', match: { type: 'call', callee: 'escape' },     effect: 'strip', appliesTo: ['xss','url'] },

  // ─── SANITIZERS (Go) ──────────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'go-html-escape',  language: 'go', match: { type: 'call', callee: 'EscapeString' }, effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'go-strconv-atoi', language: 'go', match: { type: 'call', callee: 'Atoi' },         effect: 'strip', appliesTo: ['*'] },

  // ─── SOURCES (Python) ──────────────────────────────────────────────────────
  // Flask request object — request is module-imported, properties are sources.
  { kind: 'source', id: 'py-flask-form',     language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'form'   }, label: 'flask.request.form',   provenance: 'http-body' },
  { kind: 'source', id: 'py-flask-args',     language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'args'   }, label: 'flask.request.args',   provenance: 'url-param' },
  { kind: 'source', id: 'py-flask-json',     language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'json'   }, label: 'flask.request.json',   provenance: 'http-body' },
  { kind: 'source', id: 'py-flask-values',   language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'values' }, label: 'flask.request.values', provenance: 'http-body' },
  { kind: 'source', id: 'py-flask-cookies',  language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'cookies'}, label: 'flask.request.cookies',provenance: 'cookie' },
  { kind: 'source', id: 'py-flask-headers',  language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'headers'}, label: 'flask.request.headers',provenance: 'header' },
  { kind: 'source', id: 'py-flask-data',     language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'data'   }, label: 'flask.request.data',   provenance: 'http-body' },
  { kind: 'source', id: 'py-flask-files',    language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'files'  }, label: 'flask.request.files',  provenance: 'http-body' },
  { kind: 'source', id: 'py-flask-stream',   language: 'py', framework: 'flask', match: { type: 'member', object: 'request', prop: 'stream' }, label: 'flask.request.stream', provenance: 'http-body' },
  // Django request object.
  { kind: 'source', id: 'py-django-post',    language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'POST'    }, label: 'django.request.POST',    provenance: 'http-body' },
  { kind: 'source', id: 'py-django-get',     language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'GET'     }, label: 'django.request.GET',     provenance: 'url-param' },
  { kind: 'source', id: 'py-django-body',    language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'body'    }, label: 'django.request.body',    provenance: 'http-body' },
  { kind: 'source', id: 'py-django-meta',    language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'META'    }, label: 'django.request.META',    provenance: 'header' },
  { kind: 'source', id: 'py-django-files',   language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'FILES'   }, label: 'django.request.FILES',   provenance: 'http-body' },
  { kind: 'source', id: 'py-django-headers', language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'headers' }, label: 'django.request.headers', provenance: 'header' },
  { kind: 'source', id: 'py-django-cookies', language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'COOKIES' }, label: 'django.request.COOKIES', provenance: 'cookie' },
  // FastAPI / Starlette — Request object.
  { kind: 'source', id: 'py-fastapi-query',     language: 'py', framework: 'fastapi', match: { type: 'member', object: 'request', prop: 'query_params'  }, label: 'fastapi.request.query_params',  provenance: 'url-param' },
  { kind: 'source', id: 'py-fastapi-path',      language: 'py', framework: 'fastapi', match: { type: 'member', object: 'request', prop: 'path_params'   }, label: 'fastapi.request.path_params',   provenance: 'path-param' },
  { kind: 'source', id: 'py-fastapi-headers',   language: 'py', framework: 'fastapi', match: { type: 'member', object: 'request', prop: 'headers'       }, label: 'fastapi.request.headers',       provenance: 'header' },
  { kind: 'source', id: 'py-fastapi-cookies',   language: 'py', framework: 'fastapi', match: { type: 'member', object: 'request', prop: 'cookies'       }, label: 'fastapi.request.cookies',       provenance: 'cookie' },
  // Tornado RequestHandler.
  { kind: 'source', id: 'py-tornado-get-arg',   language: 'py', framework: 'tornado', match: { type: 'call', callee: 'get_argument'      }, argIndex: 0, label: 'tornado.get_argument', provenance: 'http-body' },
  { kind: 'source', id: 'py-tornado-get-args',  language: 'py', framework: 'tornado', match: { type: 'call', callee: 'get_arguments'     }, argIndex: 0, label: 'tornado.get_arguments', provenance: 'http-body' },
  { kind: 'source', id: 'py-tornado-get-body',  language: 'py', framework: 'tornado', match: { type: 'call', callee: 'get_body_argument' }, argIndex: 0, label: 'tornado.get_body_argument', provenance: 'http-body' },
  // Starlette / Litestar — async ASGI sources.
  { kind: 'source', id: 'py-starlette-json',   language: 'py', framework: 'starlette', match: { type: 'call', callee: 'json' },         label: 'request.json() (Starlette)', provenance: 'http-body' },
  { kind: 'source', id: 'py-starlette-form',   language: 'py', framework: 'starlette', match: { type: 'call', callee: 'form' },         label: 'request.form() (Starlette)', provenance: 'http-body' },
  { kind: 'source', id: 'py-starlette-body',   language: 'py', framework: 'starlette', match: { type: 'call', callee: 'body' },         label: 'request.body() (Starlette)', provenance: 'http-body' },
  { kind: 'source', id: 'py-starlette-qparams',language: 'py', framework: 'starlette', match: { type: 'member', object: 'request', prop: 'query_params' }, label: 'request.query_params (Starlette)', provenance: 'url-param' },
  { kind: 'source', id: 'py-starlette-path',   language: 'py', framework: 'starlette', match: { type: 'member', object: 'request', prop: 'path_params' },  label: 'request.path_params (Starlette)', provenance: 'path-param' },
  { kind: 'source', id: 'py-litestar-data',    language: 'py', framework: 'litestar',  match: { type: 'call', callee: 'data' },         label: 'request.data() (Litestar)', provenance: 'http-body' },
  // Sanic — async Python web.
  { kind: 'source', id: 'py-sanic-args',       language: 'py', framework: 'sanic',     match: { type: 'member', object: 'request', prop: 'args' },  label: 'request.args (Sanic)', provenance: 'url-param' },
  { kind: 'source', id: 'py-sanic-form',       language: 'py', framework: 'sanic',     match: { type: 'member', object: 'request', prop: 'form' },  label: 'request.form (Sanic)', provenance: 'http-body' },
  { kind: 'source', id: 'py-sanic-json',       language: 'py', framework: 'sanic',     match: { type: 'member', object: 'request', prop: 'json' },  label: 'request.json (Sanic)', provenance: 'http-body' },
  { kind: 'source', id: 'py-sanic-body',       language: 'py', framework: 'sanic',     match: { type: 'member', object: 'request', prop: 'body' },  label: 'request.body (Sanic)', provenance: 'http-body' },
  // sys.argv — CLI input source. (os.environ already declared above.)
  { kind: 'source', id: 'py-sys-argv',      language: 'py', framework: 'std', match: { type: 'member', object: 'sys', prop: 'argv'   }, label: 'sys.argv', provenance: 'cli' },
  // File reads.
  { kind: 'source', id: 'py-open-read',     language: 'py', framework: 'std', match: { type: 'call', callee: 'open' }, argIndex: 0, label: 'open()', provenance: 'file-read' },
  // input() already declared above as a stdlib source (line ~120).

  // ─── SINKS (Python) ────────────────────────────────────────────────────────
  // SQL.
  { kind: 'sink', id: 'py-cursor-execute-v2', language: 'py', framework: 'db', match: { type: 'call', callee: 'execute' },     argIndex: 0,
    vuln: { name: 'SQL Injection (cursor.execute)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: cursor.execute("SELECT * FROM t WHERE id = %s", (id,)). Never %-format or f-string the SQL with untrusted input.' } },
  { kind: 'sink', id: 'py-cursor-executemany-v2', language: 'py', framework: 'db', match: { type: 'call', callee: 'executemany' }, argIndex: 0,
    vuln: { name: 'SQL Injection (executemany)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries with executemany; never concatenate user input.' } },
  { kind: 'sink', id: 'py-sqlalchemy-text', language: 'py', framework: 'sqlalchemy', match: { type: 'call', callee: 'text' }, argIndex: 0,
    vuln: { name: 'SQL Injection (sqlalchemy.text)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'sqlalchemy.text() does not parameterize. Use bindparam() or Core expressions for any untrusted input.' } },
  { kind: 'sink', id: 'py-django-raw', language: 'py', framework: 'django', match: { type: 'call', callee: 'raw' }, argIndex: 0,
    vuln: { name: 'SQL Injection (Model.objects.raw)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use Django ORM Q-objects or parameterized raw(): Model.objects.raw("SELECT ... %s", [val]).' } },
  // Command execution.
  { kind: 'sink', id: 'py-os-system-v2',     language: 'py', framework: 'std', match: { type: 'call', callee: 'system'     }, argIndex: 0,
    vuln: { name: 'Command Injection (os.system)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Replace os.system with subprocess.run([...]) using an argv array; never feed untrusted strings to a shell.' } },
  { kind: 'sink', id: 'py-os-popen',      language: 'py', framework: 'std', match: { type: 'call', callee: 'popen'      }, argIndex: 0,
    vuln: { name: 'Command Injection (os.popen)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'os.popen is a shell wrapper; use subprocess.run with argv array.' } },
  { kind: 'sink', id: 'py-subprocess-call', language: 'py', framework: 'std', match: { type: 'call', callee: 'call'      }, argIndex: 0,
    vuln: { name: 'Command Injection (subprocess.call)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Pass argv as a list and ensure shell=False (the default). If shell=True is required, escape with shlex.quote.' } },
  { kind: 'sink', id: 'py-subprocess-run-v2', language: 'py', framework: 'std', match: { type: 'call', callee: 'run'       }, argIndex: 0,
    vuln: { name: 'Command Injection (subprocess.run with shell=True)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Pass argv as a list and ensure shell=False.' } },
  { kind: 'sink', id: 'py-subprocess-Popen', language: 'py', framework: 'std', match: { type: 'call', callee: 'Popen'   }, argIndex: 0,
    vuln: { name: 'Command Injection (subprocess.Popen)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Pass argv as a list and shell=False.' } },
  { kind: 'sink', id: 'py-commands-getoutput', language: 'py', framework: 'std', match: { type: 'call', callee: 'getoutput' }, argIndex: 0,
    vuln: { name: 'Command Injection (commands.getoutput)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'commands module is deprecated and shell-based; switch to subprocess with argv.' } },
  // Code evaluation.
  { kind: 'sink', id: 'py-eval', language: 'py', framework: 'std', match: { type: 'call', callee: 'eval' }, argIndex: 0,
    vuln: { name: 'Code Injection (eval)', severity: 'critical', cwe: 'CWE-95',
            remediation: 'Never eval user input. Use ast.literal_eval for trusted literal forms; reject otherwise.' } },
  { kind: 'sink', id: 'py-exec', language: 'py', framework: 'std', match: { type: 'call', callee: 'exec' }, argIndex: 0,
    vuln: { name: 'Code Injection (exec)', severity: 'critical', cwe: 'CWE-95',
            remediation: 'Never exec user-controlled code.' } },
  { kind: 'sink', id: 'py-compile', language: 'py', framework: 'std', match: { type: 'call', callee: 'compile' }, argIndex: 0,
    vuln: { name: 'Code Injection (compile)', severity: 'high', cwe: 'CWE-95',
            remediation: 'compile() followed by exec is equivalent to eval. Avoid on untrusted input.' } },
  // Deserialization.
  { kind: 'sink', id: 'py-pickle-loads-v2', language: 'py', framework: 'std', match: { type: 'call', callee: 'loads' }, argIndex: 0,
    vuln: { name: 'Unsafe Deserialization (pickle.loads)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'pickle.loads on untrusted data is RCE. Use JSON / msgpack with explicit schema.' } },
  { kind: 'sink', id: 'py-pickle-load', language: 'py', framework: 'std', match: { type: 'call', callee: 'load' }, argIndex: 0,
    vuln: { name: 'Unsafe Deserialization (pickle.load)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'pickle.load on untrusted streams is RCE.' } },
  { kind: 'sink', id: 'py-yaml-load-v2', language: 'py', framework: 'yaml', match: { type: 'call', callee: 'load' }, argIndex: 0,
    vuln: { name: 'Unsafe Deserialization (yaml.load)', severity: 'high', cwe: 'CWE-502',
            remediation: 'Use yaml.safe_load instead of yaml.load on untrusted YAML.' } },
  // SSRF / HTTP-out.
  { kind: 'sink', id: 'py-requests-get-v2',  language: 'py', framework: 'requests', match: { type: 'call', callee: 'get'  }, argIndex: 0,
    vuln: { name: 'SSRF (requests.get)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the host first, reject 169.254.169.254 / RFC1918 / localhost; or proxy through a server-side allow-list.' } },
  { kind: 'sink', id: 'py-requests-post-v2', language: 'py', framework: 'requests', match: { type: 'call', callee: 'post' }, argIndex: 0,
    vuln: { name: 'SSRF (requests.post)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the host first and reject metadata-endpoint addresses.' } },
  { kind: 'sink', id: 'py-urllib-urlopen', language: 'py', framework: 'std', match: { type: 'call', callee: 'urlopen' }, argIndex: 0,
    vuln: { name: 'SSRF (urllib.urlopen)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve and validate the URL host before opening.' } },
  // File system sinks.
  { kind: 'sink', id: 'py-send-file', language: 'py', framework: 'flask', match: { type: 'call', callee: 'send_file' }, argIndex: 0,
    vuln: { name: 'Path Traversal (send_file)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Use flask.send_from_directory with a strict base dir, or canonicalize the path and assert it stays within the allowed root.' } },
  { kind: 'sink', id: 'py-send-from-directory', language: 'py', framework: 'flask', match: { type: 'call', callee: 'send_from_directory' }, argIndex: 1,
    vuln: { name: 'Path Traversal (send_from_directory)', severity: 'medium', cwe: 'CWE-22',
            remediation: 'send_from_directory protects against trivial traversal but verify the filename argument has no ".." or absolute prefix.' } },
  // Template injection.
  { kind: 'sink', id: 'py-jinja2-from-string', language: 'py', framework: 'jinja2', match: { type: 'call', callee: 'from_string' }, argIndex: 0,
    vuln: { name: 'Server-Side Template Injection (jinja2.Environment.from_string)', severity: 'critical', cwe: 'CWE-1336',
            remediation: 'Never compile a template from user input. If user-supplied substitution is required, use a strict allow-listed sandboxed environment.' } },
  // Crypto / hash sinks (weak hash + plaintext compare are covered elsewhere).
  // XML — XXE.
  { kind: 'sink', id: 'py-etree-fromstring', language: 'py', framework: 'xml', match: { type: 'call', callee: 'fromstring' }, argIndex: 0,
    vuln: { name: 'XXE (xml.etree.fromstring)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Use defusedxml.ElementTree.fromstring instead.' } },
  // Redirects.
  { kind: 'sink', id: 'py-flask-redirect', language: 'py', framework: 'flask', match: { type: 'call', callee: 'redirect' }, argIndex: 0,
    vuln: { name: 'Open Redirect (flask.redirect)', severity: 'medium', cwe: 'CWE-601',
            remediation: 'Validate redirect target against an allow-list; never pass req-derived strings straight to redirect.' } },

  // ─── SANITIZERS (Python) ───────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'py-shlex-quote-v2',         language: 'py', match: { type: 'call', callee: 'quote' },          effect: 'strip', appliesTo: ['cmd'] },
  { kind: 'sanitizer', id: 'py-html-escape-v2',         language: 'py', match: { type: 'call', callee: 'escape' },         effect: 'strip', appliesTo: ['xss','url'] },
  { kind: 'sanitizer', id: 'py-markupsafe-escape-v2',   language: 'py', match: { type: 'call', callee: 'Markup' },         effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'py-bleach-clean-v2',        language: 'py', match: { type: 'call', callee: 'clean' },          effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'py-urllib-quote',        language: 'py', match: { type: 'call', callee: 'quote_plus' },     effect: 'strip', appliesTo: ['url'] },
  { kind: 'sanitizer', id: 'py-int-v2',                 language: 'py', match: { type: 'call', callee: 'int' },            effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'py-float-v2',               language: 'py', match: { type: 'call', callee: 'float' },          effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'py-ast-literal-eval',    language: 'py', match: { type: 'call', callee: 'literal_eval' },   effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'py-yaml-safe-load',      language: 'py', match: { type: 'call', callee: 'safe_load' },      effect: 'strip', appliesTo: ['deserial'] },
  { kind: 'sanitizer', id: 'py-pathlib-resolve',     language: 'py', match: { type: 'call', callee: 'resolve' },        effect: 'taintIf-not-pinned', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'py-defusedxml',          language: 'py', match: { type: 'call', callee: 'fromstring' },     effect: 'strip', appliesTo: ['xxe'] },     // when called from defusedxml namespace

  // ─── SOURCES (C# — ASP.NET MVC / Core) ───────────────────────────────────
  { kind: 'source', id: 'cs-request-form',     language: 'cs', framework: 'aspnet', match: { type: 'member', object: 'Request', prop: 'Form' },        label: 'Request.Form',        provenance: 'http-body' },
  { kind: 'source', id: 'cs-request-query',    language: 'cs', framework: 'aspnet', match: { type: 'member', object: 'Request', prop: 'QueryString' }, label: 'Request.QueryString', provenance: 'url-param' },
  { kind: 'source', id: 'cs-request-cookies',  language: 'cs', framework: 'aspnet', match: { type: 'member', object: 'Request', prop: 'Cookies' },     label: 'Request.Cookies',     provenance: 'cookie' },
  { kind: 'source', id: 'cs-request-headers',  language: 'cs', framework: 'aspnet', match: { type: 'member', object: 'Request', prop: 'Headers' },     label: 'Request.Headers',     provenance: 'header' },
  { kind: 'source', id: 'cs-request-params',   language: 'cs', framework: 'aspnet', match: { type: 'member', object: 'Request', prop: 'Params' },      label: 'Request.Params' },
  { kind: 'source', id: 'cs-request-body',     language: 'cs', framework: 'aspnet-core', match: { type: 'member', object: 'Request', prop: 'Body' },   label: 'Request.Body',        provenance: 'http-body' },
  { kind: 'source', id: 'cs-env-var',          language: 'cs', framework: 'stdlib', match: { type: 'call',   callee: 'GetEnvironmentVariable' },       label: 'Environment.GetEnvironmentVariable', provenance: 'env' },

  // ─── SINKS (C#) ──────────────────────────────────────────────────────────
  { kind: 'sink', id: 'cs-sqlcommand',         language: 'cs', framework: 'ado',    match: { type: 'call', callee: 'SqlCommand' },     argIndex: 0,
    vuln: { name: 'SQL Injection (new SqlCommand with concatenated user input)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized SqlCommand: `new SqlCommand("SELECT * FROM u WHERE id=@id"); cmd.Parameters.AddWithValue("@id", id);`' } },
  { kind: 'sink', id: 'cs-executequery',       language: 'cs', framework: 'ado',    match: { type: 'call', callee: 'ExecuteQuery' },   argIndex: 0,
    vuln: { name: 'SQL Injection (DataContext.ExecuteQuery string-form)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized form or LINQ Where clauses.' } },
  { kind: 'sink', id: 'cs-dapper-query',       language: 'cs', framework: 'dapper', match: { type: 'call', callee: 'Query' },          argIndex: 0,
    vuln: { name: 'SQL Injection (Dapper Query with string concat)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Pass parameters as the 2nd arg: `Query<T>("SELECT … WHERE id=@id", new { id })`.' } },
  { kind: 'sink', id: 'cs-process-start',      language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'Start' },          argIndex: 0,
    vuln: { name: 'Command Injection (Process.Start string-form)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use ProcessStartInfo with separated FileName + Arguments; never pass /c with concat.' } },
  { kind: 'sink', id: 'cs-file-readall',       language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'ReadAllText' },    argIndex: 0,
    vuln: { name: 'Path Traversal (File.ReadAllText with user input)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the path with Path.GetFullPath and verify it starts with an allow-listed base directory.' } },
  { kind: 'sink', id: 'cs-file-writeall',      language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'WriteAllText' },   argIndex: 0,
    vuln: { name: 'Path Traversal (File.WriteAllText with user input)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the path and verify it stays within the allowed base.' } },
  { kind: 'sink', id: 'cs-webclient',          language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'DownloadString' }, argIndex: 0,
    vuln: { name: 'SSRF (WebClient.DownloadString)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the URL host against an allow-list before fetching.' } },
  { kind: 'sink', id: 'cs-httpclient-getstr',  language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'GetStringAsync' }, argIndex: 0,
    vuln: { name: 'SSRF (HttpClient.GetStringAsync)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the URL before fetching.' } },
  { kind: 'sink', id: 'cs-binformatter',       language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'Deserialize' },    argIndex: 0,
    vuln: { name: 'Insecure Deserialization (BinaryFormatter.Deserialize)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'BinaryFormatter is deprecated and unsafe. Use System.Text.Json with explicit type constraints.' } },

  // ─── SANITIZERS (C#) ─────────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'cs-html-encode',    language: 'cs', match: { type: 'call', callee: 'HtmlEncode' },     effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'cs-url-encode',     language: 'cs', match: { type: 'call', callee: 'UrlEncode' },      effect: 'strip', appliesTo: ['url'] },
  { kind: 'sanitizer', id: 'cs-path-getfullpath',language: 'cs', match: { type: 'call', callee: 'GetFullPath' },   effect: 'taintIf-not-pinned', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'cs-int-parse',      language: 'cs', match: { type: 'call', callee: 'Parse' },          effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'cs-int-tryparse',   language: 'cs', match: { type: 'call', callee: 'TryParse' },       effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'cs-regex-escape',   language: 'cs', match: { type: 'call', callee: 'Escape' },         effect: 'strip', appliesTo: ['regex'] },
  { kind: 'sanitizer', id: 'cs-addwithvalue',   language: 'cs', match: { type: 'call', callee: 'AddWithValue' },   effect: 'strip', appliesTo: ['sql'] },

  // ─── SOURCES (Kotlin — Spring / Ktor) ────────────────────────────────────
  { kind: 'source', id: 'kt-request-param',    language: 'kt', framework: 'spring', match: { type: 'call', callee: 'getParameter' }, label: 'request.getParameter (Kotlin Spring)' },
  { kind: 'source', id: 'kt-request-header',   language: 'kt', framework: 'spring', match: { type: 'call', callee: 'getHeader' },    label: 'request.getHeader' },
  { kind: 'source', id: 'kt-ktor-receive',     language: 'kt', framework: 'ktor',   match: { type: 'call', callee: 'receive' },      label: 'call.receive() (Ktor)', provenance: 'http-body' },
  { kind: 'source', id: 'kt-ktor-parameters',  language: 'kt', framework: 'ktor',   match: { type: 'member', object: 'call', prop: 'parameters' }, label: 'call.parameters (Ktor)' },
  { kind: 'source', id: 'kt-env-var',          language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'getenv' },       label: 'System.getenv (Kotlin)', provenance: 'env' },

  // ─── SINKS (Kotlin) ──────────────────────────────────────────────────────
  { kind: 'sink', id: 'kt-jdbc-execute',       language: 'kt', framework: 'jdbc',   match: { type: 'call', callee: 'executeQuery' }, argIndex: 0,
    vuln: { name: 'SQL Injection (JDBC executeQuery from Kotlin)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use PreparedStatement + setX(N, v) — Kotlin string templates concatenated into SQL are still injection.' } },
  { kind: 'sink', id: 'kt-exposed-exec',       language: 'kt', framework: 'exposed', match: { type: 'call', callee: 'exec' },        argIndex: 0,
    vuln: { name: 'SQL Injection (Exposed.exec with raw string)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use Exposed DSL queries or named-parameter exec with a typed parameter list.' } },
  { kind: 'sink', id: 'kt-runtime-exec',       language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'exec' },         argIndex: 0,
    vuln: { name: 'Command Injection (Runtime.exec / ProcessBuilder string-form, Kotlin)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Use ProcessBuilder(listOf("cmd", "arg")) — never pass a single string to exec.' } },
  { kind: 'sink', id: 'kt-file-readtext',      language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'readText' },     argIndex: 0,
    vuln: { name: 'Path Traversal (File(name).readText)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize: `File(name).canonicalFile` and verify path stays inside an allow-listed base.' } },
  { kind: 'sink', id: 'kt-url-readtext',       language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'readText' },     argIndex: 'all',
    vuln: { name: 'SSRF (URL(...).readText with user URL)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the URL host against an allow-list before reading.' } },
  { kind: 'sink', id: 'kt-objectinputstream', language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'readObject' },    argIndex: 'all',
    vuln: { name: 'Insecure Deserialization (ObjectInputStream.readObject, Kotlin)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Use kotlinx.serialization with explicit class allow-list.' } },

  // ─── SANITIZERS (Kotlin) ─────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'kt-html-escape',   language: 'kt', match: { type: 'call', callee: 'escapeHtml4' },  effect: 'strip', appliesTo: ['xss'] },
  { kind: 'sanitizer', id: 'kt-url-encode',    language: 'kt', match: { type: 'call', callee: 'URLEncoder' },   effect: 'strip', appliesTo: ['url'] },
  { kind: 'sanitizer', id: 'kt-int-toint',     language: 'kt', match: { type: 'call', callee: 'toInt' },        effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'kt-int-toIntOrNull',language: 'kt', match: { type: 'call', callee: 'toIntOrNull' }, effect: 'strip', appliesTo: ['*'] },
  { kind: 'sanitizer', id: 'kt-path-canonical',language: 'kt', match: { type: 'call', callee: 'canonicalFile' },effect: 'taintIf-not-pinned', appliesTo: ['path'] },
  { kind: 'sanitizer', id: 'kt-jdbc-setstring',language: 'kt', match: { type: 'call', callee: 'setString' },    effect: 'strip', appliesTo: ['sql'] },
];

// ─── Expanded sanitizer catalog (v0.65.0) ────────────────────────────────
// ~450 additional entries across JS / Python / Java / Ruby / PHP / Go.
// Lives in catalog-expanded.js to keep the diff reviewable. Merged into
// the main CATALOG below so the indexer treats them identically.
import { EXPANDED_SANITIZERS } from './catalog-expanded.js';
// Merge the expanded sanitizer catalog. We dedupe on `id` (case-insensitive)
// so a base-catalog entry always wins over a same-id expanded one — the base
// catalog is the curated/blessed surface; the expansion is additive coverage.
{
  const _ids = new Set();
  for (const e of CATALOG) if (e && e.id) _ids.add(String(e.id).toLowerCase());
  for (const e of EXPANDED_SANITIZERS) {
    if (!e || !e.id) continue;
    const k = String(e.id).toLowerCase();
    if (_ids.has(k)) continue;       // base catalog wins on id collision
    _ids.add(k);
    CATALOG.push(e);
  }
}

// Provenance defaults (Sentinel-parity audit P1-10):
//
// Every catalog entry is implicitly `source: 'official'` (curated by this
// repo's maintainers, drawn from upstream framework docs). Future community
// contributions or LLM-inferred entries will carry `source: 'community'` or
// `source: 'inferred'`. Operators who want to opt OUT of non-official
// entries set `AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY=1`.
//
// We default-stamp `source: 'official'` on entries that don't have one so
// existing callers keep working.
for (const e of CATALOG) {
  if (!e.source) e.source = 'official';
}

// Premortem 3R-10: OFFICIAL_ONLY was captured ONCE at module load, baked
// into the prebuilt indexes. A caller that sets the env var just before
// running a scan (e.g., a CI lane that wants strict-mode just for this one
// invocation) was silently ignored. Now the indexes hold ALL entries; the
// filter runs per-match by reading the env each call.
const CALLEE_INDEX = new Map();
const MEMBER_INDEX = new Map();
for (const e of CATALOG) {
  if (!e.match) continue;
  if (e.match.type === 'call' && e.match.callee && e.match.callee !== '*') {
    const k = e.match.callee;
    if (!CALLEE_INDEX.has(k)) CALLEE_INDEX.set(k, []);
    CALLEE_INDEX.get(k).push(e);
  } else if (e.match.type === 'member' && e.match.object && e.match.prop) {
    const k = `${e.match.object}.${e.match.prop}`;
    if (!MEMBER_INDEX.has(k)) MEMBER_INDEX.set(k, []);
    MEMBER_INDEX.get(k).push(e);
  }
}

function isOfficialOnlyMode() {
  return process.env.AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY === '1';
}

// Premortem 4R-4: the per-match `filter()` allocated a fresh array on every
// taint-engine lookup. On a 100-file Java codebase this was millions of
// allocations. Memoize by entries-identity; bump a generation counter when
// the env mode changes so a mid-process toggle invalidates cleanly.
let _modeGeneration = 0;
let _lastMode = null;
const _filterCache = new WeakMap();
function filterByProvenance(entries) {
  const mode = isOfficialOnlyMode();
  if (!mode) return entries;
  if (mode !== _lastMode) {
    _modeGeneration++;
    _lastMode = mode;
  }
  const cached = _filterCache.get(entries);
  if (cached && cached.gen === _modeGeneration) return cached.list;
  const list = entries.filter(e => e.source === 'official');
  _filterCache.set(entries, { gen: _modeGeneration, list });
  return list;
}

export function matchSource(expr) {
  if (!expr) return null;
  // Member sources (req.query): the original path — unchanged.
  if (expr.kind === 'member' && expr.object?.kind === 'ident') {
    const raw = MEMBER_INDEX.get(`${expr.object.name}.${expr.prop}`);
    if (raw) {
      const hits = filterByProvenance(raw);
      const s = hits.find(h => h.kind === 'source');
      if (s) return s;
    }
  }
  // R3 (PRD §5): CALL sources (r.FormValue(), r.URL.Query(), c.QueryParam()).
  // matchSource previously handled only member reads, so Go's call-shaped
  // sources were never recognized at the assignment RHS. Match by callee last
  // segment (Go gives a dotted string; JS/Py a member/ident expr).
  if (expr.kind === 'call') {
    let cn = null;
    if (typeof expr.callee === 'string') cn = expr.callee.includes('.') ? expr.callee.slice(expr.callee.lastIndexOf('.') + 1) : expr.callee;
    else if (expr.callee && expr.callee.kind === 'member') cn = expr.callee.prop;
    else if (expr.callee && expr.callee.kind === 'ident') cn = expr.callee.name;
    if (cn) {
      const raw = CALLEE_INDEX.get(cn);
      if (raw) {
        const hits = filterByProvenance(raw);
        const s = hits.find(h => h.kind === 'source');
        if (s) return s;
      }
    }
  }
  return null;
}

export function matchSinkOrSanitizer(calleeExpr) {
  if (!calleeExpr) return null;
  let calleeName = null;
  // R3 (PRD §5): the Go IR (and other string-callee parsers) represent a call
  // target as a dotted STRING ("db.Query") rather than a member expr. Match on
  // the last segment so those languages' sinks/sanitizers are recognized too.
  if (typeof calleeExpr === 'string') calleeName = calleeExpr.includes('.') ? calleeExpr.slice(calleeExpr.lastIndexOf('.') + 1) : calleeExpr;
  else if (calleeExpr.kind === 'ident') calleeName = calleeExpr.name;
  else if (calleeExpr.kind === 'member') calleeName = calleeExpr.prop;
  if (!calleeName) return null;
  const raw = CALLEE_INDEX.get(calleeName);
  if (!raw) return null;
  const hits = filterByProvenance(raw);
  return hits.length ? hits : null;
}

// For tests and reflection.
export function _catalogSize() { return CATALOG.length; }
