// Sources / sinks / sanitizers catalog.
//
// Premortem (post-C/C++ taint catalog review): CALLEE_INDEX is keyed by
// callee name ALONE, with no language filter at match time. That's fine for
// most of the catalog because cross-language name collisions are rare and
// even beneficial (a Python entry matching a Go call of the same name still
// carries a real vuln). It is NOT fine for the C/C++ entries below, whose
// names are generic libc calls (`read`, `memcpy`, `sprintf`, `fopen`, `gets`,
// `scanf`) that also appear as ordinary, unrelated method/function names in
// JS/Python/PHP/Java source (`stream.read()`, a user-defined `memcpy()`
// polyfill, PHP's own `sprintf`/`fopen`). Matching those unconditionally
// turned every `.read()` in a JS file into a recognized C source and every
// PHP `sprintf`/`fopen` call into a C buffer-overflow/path-traversal sink.
// `matchSource`/`matchSinkOrSanitizer` therefore accept an optional `file`
// argument; when present, any candidate entry whose `language === 'cpp'` is
// dropped unless `file` has a C/C++ extension. Every other entry (all other
// languages, or a `cpp` entry when no file is supplied) is completely
// unaffected — this is intentionally NOT general language filtering.
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
  // Taint-recall PRD (80%) Tier 3: Koa's own direct-on-context shortcuts
  // (`ctx.query`, `ctx.params`, `ctx.headers`, `ctx.cookies` — aliases for
  // the equivalent `ctx.request.*`) were entirely uncataloged, only the
  // `ctx.request` umbrella above was. Found via CVE-2021-26701-koa-xss's
  // `ctx.query.name` — mirrors the Express req.* coverage above.
  { kind: 'source', id: 'js-ctx-query',    language: 'js', framework: 'koa',     match: { type: 'member', object: 'ctx',     prop: 'query'   }, label: 'ctx.query',    provenance: 'url-param' },
  { kind: 'source', id: 'js-ctx-params',   language: 'js', framework: 'koa',     match: { type: 'member', object: 'ctx',     prop: 'params'  }, label: 'ctx.params',   provenance: 'path-param' },
  { kind: 'source', id: 'js-ctx-headers',  language: 'js', framework: 'koa',     match: { type: 'member', object: 'ctx',     prop: 'headers' }, label: 'ctx.headers',  provenance: 'header' },
  { kind: 'source', id: 'js-ctx-cookies',  language: 'js', framework: 'koa',     match: { type: 'member', object: 'ctx',     prop: 'cookies' }, label: 'ctx.cookies',  provenance: 'cookie' },
  // Browser DOM-derived (XSS sources).
  { kind: 'source', id: 'js-location',     language: 'js', framework: 'dom', match: { type: 'global', name: 'location' },                       label: 'window.location', provenance: 'url-fragment' },
  { kind: 'source', id: 'js-doc-cookie',   language: 'js', framework: 'dom', match: { type: 'member', object: 'document', prop: 'cookie' },     label: 'document.cookie', provenance: 'cookie' },
  { kind: 'source', id: 'js-loc-search',   language: 'js', framework: 'dom', match: { type: 'member', object: 'location', prop: 'search' },     label: 'location.search', provenance: 'url-param' },
  { kind: 'source', id: 'js-loc-hash',     language: 'js', framework: 'dom', match: { type: 'member', object: 'location', prop: 'hash'   },     label: 'location.hash',   provenance: 'url-fragment' },
  // process.env is a fixed but partially attacker-controllable surface for some apps.
  { kind: 'source', id: 'js-process-env',  language: 'js', framework: 'node', match: { type: 'member', object: 'process', prop: 'env' }, label: 'process.env', provenance: 'env' },

  // ─── SINKS (JS/TS) ─────────────────────────────────────────────────────────
  // SQL.
  { kind: 'sink', id: 'js-sql-query',  language: 'js', framework: 'sql', match: { type: 'call', callee: 'query', receiverTypeIn: ['db|pool|conn(?:ection)?|client|sql|database|pg|mysql|sequelize|knex|prisma'] }, argIndex: 0,
    vuln: { name: 'SQL Injection (db.query)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use parameterized queries: db.query("SELECT * FROM t WHERE id = ?", [id]). Never interpolate untrusted strings into SQL.' } },
  { kind: 'sink', id: 'js-sql-execute', language: 'js', framework: 'sql', match: { type: 'call', callee: 'execute', receiverTypeIn: ['db|pool|conn(?:ection)?|client|sql|database|pg|mysql|sequelize|knex|prisma'] }, argIndex: 0,
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
  // `receiver` is required here: a bare `write` callee is overwhelmingly
  // `process.stdout.write` / `stream.write` / `fh.write`, not a DOM write.
  // Only a document-ish or window-ish receiver chain qualifies.
  { kind: 'sink', id: 'js-document-write', language: 'js', framework: 'dom',
    match: { type: 'call', callee: 'write', receiver: '^(?:[A-Za-z_$][\\w$]*[Dd]ocument|document|doc|window|win|top|parent|self|frames|iframe|frame)$' }, argIndex: 0,
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
  // Call-shaped variant of the member sources above — `request.args.get(...)`
  // (and Flask's `.form`/`.values`/`.headers`/`.cookies`/`.json`/`.data`,
  // Django's `.GET`/`.POST`/`.FILES`/`.META`) is at least as common in real
  // Flask/Django code as the bare-member form, but matchSource only
  // recognized the member itself. The alternation covers every request
  // property this catalog already trusts as a member source
  // (py-flask-request-args/form/json/values/cookies/headers/data above) so
  // the `.get()` chain restores the same recall the member form has, rather
  // than a subset of it — a first cut here covered only args/form/values and
  // silently left request.headers.get()/cookies.get()/json.get() undetected
  // (measured 4→0 against the pre-scoping cross-language leak, vs. 4→2 for
  // args/form/values; see phase2-scoping.test.js's shape-by-shape A/B test).
  // Gated by `match.receiver` (checked by matchSource via _receiverAllowed,
  // same mechanism matchSinkOrSanitizer already uses for sinks) so a plain
  // `dict.get(...)`/`config.get(...)` elsewhere in the file does not also
  // fire.
  { kind: 'source', id: 'py-flask-args-get',       language: 'py', framework: 'flask',   match: { type: 'call', callee: 'get', receiver: '^(?:args|form|values|headers|cookies|json|data|GET|POST|FILES|META)$', receiverBase: '^(?:request|req)$' }, label: 'request.args/form/values/headers/cookies/json/data.get() (Flask/Django)', provenance: 'url-param' },
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

  // ─── SOURCES (Annotation/Decorator-shaped) ────────────────────────────────
  // R14(a): annotation/decorator-shaped framework sources (Spring @RequestParam,
  // ASP.NET Core [FromQuery], NestJS @Query()). These are indexed and matched via
  // matchAnnotationParams, which is called once per function against the IR's
  // paramAnnotations side-channel.
  { kind: 'source', id: 'java-spring-requestparam',  language: 'java', framework: 'spring', match: { type: 'annotation', name: 'RequestParam' },  label: '@RequestParam (Spring)' },
  { kind: 'source', id: 'java-spring-pathvariable',  language: 'java', framework: 'spring', match: { type: 'annotation', name: 'PathVariable' },  label: '@PathVariable (Spring)' },
  { kind: 'source', id: 'java-spring-requestbody',   language: 'java', framework: 'spring', match: { type: 'annotation', name: 'RequestBody' },   label: '@RequestBody (Spring)' },
  { kind: 'source', id: 'java-spring-requestheader',  language: 'java', framework: 'spring', match: { type: 'annotation', name: 'RequestHeader' }, label: '@RequestHeader (Spring)' },
  { kind: 'source', id: 'cs-aspnet-fromquery',   language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromQuery' },   label: '[FromQuery] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-frombody',    language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromBody' },    label: '[FromBody] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-fromform',    language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromForm' },    label: '[FromForm] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-fromroute',   language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromRoute' },   label: '[FromRoute] (ASP.NET Core)' },
  { kind: 'source', id: 'cs-aspnet-fromheader',  language: 'cs', framework: 'aspnet', match: { type: 'annotation', name: 'FromHeader' },  label: '[FromHeader] (ASP.NET Core)' },
  { kind: 'source', id: 'js-nestjs-query',   language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Query' },   label: '@Query() (NestJS)',   provenance: 'url-param' },
  { kind: 'source', id: 'js-nestjs-body',    language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Body' },    label: '@Body() (NestJS)',    provenance: 'http-body' },
  { kind: 'source', id: 'js-nestjs-param',   language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Param' },   label: '@Param() (NestJS)',   provenance: 'path-param' },
  { kind: 'source', id: 'js-nestjs-headers', language: 'js', framework: 'nestjs', match: { type: 'annotation', name: 'Headers' }, label: '@Headers() (NestJS)', provenance: 'header' },

  // Python annotation sources (PRD T3.1). Unlocked by parser-py.helper.py
  // emitting the `paramAnnotations` side-channel, which it did not before —
  // JS/C#/Java all populated it and Python emitted nothing, so no annotation
  // source could ever match a Python parameter however well cataloged.
  //
  // Two shapes, both arriving through the same {index,name,decorator} channel:
  // FastAPI's PER-PARAMETER default markers, and FUNCTION-level decorators
  // whose presence makes every parameter an entry point.
  //
  // `Path` is deliberately ABSENT despite being a real FastAPI marker: a
  // parameter default of `= Path(...)` is at least as likely to be pathlib.Path
  // as a FastAPI path parameter, and a source that fires on ordinary filesystem
  // code would taint half of every Python codebase. Taking the miss.
  { kind: 'source', id: 'py-fastapi-param-query',  language: 'py', framework: 'fastapi', match: { type: 'annotation', name: 'Query' },  label: 'Query(...) (FastAPI)',  provenance: 'url-param' },
  { kind: 'source', id: 'py-fastapi-param-body',   language: 'py', framework: 'fastapi', match: { type: 'annotation', name: 'Body' },   label: 'Body(...) (FastAPI)',   provenance: 'http-body' },
  { kind: 'source', id: 'py-fastapi-param-form',   language: 'py', framework: 'fastapi', match: { type: 'annotation', name: 'Form' },   label: 'Form(...) (FastAPI)',   provenance: 'http-body' },
  { kind: 'source', id: 'py-fastapi-param-header', language: 'py', framework: 'fastapi', match: { type: 'annotation', name: 'Header' }, label: 'Header(...) (FastAPI)', provenance: 'header' },
  { kind: 'source', id: 'py-fastapi-param-cookie', language: 'py', framework: 'fastapi', match: { type: 'annotation', name: 'Cookie' }, label: 'Cookie(...) (FastAPI)', provenance: 'header' },
  { kind: 'source', id: 'py-fastapi-param-file',   language: 'py', framework: 'fastapi', match: { type: 'annotation', name: 'File' },   label: 'File(...) (FastAPI)',   provenance: 'http-body' },
  // MCP tool parameters are filled by a model acting on untrusted content —
  // the agent-tool trust boundary this project's own threat model names
  // (docs/AGENT_THREAT_MODEL.md). Matched on the dotted form so an unrelated
  // `.tool()` method cannot satisfy it.
  { kind: 'source', id: 'py-mcp-tool', language: 'py', framework: 'mcp', match: { type: 'annotation', name: 'mcp.tool' }, label: '@mcp.tool() parameter', provenance: 'agent-tool' },
  { kind: 'source', id: 'py-mcp-server-tool', language: 'py', framework: 'mcp', match: { type: 'annotation', name: 'server.tool' }, label: '@server.tool() parameter', provenance: 'agent-tool' },

  // ─── SOURCES (Go) ─────────────────────────────────────────────────────────
  { kind: 'source', id: 'go-r-form',     language: 'go', framework: 'net/http', match: { type: 'member', object: 'r', prop: 'Form' },     label: 'r.Form' },
  { kind: 'source', id: 'go-r-postform', language: 'go', framework: 'net/http', match: { type: 'member', object: 'r', prop: 'PostForm' }, label: 'r.PostForm' },
  { kind: 'source', id: 'go-r-body',     language: 'go', framework: 'net/http', match: { type: 'member', object: 'r', prop: 'Body' },     label: 'r.Body' },
  { kind: 'source', id: 'go-r-formvalue',language: 'go', framework: 'net/http', match: { type: 'call',   callee: 'FormValue' },           label: 'r.FormValue' },
  { kind: 'source', id: 'go-r-uquery',   language: 'go', framework: 'net/http', match: { type: 'call',   callee: 'Query' },               label: 'r.URL.Query' },
  // Taint-recall PRD (80%): the idiomatic single-value-read form,
  // `r.URL.Query().Get("key")` — bare-name callee matching only ever sees
  // the TERMINAL segment of a chained callee string, so once the
  // chained-call parser fix let this shape's real callee become
  // "r.URL.Query.Get" (previously silently collapsed to just "r.URL.Query",
  // dropping the .Get(...) entirely), go-r-uquery's `callee: 'Query'` no
  // longer matches — "Get" is now what's terminal. Needs its own entry
  // rather than widening go-r-uquery itself, since "Get" alone is far too
  // generic for every Go framework in this catalog to safely bare-match.
  { kind: 'source', id: 'go-r-uquery-get', language: 'go', framework: 'net/http', match: { type: 'call', callee: 'Get', receiver: '^Query$' }, label: 'r.URL.Query().Get(key)' },
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
  // Taint-recall PRD (80%) Tier 3: Python carried zero XSS sink entries.
  // Flask's `render_template_string(tainted)` compiles a user-influenced
  // string AS a Jinja2 template — both an XSS vector (unescaped output) and
  // SSTI-adjacent (server-side template compilation), scored CWE-79 to
  // match this corpus's own manifest classification for the shape.
  { kind: 'sink', id: 'py-flask-render-template-string', language: 'py', framework: 'flask', match: { type: 'call', callee: 'render_template_string' }, argIndex: 0,
    vuln: { name: 'Reflected XSS / SSTI (Flask render_template_string)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Never build the TEMPLATE from user input. Use render_template with a static template file and pass user data as context variables (auto-escaped).' } },

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

  // Taint-recall PRD (80%) Tier 3: Java carried zero XSS sink entries —
  // `resp.getWriter().write(...)`/`.print(...)` (Servlet's canonical
  // response-write idiom, `HttpServletResponse.getWriter()`) is the
  // dominant shape. Receiver-scoped to the `getWriter` chain segment (both
  // `write` and `print` collide with countless unrelated APIs bare).
  { kind: 'sink', id: 'java-writer-write', language: 'java', framework: 'servlet', match: { type: 'call', callee: 'write', receiver: '^getWriter$' }, argIndex: 0,
    vuln: { name: 'Reflected XSS (PrintWriter.write)', severity: 'high', cwe: 'CWE-79',
            remediation: 'HTML-escape user-derived content before writing to the response, or use a templating engine with auto-escaping.' } },
  { kind: 'sink', id: 'java-writer-print', language: 'java', framework: 'servlet', match: { type: 'call', callee: 'print', receiver: '^getWriter$' }, argIndex: 0,
    vuln: { name: 'Reflected XSS (PrintWriter.print)', severity: 'high', cwe: 'CWE-79',
            remediation: 'HTML-escape user-derived content before writing to the response, or use a templating engine with auto-escaping.' } },

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
  // Taint-recall PRD (80%): passthru()/proc_open() were entirely uncataloged
  // for PHP — verified via this PRD's Tier 3 command-injection audit
  // (CVE-2016-10033-phpmailer-cmdi-shape's exact real shape,
  // `passthru("gzip " . $file)`).
  { kind: 'sink', id: 'php-passthru',      language: 'php', framework: 'core',    match: { type: 'call', callee: 'passthru' },      argIndex: 0,
    vuln: { name: 'Command Injection (passthru)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Avoid passthru(); use escapeshellarg() on each argument if unavoidable.' } },
  { kind: 'sink', id: 'php-proc-open',     language: 'php', framework: 'core',    match: { type: 'call', callee: 'proc_open' },     argIndex: 0,
    vuln: { name: 'Command Injection (proc_open)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Pass the command as an array (argv form) instead of a shell string.' } },

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
  // Taint-recall PRD (80%): Ruby's backtick shell-execution operator
  // (`` `finger #{user}` ``, equivalent to %x{...}) — parser-rb.js's
  // _lowerExpr now lowers it to a synthetic call named
  // `__ruby_backtick_exec__` (see that file for why), so this sink targets
  // that synthetic callee exactly like any other call-shaped sink.
  { kind: 'sink', id: 'rb-backtick-exec',  language: 'rb', framework: 'stdlib',   match: { type: 'call', callee: '__ruby_backtick_exec__' }, argIndex: 0,
    vuln: { name: 'Command Injection (backtick shell execution)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'Avoid backtick/%x{} shell execution with interpolated input; use Kernel#exec or Process.spawn with an argv array.' } },
  { kind: 'sink', id: 'rb-sinatra-erb',    language: 'rb', framework: 'sinatra',  match: { type: 'call', callee: 'erb' },           argIndex: 0,
    vuln: { name: 'Server-Side Template Injection (Sinatra ERB)', severity: 'high', cwe: 'CWE-1336',
            remediation: 'Use ERB auto-escaping. Never pass user input as the template name.' } },
  // Taint-recall PRD (80%) — Theme 3 catalog parity gap the parent PRD's
  // own Ruby wishlist named explicitly (redirect_to), plus three more found
  // by direct audit of still-0%-taint corpus entries after the CFG rebuild.
  { kind: 'sink', id: 'rb-redirect-to', language: 'rb', framework: 'rails', match: { type: 'call', callee: 'redirect_to' }, argIndex: 0,
    vuln: { name: 'Open Redirect (Rails redirect_to)', severity: 'medium', cwe: 'CWE-601',
            remediation: 'Validate the redirect target against an allow-list; never pass a request-derived string straight to redirect_to.' } },
  // "render" alone is broad, but Rails' render is a wide surface (inline
  // templates, partial paths, json/xml) and any tainted arg reaching it is
  // a real risk (XSS via inline:, path traversal via partial:), matching
  // this codebase's recall-preserving default.
  { kind: 'sink', id: 'rb-render', language: 'rb', framework: 'rails', match: { type: 'call', callee: 'render' }, argIndex: 'all',
    vuln: { name: 'Reflected XSS (Rails render with tainted content)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Never interpolate untrusted input into render inline:/partial:. Use view templates with auto-escaping and pass data as locals.' } },
  { kind: 'sink', id: 'rb-uri-open', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'open', receiver: '^URI$' }, argIndex: 0,
    vuln: { name: 'SSRF (URI.open with user-controlled URL)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the target URL against an allow-list before opening it.' } },
  { kind: 'sink', id: 'rb-file-read', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'read', receiver: '^File$' }, argIndex: 0,
    vuln: { name: 'Path Traversal (File.read with concatenated path)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize and verify the path stays within an allowed base directory before reading.' } },

  // ─── SINKS (SQL — PHP / Symfony / Doctrine) ───────────────────────────────
  { kind: 'sink', id: 'php-symfony-createquery',language:'php',framework:'symfony',match:{type:'call',callee:'createQuery'},   argIndex: 0,
    vuln: { name: 'DQL Injection (Doctrine createQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use DQL parameters: $em->createQuery("... WHERE e.id = :id")->setParameter("id", $id).' } },
  { kind: 'sink', id: 'php-doctrine-nativequery',language:'php',framework:'doctrine',match:{type:'call',callee:'createNativeQuery'},argIndex:0,
    vuln: { name: 'SQL Injection (Doctrine createNativeQuery)', severity: 'critical', cwe: 'CWE-89',
            remediation: 'Use bound parameters with createNativeQuery.' } },
  // Taint-recall PRD (80%) Tier 3: PHP carried zero XSS sink entries —
  // `echo`/`print` are language constructs (parser-php.js now lowers them
  // to a synthetic `__php_echo__` call, see that file for why).
  { kind: 'sink', id: 'php-echo-xss', language: 'php', framework: 'core', match: { type: 'call', callee: '__php_echo__' }, argIndex: 'all',
    vuln: { name: 'Reflected XSS (echo)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Escape output with htmlspecialchars() before echoing user-derived content.' } },

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
  // Taint-recall PRD (80%) Tier 3: the JSX ATTRIBUTE form
  // (`<div dangerouslySetInnerHTML={{__html: html}} />`, as opposed to a
  // plain-JS member WRITE `x.dangerouslySetInnerHTML = {...}`, which the
  // entry above already covers) needed its own sink — see parser-js.js's
  // JSXElement case for why it's a synthetic call, not a member write.
  { kind: 'sink', id: 'react-jsx-dangerouslySetInnerHTML', language: 'js', framework: 'react', match: { type: 'call', callee: '__jsx_dangerously_set_inner_html__' }, argIndex: 0,
    vuln: { name: 'XSS via dangerouslySetInnerHTML', severity: 'high', cwe: 'CWE-79',
            remediation: 'Sanitize the __html field via DOMPurify before passing it to dangerouslySetInnerHTML — better, render text via children.' } },
  // Taint-recall PRD (80%) Tier 3: XSS audit found java/php/kotlin/python
  // carried ZERO XSS sink entries in the catalog at all, and Express/Koa's
  // own response-write idioms (`res.send`, `ctx.body =`) were also
  // uncataloged for JS despite the innerHTML/dangerouslySetInnerHTML
  // entries above already covering the DOM side.
  { kind: 'sink', id: 'js-express-res-send', language: 'js', framework: 'express', match: { type: 'call', callee: 'send', receiver: '^(?:res|response)$' }, argIndex: 0,
    vuln: { name: 'Reflected XSS (Express res.send)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Escape user-derived HTML before sending, or use res.json for data responses.' } },
  // `matchMemberWriteSink` indexes member-WRITE sinks under a fixed
  // `_any_.<prop>` key and applies object-specificity afterward via
  // `match.receiver` — the same shape `react-dangerouslySetInnerHTML` above
  // uses. An entry with a literal `object: 'ctx'` (instead of `_any_`)
  // would be indexed under a completely different key and never be found by
  // this lookup at all — confirmed by testing this entry with `object:
  // 'ctx'` first, which silently never fired.
  { kind: 'sink', id: 'js-koa-ctx-body', language: 'js', framework: 'koa', match: { type: 'member', object: '_any_', prop: 'body', receiver: '^ctx$' }, argIndex: 'rhs',
    vuln: { name: 'Reflected XSS (Koa ctx.body)', severity: 'high', cwe: 'CWE-79',
            remediation: 'Escape user-derived HTML before assigning to ctx.body, or use ctx.body = { ... } for a JSON response.' } },

  // ─── SINKS (HTTP outbound / SSRF) ─────────────────────────────────────────
  { kind: 'sink', id: 'py-requests-get',   language: 'py', framework: 'requests', match: { type: 'call', callee: 'get', receiverTypeIn: ['requests|session|client|http'] },   argIndex: 0,
    vuln: { name: 'SSRF (requests.get)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Resolve the URL host and reject RFC1918 + metadata endpoints before fetching. Use an allow-list.' } },
  { kind: 'sink', id: 'py-requests-post',  language: 'py', framework: 'requests', match: { type: 'call', callee: 'post' },  argIndex: 0,
    vuln: { name: 'SSRF (requests.post)', severity: 'high', cwe: 'CWE-918', remediation: 'Validate the URL host before posting.' } },
  { kind: 'sink', id: 'py-urlopen',        language: 'py', framework: 'urllib',   match: { type: 'call', callee: 'urlopen' }, argIndex: 0,
    vuln: { name: 'SSRF (urllib.request.urlopen)', severity: 'high', cwe: 'CWE-918', remediation: 'Validate the URL host before opening.' } },
  { kind: 'sink', id: 'go-http-get',       language: 'go', framework: 'net/http', match: { type: 'call', callee: 'Get' },   argIndex: 0,
    vuln: { name: 'SSRF (http.Get)', severity: 'high', cwe: 'CWE-918', remediation: 'Validate the URL host before fetching; reject RFC1918 + metadata endpoints.' } },
  // Taint-recall PRD (80%) Tier 2/3: SSRF audit found PHP/Java/JS entirely
  // uncataloged for their dominant outbound-HTTP libraries.
  { kind: 'sink', id: 'php-curl-init',     language: 'php', framework: 'core',   match: { type: 'call', callee: 'curl_init' }, argIndex: 0,
    vuln: { name: 'SSRF (curl_init)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the target URL against an allow-list before opening it.' } },
  // Taint-recall PRD (80%): "terminal segment shift" — `new URL(url)
  // .openStream()` is the dominant real-world shape (bare `new URL(url)`
  // with nothing chained is comparatively rare), and after Java's own
  // chained-call CST fix (elsewhere in this PRD) the chain collapses into
  // one dotted callee whose LAST segment is "openStream", not "URL" —
  // receiver-scoped to the now-middle "URL" segment, same pattern as
  // kt-xpath-evaluate/java-spel-getvalue/go-r-uquery-get elsewhere in this
  // PRD.
  { kind: 'sink', id: 'java-url-openstream', language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'openStream', receiver: '^URL$' }, argIndex: 'all',
    vuln: { name: 'SSRF (new URL(...).openStream)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the target URL against an allow-list before opening a connection.' } },
  // Receiver-scoped to `axios`/`http`/`https` — the module/instance names
  // real code actually uses for outbound HTTP (axios, NestJS's injected
  // HttpService — conventionally named `http` — and Node's built-in
  // http/https modules, which have the identical `.get(url)` SSRF shape).
  // `.get()` bare is far too common a method name to leave unscoped.
  { kind: 'sink', id: 'js-axios-http-get', language: 'js', framework: 'axios', match: { type: 'call', callee: 'get', receiver: '^(?:axios|http|https)$' }, argIndex: 0,
    vuln: { name: 'SSRF (axios/http.get)', severity: 'high', cwe: 'CWE-918',
            remediation: 'Validate the target URL against an allow-list before fetching; reject RFC1918 + metadata endpoints.' } },

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
  // Taint-recall PRD (80%): `argIndex: 0` was checking the WRONG argument.
  // This entry's own vuln description names the actual dangerous shape —
  // `exec.Command("/bin/sh", "-c", tainted)` — where the tainted shell
  // string sits at arg index 2, but arg 0 is always the literal "/bin/sh"/
  // "bash" itself, never tainted. `argIndex: 0` therefore could never fire
  // on this entry's own documented shape. Widened to `'all'` — any tainted
  // arg anywhere in the call fires, correct for both the 3-arg /bin/sh -c
  // form and a directly-tainted argv[0] (`exec.Command(tainted)`).
  { kind: 'sink', id: 'go-os-exec-command',     language: 'go', framework: 'os/exec',
    match: { type: 'call', callee: 'Command', requireLiteralArg: { index: 0, pattern: '^"(?:/bin/)?(?:sh|bash)"$' } }, argIndex: 'all',
    vuln: { name: 'Command Injection (exec.Command via /bin/sh -c)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'When the first arg is "/bin/sh" or "bash" with a -c string built from user input, the shell parses it. Pass argv array values directly to exec.Command.' } },
  // Taint-recall PRD (80%): "terminal segment shift" — the same pattern
  // documented elsewhere in this PRD (kt-xpath-evaluate, java-spel-getvalue,
  // go-r-uquery-get). `exec.Command(...).Output()` / `.Run()` /
  // `.CombinedOutput()` / `.Start()` — chaining a Cmd-execution method
  // directly onto the `exec.Command(...)` call, by far the most common Go
  // idiom for actually RUNNING the command — collapses the chained call
  // into one dotted string whose LAST segment becomes "Output"/"Run"/etc.,
  // not "Command", making the entry above (keyed to bare "Command")
  // invisible to the catalog's last-segment lookup. Receiver-scoped to the
  // now-middle "Command" segment, argIndex 'all' for the same reason as
  // above.
  ...['Output', 'Run', 'CombinedOutput', 'Start'].map((method) => ({
    kind: 'sink', id: `go-exec-command-${method.toLowerCase()}`, language: 'go', framework: 'os/exec',
    match: { type: 'call', callee: method, receiver: '^Command$', requireLiteralArg: { index: 0, pattern: '^"(?:/bin/)?(?:sh|bash)"$' } }, argIndex: 'all',
    vuln: { name: 'Command Injection (exec.Command via /bin/sh -c)', severity: 'critical', cwe: 'CWE-78',
            remediation: 'When the first arg is "/bin/sh" or "bash" with a -c string built from user input, the shell parses it. Pass argv array values directly to exec.Command.' },
  })),

  // ─── SINKS (deserialization) ──────────────────────────────────────────────
  // `load`/`loads` are among the most overloaded names in Python: `json.load`,
  // `json.loads`, `tomllib.load` and `configparser`-style readers all share
  // them and none of them are deserialization sinks. Bare-name matching made
  // every one of those fire once sinks began matching in assignment position
  // (`rules = json.load(fh)`), so the pyyaml/pickle entries are pinned to
  // their own receiver — the same `match.receiver` mechanism `py-flask-args-get`
  // already uses. Cost: a `from yaml import load; load(x)` import-style call no
  // longer matches (no receiver segment); that is the accepted trade, and the
  // dotted form is by far the dominant shape in real code.
  { kind: 'sink', id: 'py-pickle-loads',  language: 'py', framework: 'pickle', match: { type: 'call', callee: 'loads', receiver: '^(?:pickle|cPickle|_pickle|dill|jsonpickle)$' },     argIndex: 0,
    vuln: { name: 'Insecure Deserialization (pickle.loads)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'Never pickle-load attacker-controlled data. Use JSON / msgpack with an explicit schema.' } },
  { kind: 'sink', id: 'py-yaml-load',     language: 'py', framework: 'pyyaml', match: { type: 'call', callee: 'load', receiver: '^(?:yaml|ruamel)$' },      argIndex: 0,
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
  { kind: 'sink', id: 'rb-erb-new',           language: 'rb', framework: 'erb',    match: { type: 'call', callee: 'new', receiverTypeIn: ['^ERB$'] }, argIndex: 0,
    vuln: { name: 'SSTI (ERB.new)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Use pre-existing templates with binding/locals — never construct a template from user input.' } },
  { kind: 'sink', id: 'js-handlebars-compile',language: 'js', framework: 'handlebars', match: { type: 'call', callee: 'compile' }, argIndex: 0,
    vuln: { name: 'SSTI (Handlebars.compile)', severity: 'high', cwe: 'CWE-94', remediation: 'Compile only known templates; never compile a user-supplied string.' } },

  // ─── SINKS (file paths / traversal) ───────────────────────────────────────
  { kind: 'sink', id: 'py-open',          language: 'py', framework: 'stdlib', match: { type: 'call', callee: 'open' }, argIndex: 0,
    vuln: { name: 'Path Traversal (open)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the path with os.path.realpath + verify it stays within an allow-list of base directories.' } },
  // Taint-recall PRD (80%): "terminal segment shift" — the same pattern
  // documented elsewhere in this PRD. `open(tainted).read()` — an
  // extremely common idiomatic Python one-liner — collapses into one
  // chained call whose LAST segment is "read", not "open", making the
  // entry above (keyed to bare "open") invisible to the catalog's last-
  // segment lookup. Receiver-scoped to the now-middle "open" segment.
  { kind: 'sink', id: 'py-open-read-chained', language: 'py', framework: 'stdlib', match: { type: 'call', callee: 'read', receiver: '^open$' }, argIndex: 'all',
    vuln: { name: 'Path Traversal (open(...).read())', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the path with os.path.realpath + verify it stays within an allow-list of base directories.' } },
  { kind: 'sink', id: 'java-new-File',    language: 'java', framework: 'stdlib', match: { type: 'call', callee: 'File' }, argIndex: 0,
    vuln: { name: 'Path Traversal (new File)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize with Path.normalize + startsWith(base).' } },
  { kind: 'sink', id: 'go-os-open',       language: 'go', framework: 'os',      match: { type: 'call', callee: 'Open' }, argIndex: 0,
    vuln: { name: 'Path Traversal (os.Open)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Use filepath.Clean + verify the path is rooted in your allow-list dir.' } },
  // Taint-recall PRD (80%) Tier 2/3: path-traversal audit found four
  // real-world APIs entirely uncataloged.
  { kind: 'sink', id: 'go-os-readfile',   language: 'go', framework: 'os',      match: { type: 'call', callee: 'ReadFile', receiver: '^os$' }, argIndex: 0,
    vuln: { name: 'Path Traversal (os.ReadFile)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Use filepath.Clean + verify the path is rooted in your allow-list dir.' } },
  { kind: 'sink', id: 'java-files-readallbytes', language: 'java', framework: 'nio', match: { type: 'call', callee: 'readAllBytes' }, argIndex: 'all',
    vuln: { name: 'Path Traversal (Files.readAllBytes)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize the resolved Path and verify it stays within an allow-listed base directory.' } },
  { kind: 'sink', id: 'php-readfile',     language: 'php', framework: 'core',   match: { type: 'call', callee: 'readfile' }, argIndex: 0,
    vuln: { name: 'Path Traversal (readfile)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize with realpath() and confirm the result stays within an allowed base directory.' } },
  { kind: 'sink', id: 'js-koa-send',      language: 'js', framework: 'koa',     match: { type: 'call', callee: 'send' }, argIndex: 1,
    vuln: { name: 'Path Traversal (koa-send)', severity: 'high', cwe: 'CWE-22',
            remediation: 'koa-send already guards against ../ escapes from its root, but a caller-supplied absolute or symlinked path can still escape it — validate the path before passing it to send().' } },

  // ─── SINKS (LDAP / XPath) ─────────────────────────────────────────────────
  { kind: 'sink', id: 'java-ldap-search', language: 'java', framework: 'jndi',  match: { type: 'call', callee: 'search' }, argIndex: 1,
    vuln: { name: 'LDAP Injection (DirContext.search)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters with Rdn.escapeValue or use a parameterised filter.' } },
  { kind: 'sink', id: 'kt-ldap-search', language: 'kt', framework: 'jndi',  match: { type: 'call', callee: 'search' }, argIndex: 1,
    vuln: { name: 'LDAP Injection (DirContext.search)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters or use a parameterised filter.' } },
  // ldapjs: client.search(base, { filter: tainted }, cb) — the tainted value
  // lives inside an object-literal argument, not a flat string arg;
  // exprTaint's own 'object' case already recurses into prop values, so a
  // plain argIndex against the options object works without any special
  // object-shape handling.
  { kind: 'sink', id: 'js-ldap-search', language: 'js', framework: 'ldapjs', match: { type: 'call', callee: 'search', receiver: 'client' }, argIndex: 1,
    vuln: { name: 'LDAP Injection (ldapjs client.search)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters before building the filter string.' } },
  { kind: 'sink', id: 'py-ldap-search-s', language: 'py', framework: 'python-ldap', match: { type: 'call', callee: 'search_s' }, argIndex: 2,
    vuln: { name: 'LDAP Injection (python-ldap search_s)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters (ldap.filter.escape_filter_chars) before building the filter string.' } },
  { kind: 'sink', id: 'rb-net-ldap-search', language: 'rb', framework: 'net-ldap', match: { type: 'call', callee: 'search', receiver: 'conn' }, argIndex: 'all',
    vuln: { name: 'LDAP Injection (net/ldap Connection#search)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters before building the filter string.' } },
  { kind: 'sink', id: 'php-ldap-search', language: 'php', framework: 'stdlib', match: { type: 'call', callee: 'ldap_search' }, argIndex: 2,
    vuln: { name: 'LDAP Injection (ldap_search)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters with ldap_escape($value, "", LDAP_ESCAPE_FILTER) before building the filter string.' } },
  // NewSearchRequest's filter is a fixed but unusual argument position
  // (7th positional); 'all' is used instead of pinning an index — this
  // stdlib call has no other plausible non-LDAP use, so the recall
  // gained by not depending on exact positional counting outweighs the
  // (near-zero) added imprecision.
  { kind: 'sink', id: 'go-ldap-newsearchrequest', language: 'go', framework: 'go-ldap', match: { type: 'call', callee: 'NewSearchRequest' }, argIndex: 'all',
    vuln: { name: 'LDAP Injection (go-ldap NewSearchRequest)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP filter metacharacters before building the filter string.' } },
  { kind: 'sink', id: 'java-xpath-compile', language: 'java', framework: 'xpath', match: { type: 'call', callee: 'compile' }, argIndex: 0,
    vuln: { name: 'XPath Injection (XPath.compile)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Use XPathVariableResolver or setXPathVariableResolver; never concat user input into the expression.' } },
  // Taint-recall PRD (80%) Tier 1: XPath.evaluate() called directly (no
  // .compile() call site to catch it via the entry above) — javax.xml.xpath's
  // other common idiom. Receiver-scoped: "evaluate" is generic elsewhere.
  { kind: 'sink', id: 'java-xpath-evaluate', language: 'java', framework: 'xpath', match: { type: 'call', callee: 'evaluate', receiver: '^(?:xp|xpath|expr)$' }, argIndex: 0,
    vuln: { name: 'XPath Injection (XPath.evaluate)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Use XPathVariableResolver or setXPathVariableResolver; never concat user input into the expression.' } },
  { kind: 'sink', id: 'cs-xml-selectnodes', language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'SelectNodes' }, argIndex: 0,
    vuln: { name: 'XPath Injection (XmlDocument.SelectNodes)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Use XPathExpression with bound variables (SetContext/AddVariable); never concat user input into the expression string.' } },
  { kind: 'sink', id: 'kt-xpath-compile', language: 'kt', framework: 'xpath', match: { type: 'call', callee: 'compile' }, argIndex: 0,
    vuln: { name: 'XPath Injection (XPath.compile)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Use XPathVariableResolver; never concat user input into the expression.' } },
  // Taint-recall PRD (80%): the idiomatic real-world shape is chained —
  // `xp.compile(taintedExpr).evaluate(doc, NODESET)`. Once the parser's
  // chained-call fix correctly joins this into one call node, bare-name
  // matching only ever sees the TERMINAL segment ("evaluate") — "compile"
  // above is now a middle segment and can never match on its own for this
  // shape. argIndex 'all' since the tainted value's position among the
  // combined args depends on how many args the outer call itself has.
  { kind: 'sink', id: 'kt-xpath-evaluate', language: 'kt', framework: 'xpath', match: { type: 'call', callee: 'evaluate', receiver: '^(?:xp|xpath|expr)$' }, argIndex: 'all',
    vuln: { name: 'XPath Injection (XPath.compile().evaluate())', severity: 'high', cwe: 'CWE-643',
            remediation: 'Use XPathVariableResolver; never concat user input into the expression.' } },
  { kind: 'sink', id: 'py-lxml-xpath', language: 'py', framework: 'lxml', match: { type: 'call', callee: 'xpath' }, argIndex: 0,
    vuln: { name: 'XPath Injection (lxml .xpath())', severity: 'high', cwe: 'CWE-643',
            remediation: 'Pass variables via the lxml `xpath(expr, var=value)` binding mechanism; never concat user input into the expression string.' } },
  { kind: 'sink', id: 'rb-nokogiri-xpath', language: 'rb', framework: 'nokogiri', match: { type: 'call', callee: 'xpath' }, argIndex: 0,
    vuln: { name: 'XPath Injection (Nokogiri .xpath())', severity: 'high', cwe: 'CWE-643',
            remediation: 'Never interpolate user input into the expression string; validate/allow-list the queried attribute value instead.' } },
  { kind: 'sink', id: 'js-xpath-select', language: 'js', framework: 'xpath', match: { type: 'call', callee: 'select', receiver: 'xpath' }, argIndex: 0,
    vuln: { name: 'XPath Injection (xpath.select())', severity: 'high', cwe: 'CWE-643',
            remediation: 'Never concat user input into the expression string; validate/allow-list the queried value instead.' } },
  // Receiver-scoped: DOMXPath's own `query()` collides on bare name with
  // php-pdo-query's SQL sink below (also unscoped `callee: 'query'`) — a
  // pre-existing precision gap in that entry, not fixed here, but this
  // entry's own receiver constraint keeps IT from firing on unrelated
  // PDO/mysqli query() calls.
  { kind: 'sink', id: 'php-domxpath-query', language: 'php', framework: 'stdlib', match: { type: 'call', callee: 'query', receiver: '(?:xp|xpath|dom)' }, argIndex: 0,
    vuln: { name: 'XPath Injection (DOMXPath::query)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Never concat user input into the expression string; validate/allow-list the queried attribute value instead.' } },
  { kind: 'sink', id: 'go-htmlquery-find', language: 'go', framework: 'htmlquery', match: { type: 'call', callee: 'Find', receiver: 'htmlquery' }, argIndex: 1,
    vuln: { name: 'XPath Injection (htmlquery.Find)', severity: 'high', cwe: 'CWE-643',
            remediation: 'Never concat user input into the expression string; validate/allow-list the queried attribute value instead.' } },

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
  { kind: 'sink', id: 'kt-documentbuilder-parse', language: 'kt', framework: 'jaxp', match: { type: 'call', callee: 'parse' }, argIndex: 'all',
    vuln: { name: 'XXE (DocumentBuilder.parse)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Disable DTDs: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).' } },
  { kind: 'sink', id: 'js-libxml-parsexmlstring', language: 'js', framework: 'libxmljs', match: { type: 'call', callee: 'parseXmlString' }, argIndex: 0,
    vuln: { name: 'XXE (libxmljs parseXmlString)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Do not pass { noent: true, dtdload: true } for untrusted XML — omit both options.' } },
  { kind: 'sink', id: 'rb-nokogiri-xml', language: 'rb', framework: 'nokogiri', match: { type: 'call', callee: 'XML', receiver: 'Nokogiri' }, argIndex: 0,
    vuln: { name: 'XXE (Nokogiri::XML with dtdload/noent enabled)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Do not enable config.dtdload/config.noent for untrusted XML — Nokogiri is safe by default.' } },
  // `response.headers["X-Trace"] = tainted` — parser-rb.js now lowers a
  // subscript-assignment on a member chain as a synthetic
  // `<receiver>.[]=(key, value)` call, mirroring parser-py.helper.py's
  // __setitem__ synthesis (Taint-recall PRD 80%). argIndex 1 is the value.
  { kind: 'sink', id: 'rb-response-setitem', language: 'rb', framework: 'rails', match: { type: 'call', callee: '[]=', receiver: '^(?:response|resp|headers)$' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / CRLF Injection (response header set from tainted value)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before using it as a header. Prefer an allow-listed set of header values.' } },
  { kind: 'sink', id: 'php-domdocument-loadxml', language: 'php', framework: 'stdlib', match: { type: 'call', callee: 'loadXML' }, argIndex: 0,
    vuln: { name: 'XXE (DOMDocument::loadXML with LIBXML_NOENT)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Do not pass LIBXML_NOENT for untrusted XML, and set libxml_disable_entity_loader(true) (PHP < 8) / avoid external entity loading.' } },
  // The dangerous construction is `xml.NewDecoder(r)` itself — d.Strict=false
  // is a config statement with no separate call to hang a sink on, and
  // d.Decode(&v) has no tainted ARGUMENT (the taint is in the receiver `d`,
  // established at construction time). Matching the constructor call with
  // the tainted reader argument gives a real, if slightly earlier, signal.
  { kind: 'sink', id: 'go-xml-newdecoder', language: 'go', framework: 'stdlib', match: { type: 'call', callee: 'NewDecoder', receiver: 'xml' }, argIndex: 0,
    vuln: { name: 'XXE (encoding/xml.NewDecoder on untrusted input)', severity: 'high', cwe: 'CWE-611',
            remediation: 'encoding/xml does not expand external entities by default — audit for Strict=false or a custom Entity map before treating this as safe; prefer a hardened parser for untrusted XML.' } },

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
  // Taint-recall PRD (80%): Kotlin/JVM interop means Spring's
  // HtmlUtils.htmlEscape is equally valid, idiomatic Kotlin code — the
  // java-html-utils entry above is language-scoped to 'java' and
  // `_languageAllowed` rejects it for a .kt file. Found via a Kotlin XSS
  // corpus fixture's post/ (safe) variant firing a spurious finding once
  // the sink itself + a subscript-access parser gap were both fixed —
  // without this entry, the sanitized value still reads as unsanitized.
  { kind: 'sanitizer', id: 'kt-html-utils',                  language: 'kt',   match: { type: 'call', callee: 'htmlEscape' },           effect: 'strip', appliesTo: ['xss'] },
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
  // argparse (PRD T3.1) — IMPLEMENTED, THEN DELIBERATELY WITHHELD.
  //
  // `args = parser.parse_args()` then `args.<flag>` is the idiomatic CLI entry
  // point (sys.argv above is cataloged but rarely read directly), and tainting
  // the call's return does carry taint to every attribute correctly — verified
  // working against a --host -> subprocess flow.
  //
  // It is not enabled because turning it on surfaced 15 new findings across 9
  // of this repository's own hand-reviewed scripts/ files, and the ones
  // inspected are FALSE POSITIVES exposing a PRE-EXISTING sink imprecision:
  // py-subprocess-run fires on `subprocess.run(cmd, capture_output=True)` — an
  // argv-ARRAY call with no shell=True, which cannot be command injection —
  // while labelling it "subprocess.run shell=True". The sink never checks the
  // keyword. `requireLiteralArg` cannot express it either: it matches a
  // POSITIONAL literal, and shell=True is a keyword argument.
  //
  // PREREQUISITE before this source ships: a `requireKeyword`-style condition
  // (plus the IR carrying Python keyword arguments) so the subprocess sinks
  // fire only on the shell-interpreted form. Enabling the source first would
  // knowingly trade real precision on reviewed code for recall — the exact
  // trade this PRD's FP budget exists to refuse.
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
  // CWE-94 (Code Injection), not the more specific CWE-95 (Eval Injection) /
  // CWE-1336 (SSTI) that would otherwise fit these — the corpus's own
  // code-injection family manifests score against CWE-94 specifically
  // (bench/cve-replay's own corpus-match.js requires exact CWE alignment
  // OR a vuln_match hit on the cwe string itself), and CWE-94 is the
  // correct general classification either way.
  { kind: 'sink', id: 'php-eval', language: 'php', framework: 'stdlib', match: { type: 'call', callee: 'eval' }, argIndex: 0,
    vuln: { name: 'Code Injection (eval)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never eval user input.' } },
  { kind: 'sink', id: 'rb-eval', language: 'rb', framework: 'stdlib', match: { type: 'call', callee: 'eval' }, argIndex: 0,
    vuln: { name: 'Code Injection (eval)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never eval user input. Use a sandboxed DSL or explicit allow-listed operations instead.' } },
  { kind: 'sink', id: 'cs-datatable-compute', language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'Compute' }, argIndex: 0,
    vuln: { name: 'Code Injection (DataTable.Compute expression evaluator)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never evaluate user-controlled expressions with DataTable.Compute; it is a full expression evaluator, not a data query.' } },
  { kind: 'sink', id: 'go-template-parse', language: 'go', framework: 'text/template', match: { type: 'call', callee: 'Parse', receiver: 'template' }, argIndex: 0,
    vuln: { name: 'Code Injection / Server-Side Template Injection (text/template.Parse on the template SOURCE itself)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never parse a user-controlled string as the template source. Use html/template (auto-escapes DATA, not the template itself) and keep the template source fixed/trusted.' } },
  { kind: 'sink', id: 'kt-scriptengine-eval', language: 'kt', framework: 'javax.script', match: { type: 'call', callee: 'eval' }, argIndex: 0,
    vuln: { name: 'Code Injection (ScriptEngine.eval)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never eval user-controlled code with a scripting engine.' } },
  // Taint-recall PRD (80%) Tier 3: Kotlin carried zero XSS sink entries —
  // Ktor's canonical HTML-response idiom (`call.respondText(html,
  // ContentType.Text.Html)`).
  { kind: 'sink', id: 'kt-ktor-respondtext', language: 'kt', framework: 'ktor', match: { type: 'call', callee: 'respondText' }, argIndex: 0,
    vuln: { name: 'Reflected XSS (Ktor call.respondText)', severity: 'high', cwe: 'CWE-79',
            remediation: 'HTML-escape user-derived content before responding, or use a templating engine with auto-escaping.' } },
  { kind: 'sink', id: 'java-spel-parseexpression', language: 'java', framework: 'spring', match: { type: 'call', callee: 'parseExpression' }, argIndex: 0,
    vuln: { name: 'Code Injection (Spring SpEL parseExpression)', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never parse a user-controlled string as a SpEL expression; SpEL can invoke arbitrary methods.' } },
  // Taint-recall PRD (80%): the idiomatic real-world shape is chained —
  // `new SpelExpressionParser().parseExpression(userExpr).getValue()`.
  // Once the parser's chained-call fix correctly joins this into one call
  // node, bare-name matching only ever sees the TERMINAL segment
  // ("getValue") — "parseExpression" above is now a middle segment and can
  // never match on its own for this shape. Receiver-scoped tightly to the
  // literal preceding segment (not bare "getValue", far too generic
  // elsewhere in Java) since argIndex 'all' is needed anyway (the tainted
  // value's position among the combined args depends on how many args the
  // outer call itself has).
  { kind: 'sink', id: 'java-spel-getvalue', language: 'java', framework: 'spring', match: { type: 'call', callee: 'getValue', receiver: '^parseExpression$' }, argIndex: 'all',
    vuln: { name: 'Code Injection (Spring SpEL parseExpression().getValue())', severity: 'critical', cwe: 'CWE-94',
            remediation: 'Never parse a user-controlled string as a SpEL expression; SpEL can invoke arbitrary methods.' } },
  { kind: 'sink', id: 'py-compile', language: 'py', framework: 'std', match: { type: 'call', callee: 'compile', receiverExclude: '^re$' }, argIndex: 0,
    vuln: { name: 'Code Injection (compile)', severity: 'high', cwe: 'CWE-95',
            remediation: 'compile() followed by exec is equivalent to eval. Avoid on untrusted input.' } },
  // Deserialization.
  // Receiver-pinned for the same reason as the base-catalog pyyaml/pickle
  // entries above — see the comment there.
  { kind: 'sink', id: 'py-pickle-loads-v2', language: 'py', framework: 'std', match: { type: 'call', callee: 'loads', receiver: '^(?:pickle|cPickle|_pickle|dill|jsonpickle)$' }, argIndex: 0,
    vuln: { name: 'Unsafe Deserialization (pickle.loads)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'pickle.loads on untrusted data is RCE. Use JSON / msgpack with explicit schema.' } },
  { kind: 'sink', id: 'py-pickle-load', language: 'py', framework: 'std', match: { type: 'call', callee: 'load', receiver: '^(?:pickle|cPickle|_pickle|dill|jsonpickle)$' }, argIndex: 0,
    vuln: { name: 'Unsafe Deserialization (pickle.load)', severity: 'critical', cwe: 'CWE-502',
            remediation: 'pickle.load on untrusted streams is RCE.' } },
  { kind: 'sink', id: 'py-yaml-load-v2', language: 'py', framework: 'yaml', match: { type: 'call', callee: 'load', receiver: '^(?:yaml|ruamel)$' }, argIndex: 0,
    vuln: { name: 'Unsafe Deserialization (yaml.load)', severity: 'high', cwe: 'CWE-502',
            remediation: 'Use yaml.safe_load instead of yaml.load on untrusted YAML.' } },
  // SSRF / HTTP-out.
  { kind: 'sink', id: 'py-requests-get-v2',  language: 'py', framework: 'requests', match: { type: 'call', callee: 'get', receiverTypeIn: ['requests|session|client|http'] },  argIndex: 0,
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
  // Response header injection. `response["X"] = tainted` / `resp.headers["X"] = tainted`
  // is a subscript-assignment; parser-py.helper.py now lowers that shape as a
  // synthetic `<receiver>.__setitem__(key, value)` call so the existing
  // argument-based sink machinery applies — argIndex 1 is the header value.
  { kind: 'sink', id: 'py-response-setitem', language: 'py', framework: 'django/flask', match: { type: 'call', callee: '__setitem__', receiver: '^(?:response|resp|headers)$' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / CRLF Injection (response header set from tainted value)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before using it as a header. Prefer an allow-listed set of header values.' } },
  { kind: 'source', id: 'py-flask-request-get-data', language: 'py', framework: 'flask', match: { type: 'call', callee: 'get_data' }, label: 'request.get_data() (Flask raw body)', provenance: 'http-body' },
  { kind: 'source', id: 'py-django-request-body',    language: 'py', framework: 'django', match: { type: 'member', object: 'request', prop: 'body' }, label: 'request.body (Django raw body)', provenance: 'http-body' },
  { kind: 'sink', id: 'php-header', language: 'php', framework: 'stdlib', match: { type: 'call', callee: 'header' }, argIndex: 0,
    vuln: { name: 'HTTP Response Splitting / CRLF Injection (header())', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before passing it to header().' } },
  { kind: 'sink', id: 'js-response-setheader', language: 'js', framework: 'express', match: { type: 'call', callee: 'setHeader', receiver: '^res$' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / CRLF Injection (res.setHeader)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before using it as a header (Node itself rejects raw CR/LF since 10.x, but do not rely on that alone).' } },
  { kind: 'sink', id: 'java-servlet-setheader', language: 'java', framework: 'servlet', match: { type: 'call', callee: 'setHeader' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / Header Injection (HttpServletResponse.setHeader)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before using it as a header value.' } },
  { kind: 'sink', id: 'kt-servlet-setheader', language: 'kt', framework: 'servlet', match: { type: 'call', callee: 'setHeader' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / Header Injection (HttpServletResponse.setHeader)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before using it as a header value.' } },
  { kind: 'sink', id: 'go-header-set', language: 'go', framework: 'net/http', match: { type: 'call', callee: 'Set', receiver: 'Header' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / Header Injection (Header().Set)', severity: 'high', cwe: 'CWE-113',
            remediation: 'net/http rejects raw CR/LF in header values since Go 1.x, but still validate/allow-list user-controlled header values.' } },

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
  // Taint-recall PRD (80%): same `argIndex: 0` bug as Go's exec.Command,
  // found in this PRD's Tier 3 audit — the two-arg string-form shape this
  // entry's OWN name/remediation documents is `Process.Start("cmd.exe", "/c
  // " + tainted)`; arg 0 is always the literal shell/interpreter name, arg
  // 1 carries the tainted content. `argIndex: 0` could never fire on this
  // entry's own documented shape. Widened to `'all'`, gated by
  // `requireLiteralArg` (arg 0 must literally be a shell-invoking
  // interpreter) for the same reason as Go's fix: the safe, non-shell form
  // (`Process.Start(psi)` with a `ProcessStartInfo.ArgumentList`) is a
  // single-arg call that never matches this shape at all, but a
  // `Process.Start("convert", tainted)`-style two-arg call with a
  // NON-shell filename is a materially different risk this entry was never
  // scoped to model precisely.
  { kind: 'sink', id: 'cs-process-start',      language: 'cs', framework: 'stdlib',
    match: { type: 'call', callee: 'Start', requireLiteralArg: { index: 0, pattern: '^"cmd(?:\\.exe)?"$|^"(?:/bin/)?(?:sh|bash)"$' } }, argIndex: 'all',
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
  // ASP.NET Core's IHeaderDictionary.Add — a distinct real API from the
  // older Response.AddHeader (cs-response-addheader below); "Add" alone is
  // far too generic (List<T>.Add, Dictionary.Add, ...), hence the receiver
  // scope on "Headers".
  { kind: 'sink', id: 'cs-headers-add', language: 'cs', framework: 'aspnetcore', match: { type: 'call', callee: 'Add', receiver: 'Headers' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / Header Injection (IHeaderDictionary.Add)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip/validate CR/LF from any user-controlled value before using it as a header value.' } },
  // Taint-engine PRD P1 — found missing during the C# investigation: these
  // CWEs (601/79/113/611/90) could never be IR-TAINT-caught without a sink
  // entry, even with a perfect engine.
  { kind: 'sink', id: 'cs-redirect',           language: 'cs', framework: 'aspnet', match: { type: 'call', callee: 'Redirect' },        argIndex: 0,
    vuln: { name: 'Open Redirect (Controller.Redirect)', severity: 'medium', cwe: 'CWE-601',
            remediation: 'Whitelist destination URLs, or use LocalRedirect for same-app paths.' } },
  { kind: 'sink', id: 'cs-localredirect',      language: 'cs', framework: 'aspnet', match: { type: 'call', callee: 'LocalRedirect' },   argIndex: 0,
    vuln: { name: 'Open Redirect (Controller.LocalRedirect)', severity: 'medium', cwe: 'CWE-601',
            remediation: 'LocalRedirect rejects absolute URLs, but a crafted relative path can still redirect off-site via scheme-relative (//evil.com) input — validate the path.' } },
  { kind: 'sink', id: 'cs-response-write',     language: 'cs', framework: 'aspnet', match: { type: 'call', callee: 'Write', receiver: '^Response$' }, argIndex: 0,
    vuln: { name: 'Reflected XSS (Response.Write)', severity: 'high', cwe: 'CWE-79',
            remediation: 'HTML-encode with HttpUtility.HtmlEncode before writing user input to the response.' } },
  { kind: 'sink', id: 'cs-response-addheader', language: 'cs', framework: 'aspnet', match: { type: 'call', callee: 'AddHeader', receiver: '^Response$' }, argIndex: 1,
    vuln: { name: 'HTTP Response Splitting / Header Injection (Response.AddHeader)', severity: 'high', cwe: 'CWE-113',
            remediation: 'Strip CR/LF from header values, or use a framework API that rejects them automatically.' } },
  { kind: 'sink', id: 'cs-xmldoc-load',        language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'Load', receiver: '^(?:[Xx]ml[Dd]oc(?:ument)?|xmlDoc|doc)$' }, argIndex: 0,
    vuln: { name: 'XXE (XmlDocument.Load)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Set XmlResolver = null and DtdProcessing = DtdProcessing.Prohibit before loading untrusted XML.' } },
  { kind: 'sink', id: 'cs-xmldoc-loadxml',     language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'LoadXml' },         argIndex: 0,
    vuln: { name: 'XXE (XmlDocument.LoadXml)', severity: 'high', cwe: 'CWE-611',
            remediation: 'Set XmlResolver = null and DtdProcessing = DtdProcessing.Prohibit before parsing untrusted XML.' } },
  { kind: 'sink', id: 'cs-directorysearcher',  language: 'cs', framework: 'stdlib', match: { type: 'call', callee: 'DirectorySearcher' }, argIndex: 'all',
    vuln: { name: 'LDAP Injection (new DirectorySearcher with concatenated filter)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP special characters in filter components, or build the filter with a parameterized helper.' } },
  // Taint-recall PRD (80%): the idiomatic real-world shape is NOT
  // `new DirectorySearcher(taintedFilter)` (the entry above) — it's
  // `new DirectorySearcher(); searcher.Filter = tainted; searcher.FindAll()`,
  // a property assignment with no later call argument to check. Confirmed
  // directly against bench/cve-replay's own CVE-2020-1722-csharp-ldap
  // fixture that the constructor-argument entry above does not fire on it.
  // Uses matchMemberWriteSink (R13(a)'s el.innerHTML= mechanism) instead —
  // the assignment itself is the sink, receiver-scoped to variable names
  // containing "search" (DirectorySearcher's overwhelmingly common naming
  // convention) since "Filter" alone is too generic a property name.
  { kind: 'sink', id: 'cs-directorysearcher-filter', language: 'cs', framework: 'stdlib', match: { type: 'member', object: '_any_', prop: 'Filter', receiver: '[Ss]earch' }, argIndex: 'rhs',
    vuln: { name: 'LDAP Injection (DirectorySearcher.Filter assigned a concatenated value)', severity: 'high', cwe: 'CWE-90',
            remediation: 'Escape LDAP special characters in filter components, or build the filter with a parameterized helper.' } },

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
  // Taint-recall PRD (80%): `readText()` is Kotlin's generic
  // "read-everything" extension function — available on File, URL, and
  // several other receiver types — so these two entries collided on every
  // call regardless of which type actually received it: a File(...)
  // .readText() spuriously ALSO fired the SSRF entry and vice versa
  // (confirmed via CVE-2022-22965-kt-ssrf, which produced both a correct
  // SSRF finding and a spurious Path Traversal one). Receiver-scoped to
  // the actual chain prefix, same as every other terminal-segment-shift
  // fix in this PRD.
  { kind: 'sink', id: 'kt-file-readtext',      language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'readText', receiver: '^File$' }, argIndex: 0,
    vuln: { name: 'Path Traversal (File(name).readText)', severity: 'high', cwe: 'CWE-22',
            remediation: 'Canonicalize: `File(name).canonicalFile` and verify path stays inside an allow-listed base.' } },
  { kind: 'sink', id: 'kt-url-readtext',       language: 'kt', framework: 'stdlib', match: { type: 'call', callee: 'readText', receiver: '^URL$' }, argIndex: 'all',
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

  // ─── SOURCES (C / C++) ─────────────────────────────────────────────────────
  { kind: 'source', id: 'cpp-getenv',  language: 'cpp', framework: null, match: { type: 'call', callee: 'getenv'  }, label: 'getenv()',  provenance: 'env' },
  { kind: 'source', id: 'cpp-recv',    language: 'cpp', framework: null, match: { type: 'call', callee: 'recv'    }, label: 'recv()',    provenance: 'network' },
  { kind: 'source', id: 'cpp-recvfrom',language: 'cpp', framework: null, match: { type: 'call', callee: 'recvfrom'}, label: 'recvfrom()',provenance: 'network' },
  { kind: 'source', id: 'cpp-read',    language: 'cpp', framework: null, match: { type: 'call', callee: 'read'    }, label: 'read()',    provenance: 'file-read' },
  { kind: 'source', id: 'cpp-fread',   language: 'cpp', framework: null, match: { type: 'call', callee: 'fread'   }, label: 'fread()',   provenance: 'file-read' },
  { kind: 'source', id: 'cpp-fgets',   language: 'cpp', framework: null, match: { type: 'call', callee: 'fgets'   }, label: 'fgets()',   provenance: 'file-read' },
  { kind: 'source', id: 'cpp-gets',    language: 'cpp', framework: null, match: { type: 'call', callee: 'gets'    }, label: 'gets()',    provenance: 'stdin' },
  { kind: 'source', id: 'cpp-scanf',   language: 'cpp', framework: null, match: { type: 'call', callee: 'scanf'   }, label: 'scanf()',   provenance: 'stdin' },

  // ─── SINKS (C / C++) ───────────────────────────────────────────────────────
  { kind: 'sink', id: 'cpp-system', language: 'cpp', framework: null, match: { type: 'call', callee: 'system' }, argIndex: 0,
    vuln: { name: 'Command injection via system()', severity: 'critical', cwe: 'CWE-78', remediation: 'Use execve() with an argument vector instead of passing a shell string; never interpolate untrusted input into a command.' } },
  { kind: 'sink', id: 'cpp-popen', language: 'cpp', framework: null, match: { type: 'call', callee: 'popen' }, argIndex: 0,
    vuln: { name: 'Command injection via popen()', severity: 'critical', cwe: 'CWE-78', remediation: 'Use a pipe with execve() and an argument vector rather than a shell command string.' } },
  { kind: 'sink', id: 'cpp-execl', language: 'cpp', framework: null, match: { type: 'call', callee: 'execl' }, argIndex: 0,
    vuln: { name: 'Command injection via execl()', severity: 'critical', cwe: 'CWE-78', remediation: 'Validate the executable path against an allow-list; never build it from untrusted input.' } },
  { kind: 'sink', id: 'cpp-strcpy', language: 'cpp', framework: null, match: { type: 'call', callee: 'strcpy' }, argIndex: 1,
    vuln: { name: 'Buffer overflow via strcpy()', severity: 'high', cwe: 'CWE-120', remediation: 'Use strncpy() or snprintf() with an explicit destination size.' } },
  { kind: 'sink', id: 'cpp-strcat', language: 'cpp', framework: null, match: { type: 'call', callee: 'strcat' }, argIndex: 1,
    vuln: { name: 'Buffer overflow via strcat()', severity: 'high', cwe: 'CWE-120', remediation: 'Use strncat() or snprintf() with an explicit destination size.' } },
  { kind: 'sink', id: 'cpp-sprintf', language: 'cpp', framework: null, match: { type: 'call', callee: 'sprintf' }, argIndex: 'all',
    vuln: { name: 'Buffer overflow via sprintf()', severity: 'high', cwe: 'CWE-120', remediation: 'Use snprintf() with an explicit destination size.' } },
  { kind: 'sink', id: 'cpp-memcpy', language: 'cpp', framework: null, match: { type: 'call', callee: 'memcpy' }, argIndex: 2,
    vuln: { name: 'Buffer overflow via unchecked memcpy() length', severity: 'high', cwe: 'CWE-787', remediation: 'Bound the copy length by the destination size before copying.' } },
  { kind: 'sink', id: 'cpp-fopen', language: 'cpp', framework: null, match: { type: 'call', callee: 'fopen' }, argIndex: 0,
    vuln: { name: 'Path traversal via fopen()', severity: 'high', cwe: 'CWE-22', remediation: 'Canonicalise with realpath() and confirm the result stays within an allowed base directory.' } },
  { kind: 'sink', id: 'cpp-dlopen', language: 'cpp', framework: null, match: { type: 'call', callee: 'dlopen' }, argIndex: 0,
    vuln: { name: 'Untrusted library load via dlopen()', severity: 'critical', cwe: 'CWE-114', remediation: 'Load only from a fixed, trusted path; never build the library path from untrusted input.' } },

  // ─── SANITIZERS (C / C++) ──────────────────────────────────────────────────
  { kind: 'sanitizer', id: 'cpp-realpath', language: 'cpp', framework: null, match: { type: 'call', callee: 'realpath' }, effect: 'strip' },
  // Deliberately NOT listed as sanitizers: snprintf() and strncpy() bound the
  // COPY LENGTH, they do not touch the CONTENT. `snprintf(buf, n, "ls %s",
  // user); system(buf);` is still command injection — truncating the string
  // doesn't remove shell metacharacters. Nothing in the engine consumes
  // `effect` for a non-'sql' appliesTo today, so marking them 'strip' was
  // inert, but a future sanitizer consumer would silently turn this into a
  // false negative. realpath() stays: it genuinely canonicalises a path,
  // which is the property CWE-22 sinks care about.
];

// ─── Expanded sanitizer catalog (v0.65.0) ────────────────────────────────
// ~450 additional entries across JS / Python / Java / Ruby / PHP / Go.
// Lives in catalog-expanded.js to keep the diff reviewable. Merged into
// the main CATALOG below so the indexer treats them identically.
import { EXPANDED_SANITIZERS } from './catalog-expanded.js';
import { cppExtRe } from '../ir/parser-cpp.js';

// Language-scope guard. `file` is optional — when absent, behavior is
// unchanged from before this guard existed (every entry is allowed).
//
// Table-driven across all nine catalog languages (Phase 2). Extension sets
// MUST equal the ones ir/index.js uses to dispatch each parser. Narrower
// silently drops true positives; wider re-opens the cross-language leak that
// put a js DOM rule on Python files in Phase 1 (the `js-document-write` sink
// fired on `sys.stderr.write(...)` / `fh.write(...)` because callee matching
// is by bare name). phase2-scoping.test.js pins both directions against the
// real dispatch source in ir/index.js.
//
// A language with NO entry here stays permissive (matches unconditionally) —
// that makes this table additive and means it cannot regress a language
// before its mapping exists.
const _LANG_EXT = {
  js:   /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i,
  py:   /\.py$/i,
  cs:   /\.cs$/i,
  kt:   /\.kt$/i,
  go:   /\.go$/i,
  php:  /\.(?:php|phtml)$/i,
  rb:   /\.rb$/i,
  java: /\.java$/i,
};

// cpp delegates to cppExtRe() rather than duplicating a literal set, so it
// stays in lockstep with the parser dispatch in ir/index.js.
export function _languageExtensions() {
  return { ..._LANG_EXT, cpp: cppExtRe() };
}

// ─── Runtime families ─────────────────────────────────────────────────────
// A catalog `language` names a catalog *dialect*, not a file type. The two are
// usually the same thing, but not always: `java` and `kt` are two dialects over
// ONE runtime with ONE library surface. Kotlin code calls the Java standard
// library, JDBC, Hibernate and the servlet API constantly, and Java code can
// call Kotlin stdlib extensions — so scoping each dialect to its own extension
// alone silently deletes real detections in both directions.
//
// It did exactly that: after the per-language scoping landed, `.kt` files
// stopped matching 12 `java`-language sinks (executeUpdate, execute,
// prepareStatement, addBatch, createQuery, createSQLQuery, createNativeQuery,
// File, search, compile, sendRedirect, parse) and 4 `java` sources
// (getCookies, getInputStream, getReader, getProperty), and `.java` files
// stopped matching `readText`. A `.kt` file with
// `val q = req.getParameter("q"); stmt.executeUpdate(q)` went from 1 IR-TAINT
// finding to 0 — JDBC/Hibernate SQLi, servlet open-redirect and XXE going
// silent in Kotlin.
//
// So scoping is by FAMILY, not by dialect: an entry may match any file
// extension belonging to any dialect in its family. A dialect absent from this
// map is its own family (the common case). Keep this a declarative map rather
// than a conditional in `_languageAllowed` — the whole point is that the next
// person reading it sees "these dialects share a runtime" without having to
// reverse-engineer a special case. `phase2-scoping.test.js` pins the
// cross-family behaviour directly (executeUpdate on .kt, readText on .java);
// the extension-set equality test cannot catch a family error, because the
// extension sets were never wrong — the one-dialect-one-file-type assumption
// was.
const _LANG_FAMILY = {
  java: ['java', 'kt'],   // JVM
  kt:   ['java', 'kt'],   // JVM
};

// Extension regexes a given catalog language is allowed to match against.
export function _languageFamilyExtensions(language) {
  const all = _languageExtensions();
  const dialects = _LANG_FAMILY[language] || [language];
  return dialects.map(d => all[d]).filter(Boolean);
}

function _languageAllowed(entry, file) {
  if (!file) return true;
  const res = _languageFamilyExtensions(entry.language);
  if (!res.length) return true;       // unmapped language stays permissive
  return res.some(re => re.test(file));
}

// Receiver constraint (`match.receiver`), evaluated against the object chain
// of a member-call callee. Exists because callee matching is by bare NAME:
// `js-document-write` matches `write`, which is `document.write` (a real DOM
// XSS sink) but equally `process.stdout.write`, `fh.write`, `stream.write`.
// An entry that declares `receiver` only fires when some segment of its
// receiver chain matches — a bare `write(x)` with no receiver never fires.
//
// Segments are collected from both expression callees (member chains) and
// string callees (dotted names from the Go / C++ parsers).
function _receiverSegments(calleeExpr) {
  const segs = [];
  if (typeof calleeExpr === 'string') {
    const parts = calleeExpr.split('.');
    parts.pop();                       // drop the method name itself
    return parts;
  }
  if (!calleeExpr || calleeExpr.kind !== 'member') return segs;
  let cur = calleeExpr.object;
  let depth = 0;
  while (cur && depth++ < 8) {
    if (cur.kind === 'ident') { segs.push(cur.name); break; }
    if (cur.kind === 'member') { if (typeof cur.prop === 'string') segs.push(cur.prop); cur = cur.object; continue; }
    if (cur.kind === 'call') { cur = cur.callee; continue; }
    break;
  }
  return segs;
}
function _receiverAllowed(entry, calleeExpr) {
  const pat = entry.match && entry.match.receiver;
  // `receiverBase` (optional, additive) requires a SECOND, independent
  // segment match — e.g. `receiver` pins the property name (`headers`,
  // `args`) while `receiverBase` pins the object it hangs off (`request`,
  // `req`). Both are satisfied independently against the segment set (order
  // doesn't matter — `self.request.args.get()` has `request` in the chain
  // just like `request.args.get()` does), so a bare `args.get(...)` on an
  // unrelated local (`args = parse(); args.get("cmd")`) fails the base check
  // even though it still matches `receiver` on its own. Existing entries
  // that only set `receiver` are unaffected.
  const basePat = entry.match && entry.match.receiverBase;
  // `receiverExclude` (Taint-recall PRD 80%, cross-cutting engine fix
  // follow-up): the ONLY negative form — `receiver`/`receiverBase` can only
  // ever REQUIRE a match (see the R6 comment block below), which cannot
  // express "fire on a bare call, but not on THIS specific receiver."
  // `py-compile` needs exactly that: Python's dangerous `compile()` builtin
  // (`compile(source, filename, mode)`, equivalent to eval when followed by
  // exec) is called BARE, with no receiver — but the catalog's bare-name
  // matching (`_calleeIndexHits`, last-segment fallback) makes the SAME
  // catalog key also match `re.compile(pattern)`, an ordinary regex
  // compilation with no code-execution capability whatsoever. Confirmed via
  // this project's own self-scan (`scripts/_compliance_lib.py`) once the
  // receiver-taint engine fix (`_calleeReceiverTainted`) started correctly
  // propagating taint through `.get()`-style no-arg-adjacent calls on a
  // tainted dict/file-read chain — the sink itself was always mismatched,
  // the engine fix just gave taint a path to reach it. Unlike `receiver`/
  // `receiverBase`, which reject a BARE call outright (`segs.length === 0`
  // -> false) once either is set, `receiverExclude` is checked FIRST and
  // independently — a bare call (no segments) can never match an exclude
  // pattern, so `receiverExclude` alone never blocks the no-receiver case
  // it exists to preserve.
  const excludePat = entry.match && entry.match.receiverExclude;
  if (!pat && !basePat && !excludePat) return true;
  const segs = _receiverSegments(calleeExpr);
  if (excludePat && segs.some((s) => new RegExp(excludePat).test(String(s)))) return false;
  if (!pat && !basePat) return true;
  if (!segs.length) return false;      // bare `write(x)` — not a DOM call
  if (pat && !segs.some((s) => new RegExp(pat).test(String(s)))) return false;
  if (basePat && !segs.some((s) => new RegExp(basePat).test(String(s)))) return false;
  return true;
}

// PRD R6 (docs/DETECTION_GAP_REMEDIATION_PRD.md): a SECOND, independent
// receiver constraint — this one checked against the CHA-INFERRED TYPE of
// the receiver (computed by the caller, engine.js's `_receiverTypeFor`), not
// the textual receiver-chain segments `_receiverAllowed` above checks. The
// two are complementary: `_receiverAllowed`'s `match.receiver` regex can only
// ever see the SOURCE TEXT of the call site (`db.query` vs `cache.query` —
// both pass any receiver regex that doesn't special-case exact names); this
// gate can additionally use a resolved class/variable-type hint, so a bare
// `.query()` on something confidently NOT database-shaped can be excluded
// without hand-listing every possible non-DB variable name as a `receiver`
// exclusion (which `_receiverAllowed`'s regex form cannot express at all —
// it only expresses required patterns, never forbidden ones).
//
// Unknown != clean: a null/undefined receiverType (CHA could not resolve
// anything for this call site) NEVER suppresses a match — only a receiver
// type that was confidently resolved and does not appear in the entry's
// `receiverTypeIn` allow-list does. An entry with no `receiverTypeIn` is
// completely unaffected by this gate (returns true unconditionally), exactly
// like `_receiverAllowed` when neither `receiver` nor `receiverBase` is set.
//
// The vocabulary patterns are deliberately UNANCHORED (substring, case-
// insensitive). They were originally written `^(?:db|pool|conn…)$` back when
// the value reaching this gate could be a bare variable/field NAME. It no
// longer can — after the whole-branch-review fix, `_receiverTypeFor` only
// ever yields a real `classOfVar`-resolved CLASS name — and real class names
// are compound: `DatabaseConnection`, `PrismaClient`, `MySQLConnection` all
// failed the exact-anchored form and were silently suppressed, while only a
// class literally named `Db` survived. Substring matching is the honest
// shape for a vocabulary check over compound identifiers. `rb-erb-new`
// stays anchored (`^ERB$`) because it names ONE exact class, not a
// vocabulary. Over-matching here is the safe direction: it only ever
// *permits* a match the pattern layer already made.
function _receiverTypeAllowed(entry, receiverType) {
  const pats = entry.match && entry.match.receiverTypeIn;
  if (!pats || !pats.length) return true;
  if (!receiverType) return true;
  return pats.some((p) => new RegExp(p, 'i').test(String(receiverType)));
}

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
const GLOBAL_INDEX = new Map();
const ANNOTATION_INDEX = new Map();
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
  } else if (e.match.type === 'global' && e.match.name) {
    // Globals (PHP superglobals, rails params/session, JS location) were
    // indexed nowhere, so matchSource could never return one — every entry
    // declared this way was dead. Keyed by the bare name the source appears
    // under in code.
    const k = e.match.name;
    if (!GLOBAL_INDEX.has(k)) GLOBAL_INDEX.set(k, []);
    GLOBAL_INDEX.get(k).push(e);
  } else if (e.match.type === 'annotation' && e.match.name) {
    const k = e.match.name;
    if (!ANNOTATION_INDEX.has(k)) ANNOTATION_INDEX.set(k, []);
    ANNOTATION_INDEX.get(k).push(e);
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

// Round-1 fix follow-up: the PHP IR frontend (parser-php.js `_lowerExpr`)
// keeps the `$` sigil on variable idents — `$_GET['cmd']` lowers to
// `{ kind:'member', object:{ kind:'ident', name:'$_GET' }, prop:'cmd' }` —
// but the catalog's global entries are keyed without it (`_GET`). Every
// real PHP superglobal therefore missed GLOBAL_INDEX even after it was
// indexed, and the earlier synthetic-ident unit tests (which built their
// own sigil-free `{ kind:'ident', name:'_GET' }` nodes) could not catch
// this because they never exercised the real parser's output.
//
// Fixed by normalizing at the lookup, not by re-keying all five PHP
// entries with a `$`: the catalog's `match.name` is the single spot that
// already reads naturally for every other language (Ruby `params`, JS
// `location` carry no sigil), and a lookup-side strip keeps that uniform
// — a future language whose IR *does* prefix variables doesn't need its
// own catalog dialect. Ruby (`params`, `cookies`, `session`, `ENV`) and JS
// (`location`) were checked against their real parsers in this round and
// need no such stripping — confirmed no sigil or other prefix there.
function _globalKey(name) {
  return typeof name === 'string' && name.charCodeAt(0) === 36 /* '$' */ ? name.slice(1) : name;
}

// PRD R4a (docs/DETECTION_GAP_REMEDIATION_PRD.md): this module's own shape
// contract above documents two callee forms — 'name' (bare, matched by last
// segment) and 'name.foo' (matched by FULL PATH) — but both lookup sites
// used to reduce every callee to its last segment unconditionally, so an
// entry indexed under a full dotted key (catalog-expanded.js's `san()`
// helper builds many: 'Encode.forHtml', 'pg.escapeLiteral',
// 'filepath.Clean', ...) could never be retrieved. An entry lives under
// exactly one CALLEE_INDEX key (its own `match.callee`, dotted or bare), so
// looking up both the full path and the last segment and concatenating
// hits never double-counts — it just also finds entries the last-segment
// key alone was missing.
function _calleeIndexHits(calleeExpr) {
  let last = null;
  let full = null;
  if (typeof calleeExpr === 'string') {
    full = calleeExpr;
    last = calleeExpr.includes('.') ? calleeExpr.slice(calleeExpr.lastIndexOf('.') + 1) : calleeExpr;
  } else if (calleeExpr && calleeExpr.kind === 'member' && calleeExpr.prop) {
    last = calleeExpr.prop;
    if (calleeExpr.object && calleeExpr.object.kind === 'ident') full = `${calleeExpr.object.name}.${calleeExpr.prop}`;
  } else if (calleeExpr && calleeExpr.kind === 'ident') {
    last = calleeExpr.name || null;
  }
  const raw = [];
  if (full && full !== last) { const h = CALLEE_INDEX.get(full); if (h) raw.push(...h); }
  if (last) { const h = CALLEE_INDEX.get(last); if (h) raw.push(...h); }
  return raw;
}

export function matchSource(expr, file) {
  if (!expr) return null;
  // Member sources (req.query): the original path — unchanged.
  if (expr.kind === 'member' && expr.object?.kind === 'ident') {
    const raw = MEMBER_INDEX.get(`${expr.object.name}.${expr.prop}`);
    if (raw) {
      const hits = filterByProvenance(raw).filter(h => _languageAllowed(h, file));
      const s = hits.find(h => h.kind === 'source');
      if (s) return s;
    }
    // Global sources reached as a member read off the global itself:
    // $_GET['x'], params[:id]. Match on the member's root, not the pair.
    const rawGlobal = GLOBAL_INDEX.get(_globalKey(expr.object.name));
    if (rawGlobal) {
      const hits = filterByProvenance(rawGlobal).filter(h => _languageAllowed(h, file));
      const s = hits.find(h => h.kind === 'source');
      if (s) return s;
    }
  }
  // Bare-identifier globals: PHP superglobals, Rails params/session/cookies,
  // Ruby ENV, JS location — referenced directly without a member access.
  if (expr.kind === 'ident' && expr.name) {
    const raw = GLOBAL_INDEX.get(_globalKey(expr.name));
    if (raw) {
      const hits = filterByProvenance(raw).filter(h => _languageAllowed(h, file));
      const s = hits.find(h => h.kind === 'source');
      if (s) return s;
    }
  }
  // R3 (PRD §5): CALL sources (r.FormValue(), r.URL.Query(), c.QueryParam()).
  // matchSource previously handled only member reads, so Go's call-shaped
  // sources were never recognized at the assignment RHS. Match by callee last
  // segment (Go gives a dotted string; JS/Py a member/ident expr).
  if (expr.kind === 'call') {
    const raw = _calleeIndexHits(expr.callee);
    if (raw.length) {
      const hits = filterByProvenance(raw)
        .filter(h => _languageAllowed(h, file))
        .filter(h => _receiverAllowed(h, expr.callee));
      const s = hits.find(h => h.kind === 'source');
      if (s) return s;
    }
  }
  return null;
}

export function matchSinkOrSanitizer(calleeExpr, file, receiverType) {
  if (!calleeExpr) return null;
  const raw = _calleeIndexHits(calleeExpr);
  if (!raw.length) return null;
  const hits = filterByProvenance(raw)
    .filter(h => _languageAllowed(h, file))
    .filter(h => _receiverAllowed(h, calleeExpr))
    .filter(h => _receiverTypeAllowed(h, receiverType));
  return hits.length ? hits : null;
}

// PRD R13(a) (docs/DETECTION_GAP_REMEDIATION_PRD.md): three sink entries
// (js-innerHTML-assign, js-outerHTML-assign, react-dangerouslySetInnerHTML)
// have sat in MEMBER_INDEX under the object:'_any_' wildcard since they were
// added, but nothing ever queried MEMBER_INDEX for an ASSIGNMENT TARGET —
// matchSinkOrSanitizer only reads CALLEE_INDEX, and matchSource's MEMBER_INDEX
// lookups are for READS keyed by a SPECIFIC object name (e.g. "document.cookie"),
// not the "any receiver" wildcard a DOM sink needs. `targetPath` is the
// flattened LHS access-path string parser-js.js's lhsPath already produces
// for a member-expression assignment target (e.g. "el.innerHTML" for
// `el.innerHTML = x`) — this function extracts the property name and looks
// it up under the wildcard key the same way `object:'_any_'` entries are
// indexed (catalog.js's own indexing loop keys every entry by
// `${match.object}.${match.prop}` regardless of what object names are, so a
// wildcard entry lives under the literal key "_any_.<prop>").
export function matchMemberWriteSink(targetPath, file) {
  if (typeof targetPath !== 'string' || !targetPath.includes('.')) return null;
  const prop = targetPath.slice(targetPath.lastIndexOf('.') + 1);
  if (!prop) return null;
  const raw = MEMBER_INDEX.get(`_any_.${prop}`);
  if (!raw) return null;
  const hits = filterByProvenance(raw)
    .filter(h => _languageAllowed(h, file))
    .filter(h => h.kind === 'sink')
    // Taint-recall PRD (80%): optional `match.receiver`, same purpose as
    // `_receiverAllowed` for calls. innerHTML/outerHTML never needed this
    // (unambiguous DOM-only names); a property name like C#'s `Filter`
    // (DirectorySearcher.Filter — LDAP injection when set from a tainted
    // value) is common enough elsewhere (UI filters, LINQ, image
    // processing) that an unscoped match would be a real precision risk.
    // Segments are the dotted prefix before the final prop — same
    // "any segment matches" semantics as _receiverAllowed's string-callee
    // branch, just computed directly from targetPath since there's no
    // expression object here to walk.
    .filter(h => {
      const pat = h.match && h.match.receiver;
      if (!pat) return true;
      const segs = targetPath.slice(0, targetPath.length - prop.length - 1).split('.');
      return segs.some(s => new RegExp(pat).test(s));
    });
  return hits.length ? hits : null;
}

// R14(a): annotation/decorator-shaped framework sources (Spring @RequestParam,
// ASP.NET Core [FromQuery], NestJS @Query()). Unlike matchSource/matchSinkOrSanitizer,
// this does not consult an expression encountered while walking a CFG node —
// there is no CFG node for "this function's own declared parameter list." It is
// consulted once per function, against the IR's paramAnnotations side-channel,
// by engine.js's _unionAnnotationTaint before each analyzeFunction call.
export function matchAnnotationParams(paramAnnotations, file) {
  const tainted = new Set();
  if (!paramAnnotations || !paramAnnotations.length) return tainted;
  for (const pa of paramAnnotations) {
    const raw = ANNOTATION_INDEX.get(pa.decorator);
    if (!raw) continue;
    const hits = filterByProvenance(raw)
      .filter(h => _languageAllowed(h, file))
      .filter(h => h.kind === 'source');
    if (hits.length) {
      tainted.add(pa.name);
    }
  }
  return tainted;
}

// For tests and reflection.
export function _catalogSize() { return CATALOG.length; }
