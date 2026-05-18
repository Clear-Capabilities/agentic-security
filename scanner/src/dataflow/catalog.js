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
  // Express / common Node HTTP shapes.
  { kind: 'source', id: 'js-req-body',     language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'body'    }, label: 'req.body' },
  { kind: 'source', id: 'js-req-query',    language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'query'   }, label: 'req.query' },
  { kind: 'source', id: 'js-req-params',   language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'params'  }, label: 'req.params' },
  { kind: 'source', id: 'js-req-headers',  language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'headers' }, label: 'req.headers' },
  { kind: 'source', id: 'js-req-cookies',  language: 'js', framework: 'express', match: { type: 'member', object: 'req',     prop: 'cookies' }, label: 'req.cookies' },
  { kind: 'source', id: 'js-request-body', language: 'js', framework: 'express', match: { type: 'member', object: 'request', prop: 'body'    }, label: 'request.body' },
  { kind: 'source', id: 'js-ctx-request',  language: 'js', framework: 'koa',     match: { type: 'member', object: 'ctx',     prop: 'request' }, label: 'ctx.request' },
  // Browser DOM-derived (XSS sources).
  { kind: 'source', id: 'js-location',     language: 'js', framework: 'dom', match: { type: 'global', name: 'location' }, label: 'window.location' },
  { kind: 'source', id: 'js-doc-cookie',   language: 'js', framework: 'dom', match: { type: 'member', object: 'document', prop: 'cookie' }, label: 'document.cookie' },
  { kind: 'source', id: 'js-loc-search',   language: 'js', framework: 'dom', match: { type: 'member', object: 'location', prop: 'search' }, label: 'location.search' },
  { kind: 'source', id: 'js-loc-hash',     language: 'js', framework: 'dom', match: { type: 'member', object: 'location', prop: 'hash'   }, label: 'location.hash' },
  // process.env is a fixed but partially attacker-controllable surface for some apps.
  { kind: 'source', id: 'js-process-env',  language: 'js', framework: 'node', match: { type: 'member', object: 'process', prop: 'env' }, label: 'process.env' },

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

  // ─── SOURCES (Ruby — Rails / Sinatra) ─────────────────────────────────────
  { kind: 'source', id: 'rb-rails-params',  language: 'rb', framework: 'rails', match: { type: 'global', name: 'params' }, label: 'params (Rails)' },
  { kind: 'source', id: 'rb-rails-cookies', language: 'rb', framework: 'rails', match: { type: 'global', name: 'cookies' }, label: 'cookies (Rails)' },
  { kind: 'source', id: 'rb-rails-session', language: 'rb', framework: 'rails', match: { type: 'global', name: 'session' }, label: 'session (Rails)' },
  { kind: 'source', id: 'rb-env',           language: 'rb', framework: 'stdlib',match: { type: 'global', name: 'ENV' },     label: 'ENV (Ruby)' },

  // ─── SOURCES (PHP) ────────────────────────────────────────────────────────
  { kind: 'source', id: 'php-request',  language: 'php', framework: 'core', match: { type: 'global', name: '_REQUEST' }, label: '$_REQUEST' },
  { kind: 'source', id: 'php-get',      language: 'php', framework: 'core', match: { type: 'global', name: '_GET' },     label: '$_GET' },
  { kind: 'source', id: 'php-post',     language: 'php', framework: 'core', match: { type: 'global', name: '_POST' },    label: '$_POST' },
  { kind: 'source', id: 'php-cookie',   language: 'php', framework: 'core', match: { type: 'global', name: '_COOKIE' },  label: '$_COOKIE' },
  { kind: 'source', id: 'php-server',   language: 'php', framework: 'core', match: { type: 'global', name: '_SERVER' },  label: '$_SERVER' },

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
];

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

const OFFICIAL_ONLY = process.env.AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY === '1';

// Pre-build lookups: callee name → entry. Filter by provenance.
const CALLEE_INDEX = new Map();
const MEMBER_INDEX = new Map();
for (const e of CATALOG) {
  if (!e.match) continue;
  if (OFFICIAL_ONLY && e.source !== 'official') continue;
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

export function matchSource(memberExpr) {
  // memberExpr is exprDesc: { kind: 'member', object: {kind:'ident',name}, prop }
  if (!memberExpr || memberExpr.kind !== 'member') return null;
  if (memberExpr.object?.kind !== 'ident') return null;
  const k = `${memberExpr.object.name}.${memberExpr.prop}`;
  const hits = MEMBER_INDEX.get(k);
  if (!hits) return null;
  return hits.find(h => h.kind === 'source') || null;
}

export function matchSinkOrSanitizer(calleeExpr) {
  if (!calleeExpr) return null;
  let calleeName = null;
  if (calleeExpr.kind === 'ident') calleeName = calleeExpr.name;
  else if (calleeExpr.kind === 'member') calleeName = calleeExpr.prop;
  if (!calleeName) return null;
  return CALLEE_INDEX.get(calleeName) || null;
}

// For tests and reflection.
export function _catalogSize() { return CATALOG.length; }
