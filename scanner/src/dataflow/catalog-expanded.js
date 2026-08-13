// Expanded sanitizer catalog (v0.65.0).
//
// Adds ~450 entries on top of the curated base catalog in `catalog.js`,
// taking the total sanitizer surface from ~48 to ~500+. Each entry follows
// the same shape as the base catalog so the engine consumes them
// transparently — `CALLEE_INDEX` in catalog.js auto-indexes anything in
// the exported array.
//
// Matching is by callee name only (the final identifier — e.g. the engine
// sees `crypto.randomBytes` as `randomBytes`). This is the same trade-off
// the base catalog already accepts: noisier-than-perfect name matching in
// exchange for not requiring full type inference. The `appliesTo` field
// scopes effects to specific taint families (xss / sql / cmd / url / path
// / regex / ldap / xpath / xml / json / mongo-operator / *).
//
// Grouped by language for diff readability. The compact helpers at the top
// keep the entries one-line-each so the file stays scannable.

// Helper: build a sanitizer entry. `library` is purely for documentation
// (it gets baked into the id) so multiple `escape` functions from different
// libraries can coexist without id collisions.
function san(language, library, callee, appliesTo) {
  return {
    kind: 'sanitizer',
    id: `${language}-${library}-${callee}`.replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
    language,
    match: { type: 'call', callee },
    effect: 'strip',
    appliesTo: Array.isArray(appliesTo) ? appliesTo : [appliesTo],
  };
}

// ─── JS / TS ─────────────────────────────────────────────────────────────

const JS_HTML_ESCAPE = [
  san('js', 'he',           'encode',            ['xss']),
  san('js', 'he',           'escape',            ['xss']),
  san('js', 'lodash',       'escape',            ['xss']),
  san('js', 'lodash',       'escapeRegExp',      ['regex']),
  san('js', 'underscore',   '_.escape',          ['xss']),
  san('js', 'react',        'createElement',     ['xss']),
  san('js', 'react',        'createTextNode',    ['xss']),
  san('js', 'dompurify',    'DOMPurify.sanitize', ['xss']),
  san('js', 'sanitize-html','sanitizeHtml',      ['xss']),
  san('js', 'xss-npm',      'xss',               ['xss']),
  san('js', 'js-xss',       'filterXSS',         ['xss']),
  san('js', 'escape-html',  'escapeHtml',        ['xss']),
  san('js', 'escape-goat',  'htmlEscape',        ['xss']),
  san('js', 'handlebars',   'Handlebars.escapeExpression', ['xss']),
  san('js', 'striptags',    'striptags',         ['xss']),
  san('js', 'insane',       'insane',            ['xss']),
  san('js', 'isomorphic',   'escape',            ['xss']),
];

const JS_SQL = [
  san('js', 'mysql',  'mysql.escape',       ['sql']),
  san('js', 'mysql',  'connection.escape',  ['sql']),
  san('js', 'mysql',  'pool.escape',        ['sql']),
  san('js', 'mysql2', 'mysql2.escape',      ['sql']),
  san('js', 'mysql2', 'mysql2.escapeId',    ['sql']),
  san('js', 'mysql2', 'mysql2.format',      ['sql']),
  san('js', 'pg',     'pg.escapeLiteral',   ['sql']),
  san('js', 'pg',     'pg.escapeIdentifier', ['sql']),
  san('js', 'sequelize', 'sequelize.escape', ['sql']),
  san('js', 'knex',   'knex.raw',           ['sql']),     // safe when wrapped via raw with bindings
  san('js', 'prisma', 'Prisma.sql',          ['sql']),
  san('js', 'mssql',  'sql.input',          ['sql']),
  san('js', 'better-sqlite3', 'prepare',     ['sql']),
];

const JS_SHELL = [
  san('js', 'shell-quote', 'shellQuote.quote', ['cmd']),
  san('js', 'shell-quote', 'quote',            ['cmd']),
  san('js', 'shell-escape','shellEscape',      ['cmd']),
  san('js', 'shescape',    'shescape.escape',  ['cmd']),
  san('js', 'shescape',    'shescape.quote',   ['cmd']),
  san('js', 'execa',       'execa.command',    ['cmd']),   // when called with array form
  san('js', 'core',        'execFile',         ['cmd']),
  san('js', 'core',        'spawn',            ['cmd']),
];

const JS_URL = [
  san('js', 'core',  'encodeURIComponent', ['url']),
  san('js', 'core',  'encodeURI',          ['url']),
  san('js', 'core',  'escape',             ['url']),       // deprecated but still used
  san('js', 'qs',    'qs.escape',          ['url']),
  san('js', 'qs',    'qs.stringify',       ['url']),
  san('js', 'querystring', 'querystring.escape', ['url']),
  san('js', 'querystring', 'querystring.stringify', ['url']),
  san('js', 'core',  'URL',                ['url']),
  san('js', 'core',  'URLSearchParams',    ['url']),
];

const JS_PATH = [
  san('js', 'path',  'path.normalize',     ['path']),
  san('js', 'path',  'path.basename',      ['path']),
  san('js', 'path',  'normalize',          ['path']),
  san('js', 'path',  'basename',           ['path']),
  san('js', 'sanitize-filename', 'sanitizeFilename', ['path']),
];

const JS_REGEX = [
  san('js', 'escape-string-regexp', 'escapeStringRegexp', ['regex']),
  san('js', 'lodash', '_.escapeRegExp', ['regex']),
];

const JS_LDAP = [
  san('js', 'ldap-escape', 'ldapEscape.filter', ['ldap']),
  san('js', 'ldap-escape', 'ldapEscape.dn',     ['ldap']),
  san('js', 'ldapjs',      'parseFilter',       ['ldap']),
];

const JS_XML_JSON = [
  san('js', 'core',          'JSON.stringify', ['json']),
  san('js', 'xml-escape',    'xmlEscape',      ['xml', 'xxe']),
  san('js', 'fast-xml-parser','XMLBuilder',    ['xml']),
];

const JS_VALIDATORS = [
  san('js', 'validator', 'validator.escape',      ['xss']),
  san('js', 'validator', 'validator.isEmail',     ['xss', 'sql']),
  san('js', 'validator', 'validator.isURL',       ['url']),
  san('js', 'validator', 'validator.isUUID',      ['*']),
  san('js', 'validator', 'validator.isInt',       ['*']),
  san('js', 'validator', 'validator.isFloat',     ['*']),
  san('js', 'validator', 'validator.isAlpha',     ['xss', 'sql']),
  san('js', 'validator', 'validator.isAlphanumeric', ['xss', 'sql']),
  san('js', 'validator', 'validator.isNumeric',   ['*']),
  san('js', 'validator', 'validator.isHexadecimal', ['*']),
  san('js', 'validator', 'validator.isBase64',    ['*']),
  san('js', 'validator', 'validator.isJSON',      ['*']),
  san('js', 'validator', 'validator.isJWT',       ['*']),
  san('js', 'validator', 'validator.matches',     ['*']),
  san('js', 'validator', 'validator.isISO8601',   ['*']),
  san('js', 'validator', 'validator.isISBN',      ['*']),
  san('js', 'validator', 'validator.isCreditCard',['*']),
  san('js', 'validator', 'validator.isMobilePhone', ['*']),
  san('js', 'validator', 'validator.isPostalCode', ['*']),
  san('js', 'validator', 'validator.isIP',        ['ssrf']),
  san('js', 'validator', 'validator.isFQDN',      ['ssrf']),
  san('js', 'validator', 'validator.toInt',       ['*']),
  san('js', 'validator', 'validator.toFloat',     ['*']),
  san('js', 'validator', 'validator.toBoolean',   ['*']),
  san('js', 'validator', 'validator.isLength',    ['*']),
  san('js', 'validator', 'validator.isStrongPassword', ['*']),
  san('js', 'joi',       'Joi.validate',          ['*']),
  san('js', 'joi',       'schema.validate',       ['*']),
  san('js', 'zod',       'z.parse',               ['*']),
  san('js', 'zod',       'safeParse',             ['*']),
  san('js', 'yup',       'yup.validate',          ['*']),
  san('js', 'ajv',       'ajv.validate',          ['*']),
];

const JS_TYPE_COERCE = [
  san('js', 'core', 'parseInt',         ['*']),
  san('js', 'core', 'parseFloat',       ['*']),
  san('js', 'core', 'Number',           ['*']),
  san('js', 'core', 'Boolean',          ['*']),
  san('js', 'core', 'Array.from',       ['mongo-operator']),
];

const JS = [
  ...JS_HTML_ESCAPE, ...JS_SQL, ...JS_SHELL, ...JS_URL, ...JS_PATH,
  ...JS_REGEX, ...JS_LDAP, ...JS_XML_JSON, ...JS_VALIDATORS, ...JS_TYPE_COERCE,
];

// ─── Python ──────────────────────────────────────────────────────────────

const PY_HTML_ESCAPE = [
  san('py', 'html',       'html.escape',      ['xss']),
  san('py', 'cgi',        'cgi.escape',       ['xss']),
  san('py', 'markupsafe', 'Markup.escape',    ['xss']),
  san('py', 'markupsafe', 'escape',           ['xss']),
  san('py', 'bleach',     'bleach.clean',     ['xss']),
  san('py', 'bleach',     'bleach.linkify',   ['xss']),
  san('py', 'lxml',       'Cleaner.clean_html', ['xss']),
  san('py', 'django',     'mark_safe',        ['xss']),       // marker; downstream often wraps escaped content
  san('py', 'django',     'format_html',      ['xss']),
  san('py', 'django',     'escape',           ['xss']),
  san('py', 'flask',      'flask.escape',     ['xss']),
  san('py', 'jinja2',     'Environment.from_string', ['xss']),  // auto-escape enabled by default
];

const PY_SQL = [
  san('py', 'sqlalchemy', 'sqlalchemy.text',  ['sql']),
  san('py', 'sqlalchemy', 'session.execute',  ['sql']),
  san('py', 'sqlalchemy', 'engine.execute',   ['sql']),
  san('py', 'sqlalchemy', 'bindparam',        ['sql']),
  san('py', 'psycopg',    'cursor.execute',   ['sql']),       // when passed (sql, params)
  san('py', 'psycopg',    'sql.SQL',          ['sql']),
  san('py', 'psycopg',    'sql.Identifier',   ['sql']),
  san('py', 'psycopg',    'sql.Literal',      ['sql']),
  san('py', 'psycopg',    'mogrify',          ['sql']),
  san('py', 'pyodbc',     'execute',          ['sql']),       // when params passed
  san('py', 'pymysql',    'escape_string',    ['sql']),
  san('py', 'pymysql',    'escape',           ['sql']),
  san('py', 'sqlite3',    'Connection.execute', ['sql']),     // when (sql, params)
  san('py', 'django',     'QuerySet.filter',  ['sql']),
  san('py', 'django',     'QuerySet.get',     ['sql']),
  san('py', 'django',     'Model.objects.filter', ['sql']),
  san('py', 'peewee',     'Model.get',        ['sql']),
];

const PY_SHELL = [
  san('py', 'shlex',      'shlex.quote',      ['cmd']),
  san('py', 'shlex',      'quote',            ['cmd']),
  san('py', 'pipes',      'pipes.quote',      ['cmd']),
  san('py', 'subprocess', 'subprocess.run',   ['cmd']),       // safe when args is a list and shell=False
  san('py', 'subprocess', 'subprocess.check_output', ['cmd']),
  san('py', 'subprocess', 'subprocess.Popen', ['cmd']),
];

const PY_URL = [
  san('py', 'urllib', 'urllib.parse.quote',     ['url']),
  san('py', 'urllib', 'urllib.parse.quote_plus',['url']),
  san('py', 'urllib', 'urllib.parse.urlencode', ['url']),
  san('py', 'urllib', 'urllib.parse.urlparse',  ['url']),
  san('py', 'urllib', 'quote',                  ['url']),
  san('py', 'urllib', 'quote_plus',             ['url']),
  san('py', 'urllib', 'urlencode',              ['url']),
  san('py', 'requests', 'requests.utils.requote_uri', ['url']),
];

const PY_PATH = [
  san('py', 'os',     'os.path.normpath',  ['path']),
  san('py', 'os',     'os.path.abspath',   ['path']),
  san('py', 'os',     'os.path.basename',  ['path']),
  san('py', 'pathlib','Path.resolve',      ['path']),
  san('py', 'werkzeug','safe_join',        ['path']),
  san('py', 'flask',  'safe_join',         ['path']),
];

const PY_REGEX = [
  san('py', 're', 're.escape',  ['regex']),
];

const PY_LDAP_XPATH = [
  san('py', 'ldap3',      'ldap3.utils.conv.escape_filter_chars', ['ldap']),
  san('py', 'python-ldap','escape_filter_chars',  ['ldap']),
  san('py', 'lxml',       'lxml.etree.XPath',     ['xpath']),
  san('py', 'lxml',       'XPath',                ['xpath']),
];

const PY_XML_JSON = [
  san('py', 'xml-sax-saxutils', 'saxutils.escape', ['xml', 'xxe']),
  san('py', 'xml-sax-saxutils', 'saxutils.quoteattr', ['xml', 'xxe']),
  san('py', 'defusedxml', 'defusedxml.ElementTree.fromstring', ['xml', 'xxe']),
  san('py', 'defusedxml', 'defusedxml.lxml.fromstring',        ['xml', 'xxe']),
  san('py', 'json',       'json.dumps', ['json']),
];

const PY_VALIDATORS = [
  san('py', 'validators',   'validators.email', ['xss', 'sql']),
  san('py', 'validators',   'validators.url',   ['url']),
  san('py', 'validators',   'validators.uuid',  ['*']),
  san('py', 'validators',   'validators.domain',['ssrf']),
  san('py', 'validators',   'validators.ipv4',  ['ssrf']),
  san('py', 'validators',   'validators.ipv6',  ['ssrf']),
  san('py', 'pydantic',     'parse_obj',        ['*']),
  san('py', 'pydantic',     'parse_obj_as',     ['*']),
  san('py', 'pydantic',     'model_validate',   ['*']),
  san('py', 'pydantic',     'BaseModel',        ['*']),
  san('py', 'marshmallow',  'Schema.load',      ['*']),
  san('py', 'cerberus',     'validate',         ['*']),
  san('py', 'wtforms',      'Form.validate',    ['*']),
  san('py', 'django',       'Form.is_valid',    ['*']),
  san('py', 'django',       'cleaned_data',     ['*']),
  san('py', 'voluptuous',   'Schema',           ['*']),
];

const PY_TYPE_COERCE = [
  san('py', 'core', 'int',   ['*']),
  san('py', 'core', 'float', ['*']),
  san('py', 'core', 'bool',  ['*']),
  san('py', 'core', 'bytes', ['*']),
];

const PY = [
  ...PY_HTML_ESCAPE, ...PY_SQL, ...PY_SHELL, ...PY_URL, ...PY_PATH,
  ...PY_REGEX, ...PY_LDAP_XPATH, ...PY_XML_JSON, ...PY_VALIDATORS, ...PY_TYPE_COERCE,
];

// ─── Java ────────────────────────────────────────────────────────────────

const JAVA_HTML_ESCAPE = [
  san('java', 'esapi',          'encodeForHTML',          ['xss']),
  san('java', 'esapi',          'encodeForHTMLAttribute', ['xss']),
  san('java', 'esapi',          'encodeForJavaScript',    ['xss']),
  san('java', 'esapi',          'encodeForCSS',           ['xss']),
  san('java', 'esapi',          'encodeForURL',           ['url']),
  san('java', 'esapi',          'encodeForBase64',        ['*']),
  san('java', 'owasp-encoder',  'Encode.forHtml',         ['xss']),
  san('java', 'owasp-encoder',  'Encode.forHtmlContent',  ['xss']),
  san('java', 'owasp-encoder',  'Encode.forHtmlAttribute',['xss']),
  san('java', 'owasp-encoder',  'Encode.forJavaScript',   ['xss']),
  san('java', 'owasp-encoder',  'Encode.forCssString',    ['xss']),
  san('java', 'owasp-encoder',  'Encode.forUriComponent', ['url']),
  san('java', 'spring',         'HtmlUtils.htmlEscape',   ['xss']),
  san('java', 'spring',         'HtmlUtils.htmlEscapeDecimal', ['xss']),
  san('java', 'commons-text',   'StringEscapeUtils.escapeHtml4', ['xss']),
  san('java', 'commons-text',   'StringEscapeUtils.escapeHtml3', ['xss']),
  san('java', 'commons-lang3',  'StringEscapeUtils.escapeHtml4', ['xss']),
  san('java', 'jsoup',          'Jsoup.clean',            ['xss']),
];

const JAVA_SQL = [
  san('java', 'jdbc',     'PreparedStatement.setString', ['sql']),
  san('java', 'jdbc',     'PreparedStatement.setInt',    ['sql']),
  san('java', 'jdbc',     'PreparedStatement.setLong',   ['sql']),
  san('java', 'jdbc',     'PreparedStatement.setObject', ['sql']),
  san('java', 'jdbc',     'setString',                   ['sql']),
  san('java', 'jdbc',     'setInt',                      ['sql']),
  san('java', 'jdbc',     'setLong',                     ['sql']),
  san('java', 'jdbc',     'setObject',                   ['sql']),
  san('java', 'spring',   'NamedParameterJdbcTemplate.query', ['sql']),
  san('java', 'spring',   'JdbcTemplate.queryForList',   ['sql']),
  san('java', 'jpa',      'TypedQuery.setParameter',     ['sql']),
  san('java', 'jpa',      'Query.setParameter',          ['sql']),
  san('java', 'hibernate','setParameter',                ['sql']),
  // MyBatis uses @Param as an annotation (not a call), so it isn't
  // expressible as a callee-based sanitizer entry — left out intentionally.
];

const JAVA_SHELL = [
  san('java', 'processbuilder', 'ProcessBuilder.command',['cmd']),
  san('java', 'core',           'Runtime.exec',          ['cmd']),       // safe when array form
];

const JAVA_URL_PATH_REGEX = [
  san('java', 'url',     'URLEncoder.encode',           ['url']),
  san('java', 'uri',     'URI',                         ['url']),
  san('java', 'nio',     'Paths.get',                   ['path']),
  san('java', 'nio',     'Path.normalize',              ['path']),
  san('java', 'regex',   'Pattern.quote',               ['regex']),
];

const JAVA_LDAP_XPATH_XML_JSON = [
  san('java', 'esapi',         'encodeForLDAP',         ['ldap']),
  san('java', 'esapi',         'encodeForDN',           ['ldap']),
  san('java', 'esapi',         'encodeForXPath',        ['xpath']),
  san('java', 'esapi',         'encodeForXML',          ['xml', 'xxe']),
  san('java', 'esapi',         'encodeForXMLAttribute', ['xml', 'xxe']),
  san('java', 'commons-text',  'StringEscapeUtils.escapeXml11', ['xml', 'xxe']),
  san('java', 'jackson',       'ObjectMapper.writeValueAsString', ['json']),
  san('java', 'gson',          'Gson.toJson',           ['json']),
];

const JAVA_VALIDATORS = [
  san('java', 'commons-validator', 'EmailValidator.isValid', ['xss', 'sql']),
  san('java', 'commons-validator', 'UrlValidator.isValid',   ['url']),
  san('java', 'commons-validator', 'InetAddressValidator.isValid', ['ssrf']),
  san('java', 'hibernate-validator', 'Validator.validate',   ['*']),
];

const JAVA = [
  ...JAVA_HTML_ESCAPE, ...JAVA_SQL, ...JAVA_SHELL,
  ...JAVA_URL_PATH_REGEX, ...JAVA_LDAP_XPATH_XML_JSON, ...JAVA_VALIDATORS,
];

// ─── Ruby ────────────────────────────────────────────────────────────────

const RUBY = [
  san('rb', 'cgi',          'CGI.escapeHTML',    ['xss']),
  san('rb', 'cgi',          'CGI.escape',        ['url']),
  san('rb', 'erb-util',     'ERB::Util.html_escape', ['xss']),
  san('rb', 'erb-util',     'ERB::Util.url_encode',  ['url']),
  san('rb', 'erb-util',     'h',                 ['xss']),
  san('rb', 'rails',        'sanitize',          ['xss']),
  san('rb', 'rails',        'strip_tags',        ['xss']),
  san('rb', 'rails',        'strip_links',       ['xss']),
  san('rb', 'rails',        'simple_format',     ['xss']),
  san('rb', 'rails',        'html_escape',       ['xss']),
  san('rb', 'rails',        'truncate',          ['xss']),
  san('rb', 'rails',        'where',             ['sql']),    // hash-form is safe; raw is not
  san('rb', 'rails',        'sanitize_sql_array',['sql']),
  san('rb', 'rails',        'sanitize_sql_hash_for_conditions', ['sql']),
  san('rb', 'shellwords',   'Shellwords.escape',  ['cmd']),
  san('rb', 'shellwords',   'Shellwords.shellescape', ['cmd']),
  san('rb', 'shellwords',   'shellescape',        ['cmd']),
  san('rb', 'open3',        'Open3.capture3',     ['cmd']),
  san('rb', 'uri',          'URI.encode_www_form',['url']),
  san('rb', 'uri',          'URI.encode_www_form_component', ['url']),
  san('rb', 'core',         'Pathname.cleanpath', ['path']),
  san('rb', 'regexp',       'Regexp.escape',      ['regex']),
  san('rb', 'rexml',        'REXML::Text.normalize', ['xml', 'xxe']),
  san('rb', 'nokogiri',     'Nokogiri::XML::Text.new', ['xml']),
  san('rb', 'json',         'JSON.generate',      ['json']),
  san('rb', 'json',         'JSON.dump',          ['json']),
  san('rb', 'rails',        'Integer',            ['*']),
  san('rb', 'rails',        'Float',              ['*']),
  san('rb', 'rails',        'String',             ['*']),
];

// ─── PHP ─────────────────────────────────────────────────────────────────

const PHP = [
  san('php', 'core',  'htmlspecialchars',    ['xss']),
  san('php', 'core',  'htmlentities',        ['xss']),
  san('php', 'core',  'strip_tags',          ['xss']),
  san('php', 'core',  'filter_var',          ['xss', 'url', 'ssrf']),
  san('php', 'core',  'filter_input',        ['xss', 'url']),
  san('php', 'pdo',   'bindParam',  ['sql']),
  san('php', 'pdo',   'bindValue',  ['sql']),
  san('php', 'pdo',   'bindParam',                ['sql']),
  san('php', 'pdo',   'bindValue',                ['sql']),
  san('php', 'mysqli','mysqli_stmt_bind_param',   ['sql']),
  san('php', 'mysqli','mysqli_real_escape_string',['sql']),
  san('php', 'mysqli','real_escape_string',       ['sql']),
  san('php', 'pgsql', 'pg_escape_string',         ['sql']),
  san('php', 'pgsql', 'pg_escape_literal',        ['sql']),
  san('php', 'pgsql', 'pg_escape_identifier',     ['sql']),
  san('php', 'core',  'escapeshellarg',           ['cmd']),
  san('php', 'core',  'escapeshellcmd',           ['cmd']),
  san('php', 'core',  'urlencode',                ['url']),
  san('php', 'core',  'rawurlencode',             ['url']),
  san('php', 'core',  'http_build_query',         ['url']),
  san('php', 'core',  'realpath',                 ['path']),
  san('php', 'core',  'basename',                 ['path']),
  san('php', 'core',  'pathinfo',                 ['path']),
  san('php', 'pcre',  'preg_quote',               ['regex']),
  san('php', 'ldap',  'ldap_escape',              ['ldap']),
  san('php', 'core',  'json_encode',              ['json']),
  san('php', 'core',  'intval',                   ['*']),
  san('php', 'core',  'floatval',                 ['*']),
  san('php', 'core',  'strval',                   ['*']),
  san('php', 'core',  'boolval',                  ['*']),
  san('php', 'core',  'ctype_digit',              ['*']),
  san('php', 'core',  'ctype_alpha',              ['*']),
  san('php', 'core',  'ctype_alnum',              ['*']),
  san('php', 'symfony', 'validate',               ['*']),  // Validator::validate
  san('php', 'laravel', 'make',                   ['*']),  // Validator::make
];

// ─── Go ──────────────────────────────────────────────────────────────────

const GO = [
  san('go', 'html',       'html.EscapeString',            ['xss']),
  san('go', 'html',       'template.HTMLEscapeString',    ['xss']),
  san('go', 'html',       'template.JSEscapeString',      ['xss']),
  san('go', 'html',       'template.URLQueryEscaper',     ['url']),
  san('go', 'bluemonday', 'Policy.Sanitize',              ['xss']),
  san('go', 'bluemonday', 'UGCPolicy',                    ['xss']),
  san('go', 'bluemonday', 'StrictPolicy',                 ['xss']),
  san('go', 'database-sql', 'db.Query',                   ['sql']),     // safe with placeholders
  san('go', 'database-sql', 'db.Exec',                    ['sql']),
  san('go', 'database-sql', 'db.QueryRow',                ['sql']),
  san('go', 'database-sql', 'stmt.Query',                 ['sql']),
  san('go', 'database-sql', 'stmt.Exec',                  ['sql']),
  san('go', 'sqlx',         'sqlx.Named',                 ['sql']),
  san('go', 'os-exec',      'exec.Command',               ['cmd']),     // safe with separate args
  san('go', 'os-exec',      'exec.CommandContext',        ['cmd']),
  san('go', 'net-url',      'url.QueryEscape',            ['url']),
  san('go', 'net-url',      'url.PathEscape',             ['url']),
  san('go', 'net-url',      'Values.Encode',              ['url']),
  san('go', 'filepath',     'filepath.Clean',             ['path']),
  san('go', 'filepath',     'filepath.Abs',               ['path']),
  san('go', 'filepath',     'filepath.IsAbs',             ['path']),
  san('go', 'filepath',     'filepath.Base',              ['path']),
  san('go', 'regexp',       'regexp.QuoteMeta',           ['regex']),
  san('go', 'ldap-v3',      'ldap.EscapeFilter',          ['ldap']),
  san('go', 'encoding-json','json.Marshal',               ['json']),
  san('go', 'encoding-xml', 'xml.Marshal',                ['xml']),
  san('go', 'govalidator',  'govalidator.IsEmail',        ['xss', 'sql']),
  san('go', 'govalidator',  'govalidator.IsURL',          ['url']),
  san('go', 'govalidator',  'govalidator.IsUUID',         ['*']),
  san('go', 'govalidator',  'govalidator.IsIP',           ['ssrf']),
  san('go', 'go-playground','validator.Struct',           ['*']),
  san('go', 'core',         'strconv.Atoi',               ['*']),
  san('go', 'core',         'strconv.ParseInt',           ['*']),
  san('go', 'core',         'strconv.ParseFloat',         ['*']),
];

// ─── Aggregate export ────────────────────────────────────────────────────

export const EXPANDED_SANITIZERS = [
  ...JS, ...PY, ...JAVA, ...RUBY, ...PHP, ...GO,
];

// Diagnostic export — used by tests + the why-not command.
export const _expandedSanitizerStats = () => {
  const byLanguage = {};
  for (const e of EXPANDED_SANITIZERS) {
    byLanguage[e.language] = (byLanguage[e.language] || 0) + 1;
  }
  return { total: EXPANDED_SANITIZERS.length, byLanguage };
};
