// Haskell library/API model registry (HS-003, shared by HS-004..HS-006).
//
// One declarative table of the library surfaces the Haskell analysers understand: where untrusted
// data comes from, which calls are dangerous in which CWE family, and which calls legitimately
// neutralise which family. The taint catalog (`dataflow/catalog-haskell.js`) is GENERATED from this
// table, so there is no second list to drift.
//
// Identity, not names. Every entry is keyed by the defining MODULE plus the function name
// (`System.Process.callCommand`). The Haskell IR resolves a call through the file's imports to the
// qualified name before the catalog sees it, so a user's own `execute` becomes `Main.execute` and
// never matches `Database.PostgreSQL.Simple.execute`. A wildcard import that the registry itself
// proves is the only provider of a name is resolved through `qualifyAmbiguous` and recorded as
// uncertain, never silently trusted.
//
// Version honesty. `tested` lists the package versions the model was written against (the exact
// library versions in each model fixture). A model applies to every version of the package unless
// `since`/`until` narrow it; an unrecognised version is reported by `modelStatus`, not assumed safe.
//
// Not modelled on purpose: type correctness, `Text`/`ByteString`/`newtype` wrappers, JSON decoding
// and `Safe Haskell` never sanitize (nothing here treats them as a sanitizer), and nothing here
// claims a vulnerability class for an API whose behaviour is not described.

export const HS_MODEL_VERSION = 'haskell-models/1';

const E = (module, names) => names.map((name) => ({ module, name }));
const q = (module, name) => `${module}.${name}`;

// ── packages ────────────────────────────────────────────────────────────────
export const HS_PACKAGES = Object.freeze({
  base: { modules: ['Prelude', 'System.IO', 'System.Environment', 'System.Exit', 'Data.List', 'Data.Char', 'Data.Maybe', 'Control.Monad'], tested: ['4.18', '4.19'] },
  process: { modules: ['System.Process', 'System.Process.Typed'], tested: ['1.6.17', '1.6.18'] },
  directory: { modules: ['System.Directory'], tested: ['1.3.8'] },
  filepath: { modules: ['System.FilePath', 'System.FilePath.Posix'], tested: ['1.4.100'] },
  'postgresql-simple': { modules: ['Database.PostgreSQL.Simple', 'Database.PostgreSQL.Simple.Types', 'Database.PostgreSQL.Simple.ToField'], tested: ['0.6.5', '0.7.0'] },
  'mysql-simple': { modules: ['Database.MySQL.Simple'], tested: ['0.4.9'] },
  'sqlite-simple': { modules: ['Database.SQLite.Simple'], tested: ['0.4.18'] },
  persistent: { modules: ['Database.Persist.Sql'], tested: ['2.14'] },
  scotty: { modules: ['Web.Scotty', 'Web.Scotty.Trans'], tested: ['0.12', '0.20'] },
  wai: { modules: ['Network.Wai'], tested: ['3.2'] },
  yesod: { modules: ['Yesod.Core', 'Yesod'], tested: ['1.6'] },
  'http-client': { modules: ['Network.HTTP.Client', 'Network.HTTP.Client.TLS'], tested: ['0.7'] },
  'http-conduit': { modules: ['Network.HTTP.Simple', 'Network.HTTP.Conduit'], tested: ['2.3'] },
  wreq: { modules: ['Network.Wreq', 'Network.Wreq.Session'], tested: ['0.5'] },
  'blaze-html': { modules: ['Text.Blaze', 'Text.Blaze.Html', 'Text.Blaze.Html5', 'Text.Blaze.Internal'], tested: ['0.9'] },
  lucid: { modules: ['Lucid', 'Lucid.Base'], tested: ['2.11'] },
  shakespeare: { modules: ['Text.Hamlet', 'Text.Shakespeare'], tested: ['2.0'] },
  text: { modules: ['Data.Text', 'Data.Text.IO', 'Data.Text.Lazy', 'Data.Text.Lazy.IO', 'Data.Text.Encoding'], tested: ['2.0'] },
  cryptonite: { modules: ['Crypto.Hash', 'Crypto.Cipher.Types', 'Crypto.Random', 'Crypto.KDF.PBKDF2', 'Crypto.Hash.MD5', 'Crypto.Hash.SHA1', 'Crypto.Hash.SHA256', 'Crypto.Hash.SHA512', 'Crypto.Cipher.ChaChaPoly1305'], tested: ['0.30'] },
  random: { modules: ['System.Random'], tested: ['1.2'] },
  hxt: { modules: ['Text.XML.HXT.Core'], tested: ['9.3'] },
  bytestring: { modules: ['Data.ByteString', 'Data.ByteString.Char8', 'Data.ByteString.Lazy'], tested: ['0.11', '0.12'] },
});

// ── sources ─────────────────────────────────────────────────────────────────
// provenance follows the existing taxonomy: http-body | url-param | path-param | header | cookie | env | cli | file-read | stdin | network
const SRC = [];
const src = (module, names, provenance, label, extra = {}) => { for (const e of E(module, names)) SRC.push({ ...e, provenance, label: `${label}${names.length > 1 ? '' : ''}`, package: extra.package, framework: extra.framework || null }); };

src('Prelude', ['getLine', 'getContents', 'readLn', 'interact'], 'stdin', 'standard input', { package: 'base' });
src('System.IO', ['getLine', 'getContents', 'hGetLine', 'hGetContents', 'hGetChar'], 'stdin', 'handle input', { package: 'base' });
src('Data.Text.IO', ['getLine', 'getContents', 'hGetLine', 'hGetContents', 'interact'], 'stdin', 'text input', { package: 'text' });
src('Data.ByteString', ['getLine', 'getContents', 'hGetLine', 'hGetContents'], 'stdin', 'bytes input', { package: 'bytestring' });
src('Data.ByteString.Char8', ['getLine', 'getContents', 'hGetLine', 'hGetContents'], 'stdin', 'bytes input', { package: 'bytestring' });
src('System.Environment', ['getArgs'], 'cli', 'command-line argument', { package: 'base' });
src('System.Environment', ['getEnv', 'lookupEnv', 'getEnvironment'], 'env', 'environment variable', { package: 'base' });
src('Prelude', ['readFile'], 'file-read', 'file content', { package: 'base' });
src('System.IO', ['readFile'], 'file-read', 'file content', { package: 'base' });
src('Data.Text.IO', ['readFile'], 'file-read', 'file content', { package: 'text' });
src('Data.ByteString', ['readFile'], 'file-read', 'file content', { package: 'bytestring' });
src('Data.ByteString.Lazy', ['readFile'], 'file-read', 'file content', { package: 'bytestring' });
// HTTP: scotty
src('Web.Scotty', ['param', 'params', 'queryParam', 'queryParams', 'captureParam', 'captureParams', 'formParam', 'formParams', 'pathParam'], 'url-param', 'scotty request parameter', { package: 'scotty', framework: 'scotty' });
src('Web.Scotty', ['header', 'headers'], 'header', 'scotty request header', { package: 'scotty', framework: 'scotty' });
src('Web.Scotty', ['body', 'jsonData', 'files'], 'http-body', 'scotty request body', { package: 'scotty', framework: 'scotty' });
src('Web.Scotty.Trans', ['param', 'params', 'queryParam', 'queryParams', 'captureParam', 'captureParams', 'formParam', 'formParams', 'pathParam'], 'url-param', 'scotty request parameter', { package: 'scotty', framework: 'scotty' });
src('Web.Scotty.Trans', ['header', 'headers'], 'header', 'scotty request header', { package: 'scotty', framework: 'scotty' });
src('Web.Scotty.Trans', ['body', 'jsonData', 'files'], 'http-body', 'scotty request body', { package: 'scotty', framework: 'scotty' });
// HTTP: WAI
src('Network.Wai', ['queryString', 'rawQueryString', 'rawPathInfo', 'pathInfo'], 'url-param', 'WAI request target', { package: 'wai', framework: 'wai' });
src('Network.Wai', ['requestHeaders', 'requestHeaderHost', 'requestHeaderReferer', 'requestHeaderUserAgent'], 'header', 'WAI request header', { package: 'wai', framework: 'wai' });
src('Network.Wai', ['getRequestBodyChunk', 'strictRequestBody', 'lazyRequestBody', 'requestBody'], 'http-body', 'WAI request body', { package: 'wai', framework: 'wai' });
// HTTP: yesod
src('Yesod.Core', ['lookupGetParam', 'lookupGetParams', 'lookupPostParam', 'lookupPostParams', 'runInputGet', 'runInputPost', 'lookupHeader', 'lookupCookie', 'lookupBearerAuth'], 'url-param', 'yesod request input', { package: 'yesod', framework: 'yesod' });
src('Yesod', ['lookupGetParam', 'lookupGetParams', 'lookupPostParam', 'lookupPostParams', 'runInputGet', 'runInputPost', 'lookupHeader', 'lookupCookie', 'lookupBearerAuth'], 'url-param', 'yesod request input', { package: 'yesod', framework: 'yesod' });
// HTTP responses are untrusted data too when they come back from a remote service the app calls
src('Network.HTTP.Simple', ['getResponseBody'], 'network', 'remote HTTP response', { package: 'http-conduit' });
src('Network.HTTP.Client', ['responseBody'], 'network', 'remote HTTP response', { package: 'http-client' });

// ── sinks ───────────────────────────────────────────────────────────────────
// family: the taint family the existing engine already uses (cmd | sql | path | url | xss)
const SINK = [];
const sink = (module, names, def) => { for (const e of E(module, names)) SINK.push({ ...e, ...def }); };

// CWE-78. A shell string is parsed by /bin/sh; an executable path is not, but a tainted one is still arbitrary execution.
sink('System.Process', ['callCommand', 'system', 'rawSystem'], { family: 'cmd', cwe: 'CWE-78', severity: 'critical', argIndex: 0, shell: true, package: 'process', vuln: 'OS Command Injection (shell string)', remediation: 'Do not build a shell string from input. Use `callProcess "prog" [args]` (no shell) with a fixed program, and validate each argument.' });
sink('System.Process', ['shell'], { family: 'cmd', cwe: 'CWE-78', severity: 'critical', argIndex: 0, shell: true, package: 'process', vuln: 'OS Command Injection (shell command spec)', remediation: 'Use `proc` with a fixed program and an argument list instead of `shell`.' });
sink('System.Process', ['spawnCommand', 'readCreateProcess'], { family: 'cmd', cwe: 'CWE-78', severity: 'critical', argIndex: 0, shell: true, package: 'process', vuln: 'OS Command Injection (spawnCommand)', remediation: 'Use `spawnProcess "prog" [args]` with a fixed program.' });
sink('System.Process', ['callProcess', 'spawnProcess', 'readProcess', 'readProcessWithExitCode', 'proc', 'createProcess'], { family: 'cmd', cwe: 'CWE-78', severity: 'high', argIndex: 0, shell: false, package: 'process', vuln: 'OS Command Injection (attacker-chosen executable)', remediation: 'The program path must be a fixed value or chosen from an allow-list.' });
// Argument/option injection: shell-free, so no shell parsing, but an attacker still steers the program (`--output=/etc/x`, `-e`).
sink('System.Process', ['callProcess', 'spawnProcess', 'proc'], { family: 'cmd', cwe: 'CWE-88', severity: 'medium', argIndex: 1, shell: false, argv: true, package: 'process', vuln: 'Argument Injection (process arguments)', remediation: 'Shell-free argument lists prevent shell parsing but not option injection: validate each argument against an allow-list and insert `--` before untrusted values.' });
sink('System.Process', ['readProcess', 'readProcessWithExitCode'], { family: 'cmd', cwe: 'CWE-88', severity: 'medium', argIndex: 1, shell: false, argv: true, package: 'process', vuln: 'Argument Injection (process arguments)', remediation: 'Validate each argument against an allow-list and insert `--` before untrusted values.' });
sink('System.Process.Typed', ['shell'], { family: 'cmd', cwe: 'CWE-78', severity: 'critical', argIndex: 0, shell: true, package: 'process', vuln: 'OS Command Injection (typed-process shell)', remediation: 'Use `proc` with a fixed program and an argument list.' });

// CWE-22. Path-taking operations.
const PATH_FN = ['readFile', 'writeFile', 'appendFile', 'openFile', 'withFile', 'readFile\'', 'openBinaryFile', 'withBinaryFile'];
sink('Prelude', ['readFile', 'writeFile', 'appendFile'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 0, package: 'base', vuln: 'Path Traversal', remediation: 'Resolve the path with `canonicalizePath` and confirm it stays under an allowed base directory, or accept only a bare file name (`takeFileName p == p`).' });
sink('System.IO', ['openFile', 'withFile', 'openBinaryFile', 'withBinaryFile', 'readFile', 'writeFile', 'appendFile'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 0, package: 'base', vuln: 'Path Traversal', remediation: 'Resolve the path with `canonicalizePath` and confirm it stays under an allowed base directory.' });
sink('Data.Text.IO', ['readFile', 'writeFile', 'appendFile'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 0, package: 'text', vuln: 'Path Traversal', remediation: 'Confirm the canonical path stays under an allowed base directory.' });
sink('Data.ByteString', ['readFile', 'writeFile', 'appendFile'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 0, package: 'bytestring', vuln: 'Path Traversal', remediation: 'Confirm the canonical path stays under an allowed base directory.' });
sink('Data.ByteString.Lazy', ['readFile', 'writeFile', 'appendFile'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 0, package: 'bytestring', vuln: 'Path Traversal', remediation: 'Confirm the canonical path stays under an allowed base directory.' });
sink('System.Directory', ['removeFile', 'removeDirectory', 'removeDirectoryRecursive', 'removePathForcibly', 'createDirectory', 'createDirectoryIfMissing', 'listDirectory', 'getDirectoryContents', 'doesFileExist', 'doesDirectoryExist', 'getPermissions', 'setPermissions', 'setCurrentDirectory', 'withCurrentDirectory', 'getFileSize'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 0, package: 'directory', vuln: 'Path Traversal (filesystem operation)', remediation: 'Confirm the canonical path stays under an allowed base directory before using it.' });
sink('System.Directory', ['copyFile', 'renameFile', 'renamePath', 'renameDirectory', 'copyFileWithMetadata'], { family: 'path', cwe: 'CWE-22', severity: 'high', argIndex: 'all', package: 'directory', vuln: 'Path Traversal (copy/rename)', remediation: 'Confirm both canonical paths stay under an allowed base directory.' });
void PATH_FN;

// CWE-89. The query TEXT is the sink; parameters bound through `Only`/`(a, b)` are the safe form.
const SQL = { family: 'sql', cwe: 'CWE-89', severity: 'critical', argIndex: 1, vuln: 'SQL Injection (query text)', remediation: 'Pass values as parameters: `query conn "SELECT … WHERE id = ?" (Only x)`. Never concatenate input into the query text.' };
sink('Database.PostgreSQL.Simple', ['query', 'execute', 'executeMany', 'returning', 'fold', 'forEach'], { ...SQL, package: 'postgresql-simple' });
sink('Database.PostgreSQL.Simple', ['query_', 'execute_', 'fold_', 'forEach_'], { ...SQL, package: 'postgresql-simple' });
sink('Database.PostgreSQL.Simple.Types', ['Query'], { ...SQL, argIndex: 0, package: 'postgresql-simple', vuln: 'SQL Injection (Query constructed from text)' });
sink('Database.MySQL.Simple', ['query', 'execute', 'executeMany', 'query_', 'execute_'], { ...SQL, package: 'mysql-simple' });
sink('Database.SQLite.Simple', ['query', 'execute', 'executeMany', 'query_', 'execute_', 'executeNamed', 'queryNamed', 'fold', 'fold_'], { ...SQL, package: 'sqlite-simple' });
sink('Database.Persist.Sql', ['rawSql', 'rawExecute', 'rawQuery'], { ...SQL, argIndex: 0, package: 'persistent', vuln: 'SQL Injection (raw SQL text)' });

// CWE-918. The URL (or request spec built from it) is the sink.
const SSRF = { family: 'url', cwe: 'CWE-918', severity: 'high', argIndex: 0, vuln: 'Server-Side Request Forgery', remediation: 'Parse the URL, require an allow-listed scheme and host, and reject private or link-local addresses after DNS resolution.' };
sink('Network.HTTP.Simple', ['httpBS', 'httpLBS', 'httpJSON', 'httpNoBody', 'httpSink', 'parseRequest', 'parseRequest_'], { ...SSRF, package: 'http-conduit' });
sink('Network.HTTP.Conduit', ['simpleHttp', 'parseRequest', 'parseUrlThrow', 'parseRequest_', 'httpLbs'], { ...SSRF, package: 'http-conduit' });
sink('Network.HTTP.Client', ['parseRequest', 'parseUrlThrow', 'parseRequest_', 'requestFromURI'], { ...SSRF, package: 'http-client' });
sink('Network.HTTP.Client', ['httpLbs', 'httpNoBody', 'withResponse', 'responseOpen'], { ...SSRF, argIndex: 0, package: 'http-client' });
// wreq: where the URL sits depends on the function. `get url`, but `getWith opts url` (the first argument is the Options, not the target),
// `customMethod method url`, `customMethodWith method opts url`; the Session forms take the session before the URL.
sink('Network.Wreq', ['get', 'post', 'put', 'delete', 'head', 'options', 'patch'], { ...SSRF, argIndex: 0, package: 'wreq' });
sink('Network.Wreq', ['getWith', 'postWith', 'putWith', 'deleteWith', 'headWith', 'optionsWith', 'patchWith', 'customMethod', 'customPayloadMethod'], { ...SSRF, argIndex: 1, package: 'wreq' });
sink('Network.Wreq', ['customMethodWith', 'customPayloadMethodWith'], { ...SSRF, argIndex: 2, package: 'wreq' });
sink('Network.Wreq.Session', ['get', 'post', 'put', 'delete', 'head', 'options', 'patch'], { ...SSRF, argIndex: 1, package: 'wreq' });
sink('Network.Wreq.Session', ['getWith', 'postWith', 'putWith', 'deleteWith', 'headWith', 'optionsWith', 'patchWith'], { ...SSRF, argIndex: 2, package: 'wreq' });

// CWE-1427. Untrusted text placed in a model request body. The call is an ordinary HTTP body setter, so the
// finding is kept only for a file that shows AI evidence (an AI endpoint, model literal or SDK import):
// haskell-llm.js drops the same flow anywhere else, because there it is just an HTTP body.
const LLM = { family: 'llm-prompt', cwe: 'CWE-1427', severity: 'high', argIndex: 0, vuln: 'Prompt Injection (untrusted text in a model request)', remediation: 'Keep untrusted text out of the system/instruction part of the request, constrain what the model may do with it, and treat the response as untrusted too. An allow-list or length/charset check on the value is a real control; a delimiter in the prompt is not.' };
sink('Network.HTTP.Simple', ['setRequestBodyJSON', 'setRequestBodyLBS', 'setRequestBodyURLEncoded'], { ...LLM, package: 'http-conduit' });
sink('Network.HTTP.Conduit', ['setRequestBodyJSON', 'setRequestBodyLBS'], { ...LLM, package: 'http-conduit' });

// CWE-79. Raw (already-escaped-by-contract) HTML sinks, and Scotty's html response.
const XSS = { family: 'xss', cwe: 'CWE-79', severity: 'high', argIndex: 0, vuln: 'Cross-Site Scripting (unescaped HTML)', remediation: 'Render with the escaping combinator (`toHtml`) instead of the raw/pre-escaped one, or sanitize with an HTML allow-list.' };
sink('Text.Blaze.Html', ['preEscapedToHtml'], { ...XSS, package: 'blaze-html' });
sink('Text.Blaze', ['preEscapedText', 'preEscapedString', 'preEscapedLazyText', 'unsafeByteString', 'unsafeLazyByteString'], { ...XSS, package: 'blaze-html' });
sink('Text.Blaze.Internal', ['preEscapedText', 'preEscapedString', 'preEscapedLazyText', 'unsafeByteString', 'unsafeLazyByteString'], { ...XSS, package: 'blaze-html' });
sink('Text.Blaze.Html5', ['preEscapedToHtml'], { ...XSS, package: 'blaze-html' });
sink('Lucid', ['toHtmlRaw'], { ...XSS, package: 'lucid' });
sink('Lucid.Base', ['toHtmlRaw'], { ...XSS, package: 'lucid' });
sink('Text.Hamlet', ['preEscapedToMarkup'], { ...XSS, package: 'shakespeare' });
sink('Web.Scotty', ['html'], { ...XSS, package: 'scotty', framework: 'scotty', vuln: 'Cross-Site Scripting (HTML response from text)' });
sink('Web.Scotty.Trans', ['html'], { ...XSS, package: 'scotty', framework: 'scotty', vuln: 'Cross-Site Scripting (HTML response from text)' });

// HTML assembled by concatenation and written out as text: only when the string being built contains markup (a literal
// "<tag"), because `putStrLn` on its own is not an HTML sink. Medium: the output channel is not proven to be a browser.
const XSS_TEXT = { ...XSS, severity: 'medium', htmlSkeleton: true, vuln: 'Cross-Site Scripting (HTML built by string concatenation)' };
sink('Prelude', ['putStrLn', 'putStr'], XSS_TEXT);
sink('System.IO', ['putStrLn', 'putStr'], XSS_TEXT);
sink('Data.Text.IO', ['putStrLn', 'putStr'], { ...XSS_TEXT, package: 'text' });

// ── sanitizers (context-specific; `appliesTo` is the family each one actually neutralises) ──
const SAN = [];
const san = (module, names, appliesTo, note, extra = {}) => { for (const e of E(module, names)) SAN.push({ ...e, appliesTo, note, ...extra }); };
san('Text.Blaze.Html', ['toHtml', 'toMarkup', 'text', 'string', 'lazyText'], ['xss'], 'escapes &, <, >, quotes for HTML text/attribute context');
san('Text.Blaze', ['toMarkup', 'toValue', 'text', 'string', 'lazyText'], ['xss'], 'escapes for HTML context');
san('Lucid', ['toHtml', 'toHtmlRaw_'], ['xss'], 'Lucid.toHtml escapes');
san('System.FilePath', ['takeFileName', 'takeBaseName'], ['path'], 'drops every directory component');
san('System.FilePath.Posix', ['takeFileName', 'takeBaseName'], ['path'], 'drops every directory component');
// A function whose result is a number or a boolean cannot carry caller text: nothing of the argument survives (`show (length x)`).
const ALL_FAMILIES = ['*'];
san('Prelude', ['length', 'null', 'fromEnum'], ALL_FAMILIES, 'returns a number or boolean: no caller text survives');
san('Data.List', ['length', 'genericLength'], ALL_FAMILIES, 'returns a number: no caller text survives');
san('Data.Foldable', ['length', 'null'], ALL_FAMILIES, 'returns a number or boolean: no caller text survives');
san('Data.Text', ['length'], ALL_FAMILIES, 'returns a number: no caller text survives');
san('Data.ByteString', ['length'], ALL_FAMILIES, 'returns a number: no caller text survives');
san('Data.Char', ['ord'], ALL_FAMILIES, 'returns a number: no caller text survives');
san('Database.PostgreSQL.Simple', ['Only'], [], 'binds a parameter; it is a safe argument position, not a query-text sanitizer');

export const HS_SOURCES = Object.freeze(SRC);
export const HS_SINKS = Object.freeze(SINK);
export const HS_SANITIZERS = Object.freeze(SAN);


// ── logging sinks (HS-004 sensitive-data logging) ─────────────────────────────
// argIndex is the position of the MESSAGE (not the handle / level).
export const HS_LOG_SINKS = Object.freeze([
  ...E('Prelude', ['putStrLn', 'putStr', 'print']).map((e) => ({ ...e, argIndex: 0, channel: 'stdout' })),
  ...E('System.IO', ['putStrLn', 'putStr', 'print']).map((e) => ({ ...e, argIndex: 0, channel: 'stdout' })),
  ...E('System.IO', ['hPutStrLn', 'hPutStr', 'hPrint']).map((e) => ({ ...e, argIndex: 1, channel: 'handle' })),
  ...E('Data.Text.IO', ['putStrLn', 'putStr', 'hPutStrLn', 'hPutStr']).map((e) => ({ ...e, argIndex: e.name.startsWith('h') ? 1 : 0, channel: 'stdout' })),
  ...E('Prelude', ['appendFile']).map((e) => ({ ...e, argIndex: 1, channel: 'file' })),
  ...E('System.IO', ['appendFile']).map((e) => ({ ...e, argIndex: 1, channel: 'file' })),
  ...E('Debug.Trace', ['trace', 'traceShow', 'traceM', 'traceShowM', 'traceShowId', 'traceId']).map((e) => ({ ...e, argIndex: 0, channel: 'trace' })),
  ...E('Control.Monad.Logger', ['logDebugN', 'logInfoN', 'logWarnN', 'logErrorN', 'logOtherN']).map((e) => ({ ...e, argIndex: 0, channel: 'logger' })),
  ...E('Katip', ['logFM', 'logTM', 'logItem']).map((e) => ({ ...e, argIndex: 1, channel: 'logger' })),
  ...E('System.Log.Logger', ['debugM', 'infoM', 'noticeM', 'warningM', 'errorM', 'criticalM']).map((e) => ({ ...e, argIndex: 1, channel: 'logger' })),
]);

// Library surfaces the structural rules (haskell-security-rules.js) look for; registering them here makes
// the IR qualify these names through imports exactly as it does for the taint models.
export const HS_RULE_APIS = Object.freeze([
  ...E('Crypto.Hash', ['hash', 'hashWith', 'hashlazy']),
  ...E('Crypto.Hash.MD5', ['hash', 'hashlazy']), ...E('Crypto.Hash.SHA1', ['hash', 'hashlazy']),
  ...E('Crypto.Hash.SHA256', ['hash', 'hashlazy']), ...E('Crypto.Hash.SHA512', ['hash', 'hashlazy']),
  ...E('Data.Digest.Pure.MD5', ['md5']), ...E('Data.Digest.Pure.SHA', ['sha1', 'sha256', 'sha512']),
  ...E('Crypto.Cipher.Types', ['makeIV', 'ecbEncrypt', 'ecbDecrypt', 'nullIV', 'cbcEncrypt', 'cbcDecrypt']),
  ...E('Crypto.Cipher.ChaChaPoly1305', ['nonce12', 'nonce8']),
  ...E('Crypto.KDF.PBKDF2', ['generate', 'fastPBKDF2_SHA1', 'fastPBKDF2_SHA256', 'fastPBKDF2_SHA512']),
  ...E('System.Random', ['randomRIO', 'randomIO', 'newStdGen', 'getStdGen', 'mkStdGen', 'randomR', 'random', 'randoms', 'randomRs']),
  ...E('Crypto.Random', ['getRandomBytes']), ...E('System.Entropy', ['getEntropy']),
  ...E('Network.Wai', ['strictRequestBody', 'lazyRequestBody']),
  ...E('Data.Time.Clock.POSIX', ['getPOSIXTime']), ...E('Data.Time.Clock', ['getCurrentTime']), ...E('System.CPUTime', ['getCPUTime']),
  ...E('System.IO', ['getContents', 'hGetContents', 'appendFile']),
  ...E('Data.ByteString', ['getContents', 'hGetContents', 'replicate']), ...E('Data.ByteString.Char8', ['getContents', 'hGetContents', 'replicate']),
  ...E('Data.ByteString.Lazy', ['getContents', 'hGetContents', 'take', 'replicate']), ...E('Data.ByteString.Lazy.Char8', ['getContents', 'hGetContents', 'take']),
  ...E('Data.Text.IO', ['getContents', 'hGetContents']), ...E('Data.Text.Lazy.IO', ['getContents', 'hGetContents']),
  ...E('Data.Text', ['replicate', 'take']), ...E('Data.Vector', ['replicate']),
  ...E('Web.Cookie', ['defaultSetCookie']),
  ...E('Text.XML.HXT.Core', ['withSubstDTDEntities']),
  ...E('System.IO.Unsafe', ['unsafePerformIO', 'unsafeInterleaveIO', 'unsafeDupablePerformIO']),
  ...E('Unsafe.Coerce', ['unsafeCoerce']),
]);


// ── web framework surface (HS-006) ─────────────────────────────────────────────
// Route registration, middleware and the credential/rejection primitives the web analyser keys on.
export const HS_WEB_MODEL_VERSION = 'haskell-web-models/1';
export const HS_WEB_FRAMEWORKS = Object.freeze({
  scotty: { modules: ['Web.Scotty', 'Web.Scotty.Trans'], package: 'scotty', tested: ['0.12', '0.20'], routeFns: ['get', 'post', 'put', 'delete', 'patch', 'options', 'addroute', 'matchAny'] },
  wai: { modules: ['Network.Wai', 'Network.Wai.Handler.Warp'], package: 'wai', tested: ['3.2'] },
  servant: { modules: ['Servant', 'Servant.API', 'Servant.Server', 'Servant.Auth', 'Servant.Auth.Server'], package: 'servant-server', tested: ['0.19', '0.20'] },
  yesod: { modules: ['Yesod', 'Yesod.Core', 'Yesod.Auth'], package: 'yesod', tested: ['1.6'] },
});
export const HS_WEB_APIS = Object.freeze([
  ...E('Web.Scotty', ['get', 'post', 'put', 'delete', 'patch', 'options', 'addroute', 'matchAny', 'middleware', 'scotty', 'scottyApp', 'status', 'finish', 'raise', 'raiseStatus', 'redirect', 'text', 'json', 'html', 'file', 'setHeader', 'header', 'headers', 'param', 'params', 'captureParam', 'queryParam', 'formParam', 'body', 'jsonData', 'files', 'rescue', 'liftIO', 'notFound']),
  ...E('Web.Scotty.Trans', ['get', 'post', 'put', 'delete', 'patch', 'middleware', 'scottyT', 'status', 'finish', 'raise', 'raiseStatus', 'redirect', 'text', 'json', 'html', 'header', 'param', 'captureParam', 'queryParam', 'formParam', 'body', 'jsonData']),
  ...E('Network.Wai', ['pathInfo', 'requestMethod', 'requestHeaders', 'responseLBS', 'queryString', 'rawPathInfo']),
  ...E('Network.Wai.Handler.Warp', ['run', 'runSettings']),
  ...E('Network.HTTP.Types', ['status200', 'status201', 'status400', 'status401', 'status403', 'status404', 'unauthorized401', 'forbidden403', 'methodGet', 'methodPost', 'methodPut', 'methodDelete', 'hAuthorization', 'hCookie']),
  ...E('Network.Wai.Middleware.HttpAuth', ['basicAuth', 'extractBasicAuth']),
  ...E('Yesod.Core', ['requireAuthId', 'requireAuth', 'maybeAuthId', 'maybeAuth', 'permissionDenied', 'notAuthenticated', 'lookupHeader', 'lookupBearerAuth', 'lookupBasicAuth', 'lookupGetParam', 'lookupPostParam', 'runInputPost', 'runInputGet', 'getYesod', 'redirect']),
  ...E('Yesod', ['requireAuthId', 'requireAuth', 'maybeAuthId', 'maybeAuth', 'permissionDenied', 'notAuthenticated', 'lookupHeader', 'lookupBearerAuth', 'lookupBasicAuth']),
  ...E('Yesod.Auth', ['requireAuthId', 'requireAuth', 'maybeAuthId', 'maybeAuth', 'isAdmin']),
  ...E('Servant', ['throwError', 'err401', 'err403', 'err404']),
  ...E('Servant.Server', ['throwError', 'err401', 'err403', 'err404', 'serve']),
  ...E('Web.JWT', ['decodeAndVerifySignature', 'decode', 'verify']),
  ...E('Web.Cookie', ['parseCookies']),
  ...E('Control.Monad.Except', ['throwError']),
  ...E('Control.Exception', ['throwIO', 'throw']),
]);

const API_INDEX = new Map();
for (const s of [...SRC, ...SINK, ...SAN, ...HS_LOG_SINKS, ...HS_RULE_APIS, ...HS_WEB_APIS]) { const k = q(s.module, s.name); if (!API_INDEX.has(k)) API_INDEX.set(k, []); API_INDEX.get(k).push(s); }
const NAME_TO_MODULES = new Map();
for (const s of [...SRC, ...SINK, ...SAN, ...HS_LOG_SINKS, ...HS_RULE_APIS, ...HS_WEB_APIS]) { if (!NAME_TO_MODULES.has(s.name)) NAME_TO_MODULES.set(s.name, new Set()); NAME_TO_MODULES.get(s.name).add(s.module); }

export const isKnownApi = (module, name) => API_INDEX.has(q(module, name));
const SOURCE_QNAMES = new Set(SRC.map((e) => q(e.module, e.name)));
export const isSourceApi = (qualified) => SOURCE_QNAMES.has(qualified);
const SOURCE_INFO = new Map(SRC.map((e) => [q(e.module, e.name), { label: e.label, provenance: e.provenance }]));
export const sourceInfo = (qualified) => SOURCE_INFO.get(qualified) || null;
export const modelsFor = (qualified) => API_INDEX.get(qualified) || [];

/**
 * A call whose import is a wildcard among several (`import Web.Scotty` + `import Data.Text`) cannot be
 * attributed to one module by the IR alone. If EXACTLY ONE candidate module is one this registry
 * models for that name, use it, and report that the choice rests on the registry, not on the import list.
 * Zero or several modelled candidates stay unresolved (returns null): the name is never guessed.
 */
export function qualifyAmbiguous(name, candidateModules) {
  const hits = (candidateModules || []).filter((m) => isKnownApi(m, name));
  return hits.length === 1 ? { module: hits[0], viaRegistry: true } : null;
}

/** Which package a module belongs to, with the versions the models were written against. */
export function packageOfModule(module) {
  for (const [pkg, def] of Object.entries(HS_PACKAGES)) if (def.modules.includes(module)) return { package: pkg, tested: def.tested };
  return null;
}

/**
 * Tested-version status for a package. Absent version data is `unknown`, never `ok`.
 * @returns {'tested'|'untested-version'|'unknown-version'|'unmodelled-package'}
 */
export function modelStatus(pkg, version) {
  const def = HS_PACKAGES[pkg];
  if (!def) return 'unmodelled-package';
  if (!version) return 'unknown-version';
  return def.tested.some((t) => String(version) === t || String(version).startsWith(`${t}.`)) ? 'tested' : 'untested-version';
}
