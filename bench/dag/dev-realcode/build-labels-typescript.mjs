// Builds labels-typescript.json from the hand labels below (see build-labels-python.mjs for the rule; the same labeller read both halves
// before any fix, a stated limit). Keyed by the index of the seeded sample (sample-typescript.json).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const sampleDoc = JSON.parse(fs.readFileSync(path.join(H, 'sample-typescript.json'), 'utf8'));
const L = new Map();
const set = (idx, label, reason) => { for (const i of Array.isArray(idx) ? idx : [idx]) L.set(i, { label, reason }); };

set(0, 'FP', 'The ETag is a number derived from the record\'s modification time; Node\'s setHeader also refuses a value with CR or LF.');
set(1, 'FP', 'Content-Range is built from three numbers of the file response; Node\'s setHeader refuses CR or LF.');
set([2, 3], 'FP', 'Cache-Control comes from getCacheControlHeader, which composes directives from the environment TTL and request flags; Node\'s setHeader refuses CR or LF.');
set(4, 'FP', 'The ETag is a number derived from a timestamp; Node\'s setHeader refuses CR or LF.');
set([5, 11], 'FP', 'Retry-After is String() of a number from the rate limiter; Node\'s setHeader refuses CR or LF.');
set(6, 'FP', 'A repository maintenance script: the pattern is a translation tag with every regex metacharacter escaped first, run by a developer on the command line.');
set(7, 'FP', 'The mention is "@" followed by a value that isValidUuid accepted two lines above, so the pattern has no metacharacters.');
set(8, 'FP', 'Browser-side code: a fetch wrapper the client uses to load an image; a request from the user\'s own browser is not a server-side request.');
set(9, 'FP', 'wellKnownUrl is the OpenID provider\'s configuration URL from the organisation\'s configured provider, passed by the OAuth authorise and callback handlers; not a request value.');
set(10, 'FP', 'A front component of the Discord app: the base URL and token come from the environment and the path from the component\'s own calls.');
set(12, 'FP', 'An Angular client service calling this application\'s own API with an encoded path segment; a browser request to its own origin.');
set([13, 17], 'FP', 'A Vite dev-server plugin: the file name is accepted only when EMOJIBASE_DATA_FILE_NAMES.includes(fileName), a fixed list.');
set(14, 'FP', 'The template path is resolved from a template name the mail service\'s own callers pass (a fixed set of templates), after an existence check; the user record only supplies variables.');
set(15, 'FP', 'A command-line tool reading JSON from the directories it walks on the developer\'s machine.');
set(16, 'FP', 'The source location is the stored manifest of an application the server itself published, read back from the server\'s file storage and checksum-verified.');
set(18, 'FP', 'A build script of the repository reading each package\'s package.json.');
set(19, 'FP', 'getSsoRecoveryConfirmUrl builds this application\'s own confirmation URL and places the state id in its query.');
set(20, 'FP', 'handleRedirects maps a few legacy request paths to fixed internal paths and returns null otherwise.');
set(21, 'FP', 'The redirect URL was accepted by resolveLoginRedirect against the provider\'s allow list when the login started and travels in a server-signed state token.');
set(22, 'FP', 'The callback URL is the recovery flow\'s own completion URL resolved by resolveRecoveryCallbackUrl from the trusted origins; the form body only carries the proof.');
set(23, 'FP', 'redirect() to formatDocumentsPath of the team\'s own URL slug, an internal path built from a database record.');
set(24, 'FP', 'The redirect target is formatOrganisationLoginUrl of the organisation\'s own URL from the database, with an error code in its query.');
set([25, 27, 30], 'FP', 'The file storage service writes build outputs under the application\'s own dependency folder at paths the server built (resourcePath from builtPath); the workspace scopes the storage.');
set(26, 'FP', 'A build script writing the checksum file next to the archive it just produced.');
set(28, 'FP', 'The command-line tool writing its own configuration file atomically in the user\'s config directory.');
set(29, 'FP', 'The command-line tool writing a project-link manifest inside the project directory the developer linked.');
set(31, 'FP', 'A cross-file finding whose sink is the client-side table state codec reading a regular expression of its own (FILTER_KEY_PATTERN) against URL keys in the browser.');
set(32, 'FP', 'separator is the regular expression /[ ,]/g bound in this function; .exec here is RegExp.prototype.exec, not child_process.exec (another function of the file binds the same name to a number).');
set(33, 'FP', 'The response body comes from a sandboxed extension route an operator installed; the request is passed to the extension\'s code, not reflected.');
set(34, 'FP', 'The development mailbox of the email plugin, a development-only server: it serves the application\'s own generated emails by id.');
set(35, 'FP', 'The web manifest is sent as application/json after interpolating a language code and the configured root URL; not an HTML response.');
set(36, 'FP', 'The consent page is rendered by a Liquid template with output escaping enabled (outputEscape: escape).');
set(37, 'FP', 'The mock server returns the user\'s own configured mock response, the feature\'s purpose, with X-Content-Type-Options: nosniff and a sandboxing Content-Security-Policy when not served from a per-mock subdomain.');
set(38, 'FP', 'The index HTML is assembled from a fixed locale table and values passed through escapeAttribute; the request path selects the locale entry.');
set([39, 44], 'FP', 'helpers.st.nintersects and nintersects_bbox return knex.raw("st_intersects(??, ?)", [key, geometry]) wrapped in isFalse: identifier and value are bound, the raw text is constant.');
set(40, 'FP', 'execute here invokes the desktop relay plugin with a request object; it is not a database call.');
set(41, 'FP', 'whereRaw with ?? and ? placeholders and a bindings array of the email values; the raw text is built from placeholders only.');
set(42, 'FP', 'commonCreateOneQueryRunnerService.execute is the application\'s own service method taking a structured input, not a database execute.');
set(43, 'FP', 'coreApiClient.query sends a structured GraphQL selection to this application\'s API; the base URL and token come from the environment.');
set(45, 'FP', 'fetch of the configured AI provider\'s API URL with a request body the server composed; the URL is operator configuration.');
set(46, 'FP', 'Browser-side API client calling this application\'s own API path built from an id; a same-origin request from the user\'s browser.');
set([47, 49], 'FP', 'The base URL comes from the environment and the path from the caller\'s own constants; operator configuration, not request data.');
set(48, 'FP', 'The ingest proxy sets protocol, hostname and port to the fixed analytics host before fetching; the request supplies only the path and body.');
set(50, 'FP', 'A cross-file finding whose sink is a browser-side client fetching this application\'s own /api/v3 path with a query built from table state.');
set(51, 'FP', 'A cross-file finding whose sink is redis.eval of a Lua script constant of the module (SCRIPT), fed by the rate limiter\'s own options.');

const labels = {};
for (const s of sampleDoc.sample) {
  const l = L.get(s.index);
  if (!l) throw new Error(`no label for sample index ${s.index} (${s.key})`);
  labels[`${s.index}`] = { index: s.index, key: s.key, half: s.half, stratum: s.stratum, project: s.project, file: s.file, line: s.line, vuln: s.vuln, cwe: s.cwe, parser: s.parser, severity: s.severity, label: l.label, reason: l.reason };
}
fs.writeFileSync(path.join(H, 'labels-typescript.json'), JSON.stringify({ note: 'Hand labels by code behaviour, one labeller, both halves read before any fix (a stated limit). Keyed by the seeded sample index.', set: 'typescript', seed: sampleDoc.seed, labels }, null, 1) + '\n');
const tp = Object.values(labels).filter((l) => l.label === 'TP').length;
console.log(`labels-typescript.json: ${Object.keys(labels).length} sites, ${tp} TP, ${Object.keys(labels).length - tp} FP`);
