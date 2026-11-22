// Builds labels-python.json from the hand labels below. Labels were assigned by reading the code at each sampled site (behaviour only: does
// attacker-controlled data reach the dangerous operation across a real trust boundary without effective neutralisation), keyed by the index
// of the seeded sample (sample-python.json). TP = a real weakness at that site; FP = not a vulnerability. A label is never edited after seeing
// scanner output except to correct a clear mistake, logged in LABEL-CHANGES.md. Both halves were read by the one labeller (see README.md).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const sampleDoc = JSON.parse(fs.readFileSync(path.join(H, 'sample-python.json'), 'utf8'));
const L = new Map();
const set = (idx, label, reason) => { for (const i of Array.isArray(idx) ? idx : [idx]) L.set(i, { label, reason }); };

set(0, 'FP', 'The header is set on an OUTGOING requests.Request the server prepares for a webhook, and the value is an HMAC hex digest; nothing of a client reaches a response header.');
set(1, 'FP', 'Location is the URL of a job built by reverse() from a route name and a primary key; reverse() output cannot carry CR or LF, and Django rejects them in header values.');
set(2, 'FP', 'Content-Disposition filename is a UUID and an integer of the server\'s own records; Django rejects CR/LF in header values.');
set(3, 'FP', 'Filename is the model\'s static verbose name through Django\'s content_disposition_header; Django rejects CR/LF in header values.');
set(4, 'FP', 'The filename is escaped and URL-quoted before the header is set, and werkzeug refuses header values that contain CR or LF.');
set(5, 'FP', 'Filename comes from a stored object name through Django\'s content_disposition_header, which quotes it; Django rejects CR/LF in header values.');
set(6, 'TP', 'The bulk-rename form lets an authenticated user supply a regular expression that re.sub applies server-side to every selected object; a catastrophic pattern is applied at the user\'s request (ReDoS, the low severity reported).');
set(7, 'TP', 'The search view compiles the user\'s query as a regular expression when the regex lookup is chosen; a catastrophic pattern is compiled and applied at the user\'s request (ReDoS, low).');
set(8, 'FP', 'The template text is a workflow action configured by an administrator in the application\'s own settings and rendered in the application\'s template environment; no request data reaches it at this boundary.');
set(9, 'FP', 'A code-generation script of the development tree reading a template file of the repository.');
set(10, 'FP', 'The filename-format template is storage-path configuration set by an administrator; the rendered path is then checked with is_safe_relative_path.');
set(11, 'FP', 'The path is confined to the asset directory by is_relative_to(asset_dir.resolve()) two lines above the response.');
set(12, 'FP', 'The unpickled bytes are the decrypted content of a server-side session file the server itself wrote; the "network read" origin is a file read misread as urlopen.');
set(13, 'FP', 'A SQLModel select with bound parameters; skip and limit are integers.');
set(14, 'FP', 'A SQLAlchemy delete() construct with a bound parameter, not SQL text.');
set(15, 'FP', 'The message is built with format() over escape(device) and a model URL; mark_safe wraps already-escaped content.');
set(16, 'FP', 'The same site as #8 (the workflow template is administrator configuration), reported a second time as a multi-sink chain.');
set(17, 'FP', 'The path was returned by check_access_permission, which resolves symlinks and confines it to the user\'s storage directory in server mode; the file manager\'s purpose is to write there.');
set(18, 'FP', 'The TIFF path is a document the server itself placed in its consumption or scratch directory and handed to the task.');
set(19, 'FP', 'The client-secret path is confined by filename_with_file_manager_path to the user\'s storage directory before it is opened.');
set(20, 'FP', 'A release-verification script of the development tree opening the sdist named on its own command line.');
set([21, 22], 'FP', 'A build-tooling script reading and writing the lock file named on its own command line; the operator runs it.');
set([23, 24], 'FP', 'The same site as #12: server-written session file content, misattributed to a network read.');
set(25, 'FP', 'redirect() to the object\'s own get_absolute_url(), a URL the model builds from a route name.');
set(26, 'FP', 'The next URL is accepted only when _allow_redirect finds no netloc and resolves the path as a route of this application.');
set(27, 'FP', 'The next URL passes url_has_allowed_host_and_scheme with the request\'s own host before the redirect.');
set(28, 'FP', 'get_return_url validates the return URL with url_has_allowed_host_and_scheme and falls back to the list view.');
set(29, 'FP', 'The redirect target is the application\'s own login route with the current URL as its next parameter.');
set(30, 'FP', 'The next URL is replaced by the index URL unless _is_safe_redirect_url accepts it, a dozen lines above.');
set(31, 'FP', 'parser.parse here is the document parser of the consumer reading the document the server stored; it is not an XML parser, and the path is the server\'s.');
set([32, 33], 'FP', 'sqlparse.parse tokenises SQL text for autocompletion; it is not lxml.etree.parse.');
set(34, 'FP', 'parse is a local string parser of a publishing script over archive keys from its own command line; a name collision with the XML parser.');
set(35, 'FP', 'dateparser.parse of a comma-separated environment setting; not an XML parser, and the operator sets the environment.');
set(36, 'FP', 'parser.parse is the ingredient parser (natural-language parsing of a recipe line); a name collision with the XML parser.');
set([37, 38], 'FP', 'The background-process executor is started by the server with the argument list it built; Popen receives a list, and sys.argv here is the server\'s own, not a client\'s.');
set(39, 'FP', 'A publishing script of the development tree running an aws command with the distribution id from its own command line.');
set(40, 'FP', 'The HTML is produced by plugin template extensions, code the operator installed; not request data.');
set(41, 'FP', 'The HTML passed through clean_html (the project\'s HTML sanitiser with the configured scheme list) immediately before mark_safe.');
set(42, 'FP', 'The fragment is built with format_html (escaped) and a URL from reverse(); the replace inserts that escaped fragment.');
set(43, 'FP', 'HX-Location carries the return URL that get_return_url validated with url_has_allowed_host_and_scheme.');
set(44, 'FP', 'Custom links are templates an administrator configures; the group name is passed through escape() and the rendered links come from that configuration.');
set(45, 'FP', 'extra_buttons is template code set on the column class in the project\'s own source and rendered by the Django template engine, which escapes record values.');
set([46, 47, 48, 49, 50, 51], 'FP', 'A SQLAlchemy select or delete construct executed with bound parameters; no SQL text is built from a value.');
set([52, 53], 'FP', 'db.session.delete is the ORM\'s delete of a model instance, not an HTTP DELETE; a name collision with requests.delete.');
set(54, 'FP', 'The video URL comes from the exercise-sync API of the wger instance the administrator configured as upstream, fetched by a management command; no client of this server steers it.');
set([55, 56], 'FP', 'session.delete is the ORM session\'s delete of a model instance, not an HTTP DELETE.');
set(57, 'FP', 'The API URL is checked against ALLOWED_LLM_API_URLS a few lines above; a URL outside the allow list raises before the request is built.');
set([58, 59], 'FP', 'The same sites as #8 and #10 (administrator-configured templates), reported under CWE-94.');
set([60, 62, 63], 'FP', 'session.exec is SQLModel\'s statement execution with bound parameters, not Python\'s exec builtin; a name collision.');
set(61, 'FP', 'The code executed is a custom script file an administrator uploaded to the scripts storage, the feature\'s purpose; the "network read" origin is a file read misread as urlopen.');

const labels = {};
for (const s of sampleDoc.sample) {
  const l = L.get(s.index);
  if (!l) throw new Error(`no label for sample index ${s.index} (${s.key})`);
  labels[`${s.index}`] = { index: s.index, key: s.key, half: s.half, stratum: s.stratum, project: s.project, file: s.file, line: s.line, vuln: s.vuln, cwe: s.cwe, parser: s.parser, severity: s.severity, label: l.label, reason: l.reason };
}
fs.writeFileSync(path.join(H, 'labels-python.json'), JSON.stringify({ note: 'Hand labels by code behaviour, one labeller, both halves read before any fix (a stated limit). Keyed by the seeded sample index.', set: 'python', seed: sampleDoc.seed, labels }, null, 1) + '\n');
const tp = Object.values(labels).filter((l) => l.label === 'TP').length;
console.log(`labels-python.json: ${Object.keys(labels).length} sites, ${tp} TP, ${Object.keys(labels).length - tp} FP`);
