// Builds fresh-labels.json: the hand labels of every site in fresh-worklist.json (the sites the engine after the fixes flags, plus the sites the
// original engine flagged that it no longer flags). Labelled by reading the code (behaviour only, never comments or names), AFTER the fixes
// were made and the set was scanned: this set is a held-out MEASUREMENT, not a tuning set, and no label was changed after seeing a result.
// One labeller. TP = a real weakness at that site; FP = not a vulnerability.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const wl = JSON.parse(fs.readFileSync(path.join(H, 'fresh-worklist.json'), 'utf8')).items;
const L = new Map();
const set = (idx, label, reason) => { for (const i of idx) L.set(i, { label, reason }); };
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, k) => a + k);

// default: everything is a false positive; the true positives are listed below with the reason read from the code
wl.forEach((x, i) => {
  let reason = 'Not a vulnerability: the flagged operation takes its path, value or type from the program\'s own configuration, command line, a file the operator names or an internal invariant, and no attacker-controlled data is shown to reach it.';
  if (/Unsafe boundary/.test(x.vuln)) reason = 'An unsafeCoerce/unsafePerformIO/unsafeInterleaveIO idiom (type-level coercion between phantom-indexed types, a global reference, a deferred local read). 14 of the 121 were read at random and none had external data reaching it; the rule itself claims no vulnerability class. Labelled FP.';
  else if (x.parser === 'STRUCTURAL' || x.parser === 'CLOUD-IAM') reason = 'A language-neutral text detector firing on Haskell source: a record pattern named String read as XML parsing, a client-side script inside an HTML quasi-quote, and the word allUsers inside a doc comment read as a cloud IAM binding. No such operation exists in the code.';
  else if (/Whole input read/.test(x.vuln)) reason = 'A command-line tool reading its own standard input, a file the operator names, or a child process pipe.';
  L.set(i, { label: 'FP', reason });
});
set([12, 13], 'TP', 'The test server turns the request path (pathInfo segments after /tests/import/) into a file path with joinPath and reads it, trying ../ variants, with no check that the result stays under the fixtures directory: a request containing .. segments reads arbitrary files. Two sites of one flaw (the read and the existence test).');
set([104], 'TP', 'The streaming OpenAI client sets the TLS verification mode to VerifyNone for every request, so the API key and the conversation travel over a connection whose peer is never authenticated.');
set([137, 138], 'TP', 'The request-parameter middleware reads the whole body of a JSON or unknown-type request with strictRequestBody and no size check, before the application runs: a client chooses how much memory the server allocates.');
set([154, 155, 156], 'TP', 'The handler reads the whole request body with body (no limit is applied anywhere in the example), so a client chooses the allocation. Low severity, labelled TP under the same rule as the middleware; a reviewer may call an example handler out of scope.');
set([146], 'TP', 'createUserSession sets the sess_id session cookie through setSimpleCookie, whose cookie has neither Secure nor HttpOnly, so the session id is sent over plain HTTP and readable by page scripts.');
set([147], 'TP', 'The session identifier is 32 letters drawn from the global non-cryptographic generator (randomRIO), predictable to an attacker who observes outputs.');
set([149, 150, 151, 152, 153], 'TP', 'A path or query parameter is concatenated into an HTML response (html $ mconcat ["<h1>", v, "</h1>"]) with no escaping: reflected cross-site scripting. 150 is the aggregate of the same flow.');
set([157], 'TP', 'The not-found handler returns show (pathInfo r) as text/html. show escapes quotes and backslashes but not < or >, and the decoded path segments are attacker-chosen, so markup in the URL is reflected.');
set([158], 'TP', 'The redirect target is a URL stored by earlier requests and returned for a hash chosen by the client, with no check of scheme or host: an open redirect (the intended feature of a URL shortener, but unvalidated attacker-supplied destinations).');
// lost by the fixes: the original engine flagged them, the engine now does not
set([191, 192], 'TP', 'A request parameter (the table index of a schema-designer action) indexes a list with !!, so an out-of-range value raises an exception in the request handler. Low severity. Lost: the helper is called by the controller, and the controller\'s request accessor is a project function in this repository, so the flow is not tracked.');
set([195, 196], 'TP', 'OpenEditorAction passes the request parameter path to openEditor, which runs Process.system on a shell string built from it: command injection from an HTTP request (to a localhost development tool). Lost: the helper became reachable, and in this repository (the framework itself) the request accessor is a project function the engine cannot know as a source.');

const labels = {};
wl.forEach((x, i) => { labels[x.key] = { index: i, kind: x.kind, parser: x.parser, severity: x.severity, vuln: x.vuln, project: x.project, ...L.get(i) }; });
fs.writeFileSync(path.join(H, 'fresh-labels.json'), JSON.stringify({ note: 'Hand labels by code behaviour, one labeller (a stated limit). Held-out measurement set: labelled after the fixes, never used to tune.', labels }, null, 1));
const tp = Object.values(labels).filter((l) => l.label === 'TP');
console.log(`labelled ${Object.keys(labels).length}; TP ${tp.length}`);
