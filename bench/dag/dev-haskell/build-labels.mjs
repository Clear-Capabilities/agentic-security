// Builds labels.json from the hand labels below. Labels were assigned by reading the code at each
// sampled site (behaviour only: data reaching a dangerous operation across a trust boundary without
// effective neutralisation), BEFORE any scanner change, and are keyed by the sample index of the seeded
// sample (sample.json). TP = a real weakness at that site; FP = not a vulnerability.
// A label is never edited after seeing scanner output except to correct a clear mistake, logged in
// LABEL-CHANGES.md (next to this file; it did not exist until the precision gate made the promise enforceable, and it says what can and cannot be established).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const sample = JSON.parse(fs.readFileSync(path.join(H, 'sample.json'), 'utf8')).sample;
const L = new Map();
const set = (from, to, label, reason) => { for (let i = from; i <= to; i++) L.set(i, { label, reason }); };

set(0, 8, 'FP', 'Generic process-spawning wrapper whose executable and arguments are its own parameters; nothing in the module takes them from a request, socket or other external input, and callers pass fixed tool names.');
set(2, 2, 'FP', 'Renders markdown files read from the application\'s own content checkout, an operator-controlled repository, not request data.');
set(9, 9, 'FP', 'T.last is guarded by the not-null test on the same expression.');
set(10, 10, 'FP', 'head applies to the groups of List.group, which are never empty.');
set(11, 11, 'FP', 'tail applies to a text that starts with the comma breakOn found (an empty remainder is rejected first); the input is the operator\'s own command line.');
set(12, 12, 'FP', 'findMax over sets read from the server\'s own state; no external input reaches it.');
set(13, 13, 'FP', 'cycle of a string from the operator\'s own bar configuration, consumed lazily by take.');
set(14, 15, 'FP', 'init/last are guarded by the length > 1 test on the same list.');
set(16, 18, 'TP', 'Account password hashed with one round of salted SHA-512 (a fast hash, not a password KDF) and compared with ==; stolen hashes can be brute-forced quickly. Three sites of one weakness (hash call, definition, comparison).');
set(19, 19, 'TP', 'Session identifier drawn from the global non-cryptographic generator over a 30-bit range; a session key must be unguessable.');
set(20, 20, 'FP', 'A password salt needs uniqueness, not secrecy or unpredictability; the generator choice has no security consequence here.');
set(21, 21, 'TP', 'HTTP Digest challenge nonce drawn from a non-cryptographic generator (newStdGen), predictable to an attacker who has seen outputs.');
set(22, 22, 'FP', 'Command-line maintenance script; the URI is an argument the operator types.');
set(23, 23, 'FP', 'The cookie written is the literal value 0 that clears a login on auth failure; it carries no credential.');
set(24, 30, 'FP', 'SHA-1/MD5 used to derive a file name, bookmark name, cache key, document ID or a documented hash helper; no authentication, signature or password decision depends on its collision or preimage resistance.');
set(31, 46, 'FP', 'Reads a local file, a child process\'s pipe, or the operator\'s own stdin; the amount is not controlled by a remote party across a trust boundary (and lazy hGetContents consumers stream).');
set(47, 91, 'FP', 'File path is operator configuration, a command-line argument, a state directory, a temp file or a value the program derived itself; no request, network or untrusted-archive data reaches it (the one request-derived path, the cache expiry, is first validated by a page-name predicate that rejects ".." and a leading underscore).');
set(92, 102, 'FP', 'Not a vulnerability: the flagged identifier is a local function parameter (a plain constructor argument), not an unsafe boundary.');
set(103, 103, 'FP', 'unsafeCoerce after compileExpr of a plugin the operator configured; a type-cast idiom with no attacker-reachable input.');
set(104, 105, 'FP', 'unsafeInterleaveIO defers a local read or lookup; no external data or security consequence.');
set(106, 109, 'FP', 'Not a vulnerability: the flagged identifier is a local function parameter, not an unsafe boundary.');
set(110, 110, 'FP', 'unsafePerformIO for a global IORef or pure FFI call; no external input.');
set(111, 112, 'FP', 'unsafeInterleaveIO / unsafePerformIO for a lazily read channel or global reference; no external input.');
set(113, 115, 'FP', 'Not a vulnerability: the flagged identifier is a local function parameter, not an unsafe boundary.');
set(116, 116, 'FP', 'unsafePerformIO around a pure stemming library call.');
set(117, 117, 'FP', 'Not a vulnerability: the flagged identifier is a let-bound local function, not an unsafe boundary.');
set(107, 107, 'FP', 'Not a vulnerability: toString is the UUID-to-string function.');
set(93, 93, 'FP', 'Not a vulnerability: toString is a ByteString-to-string conversion of a header.');
// Fix up: 107 and 93 are conversions, set above after the ranges they sit inside.

const labels = {};
let missing = 0;
sample.forEach((s, i) => { const l = L.get(i); if (!l) { missing++; return; } labels[s.key] = { index: i, project: s.project, file: s.file, line: s.line, vuln: s.vuln, half: s.half, ...l }; });
if (missing) { console.error(`unlabelled sample rows: ${missing}`); process.exit(1); }
fs.writeFileSync(path.join(H, 'labels.json'), JSON.stringify({ note: 'Hand labels by code behaviour, one labeller (a stated limit).', labels }, null, 1));
console.log(`labels: ${Object.keys(labels).length}, TP ${Object.values(labels).filter((l) => l.label === 'TP').length}`);
