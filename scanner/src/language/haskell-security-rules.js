// Haskell crypto, randomness, resource, XML and sensitive-logging rules (HS-004).
//
// Structural, API-aware rules over the Haskell IR. Every callee is the IMPORT-QUALIFIED name the IR
// resolved (`Crypto.Hash.hashWith`), so an unrelated user function with the same bare name never
// matches. A rule fires only for the API behaviour it describes:
//
//   - a generic `decode`, `read`, `random` or `hash` identifier is NOT evidence of anything;
//   - a randomness call is a finding only when its result is BOUND to something security-shaped;
//   - a hash is a password-storage finding only when a password-shaped value is hashed with a fast hash;
//   - CWE-502 is not claimed: no modelled Haskell API here executes code on decode, and `read`/`readMaybe`
//     are parsers, not code execution (the modelled boundaries are listed in `BOUNDARIES`);
//   - type-directed selection (`hash x :: Digest MD5`) is NOT resolved: it is disclosed, never guessed.
//
// Nothing here executes code, evaluates a type, or reads a path outside the files it is handed.

import { buildHaskellIR } from './haskell-ir.js';
import { HS_LOG_SINKS, HS_MODEL_VERSION } from './haskell-models.js';
import { codeOfLine } from './haskell-comments.js';

export const HS_RULES_VERSION = 'haskell-security-rules/1';

export const RULES = Object.freeze({
  'hs-weak-hash': { cwe: 'CWE-328', severity: 'medium', family: 'weak-hash', vuln: 'Weak hash function (MD5/SHA-1)', remediation: 'Use SHA-256 or stronger (or BLAKE2) for integrity; use a password KDF for secrets.' },
  'hs-fast-password-hash': { cwe: 'CWE-916', severity: 'high', family: 'password-hashing', vuln: 'Password hashed with a fast general-purpose hash', remediation: 'Hash passwords with a memory-hard or iterated KDF (Argon2id, scrypt, bcrypt, PBKDF2 with a high iteration count) and a per-user salt.' },
  'hs-pbkdf2-low-iterations': { cwe: 'CWE-916', severity: 'medium', family: 'password-hashing', vuln: 'PBKDF2 with too few iterations', remediation: 'Use at least 600000 iterations for PBKDF2-HMAC-SHA256 (OWASP), or prefer Argon2id.' },
  'hs-weak-cipher': { cwe: 'CWE-327', severity: 'high', family: 'weak-crypto', vuln: 'Broken or obsolete cipher', remediation: 'Use AES-GCM or ChaCha20-Poly1305 (an AEAD).' },
  'hs-ecb-mode': { cwe: 'CWE-327', severity: 'high', family: 'weak-crypto', vuln: 'ECB block cipher mode', remediation: 'ECB leaks plaintext structure. Use an AEAD mode (AES-GCM) with a fresh nonce.' },
  'hs-static-iv': { cwe: 'CWE-329', severity: 'high', family: 'weak-crypto', vuln: 'Static IV or nonce', remediation: 'Generate a fresh random IV/nonce per message with `getRandomBytes`; never reuse one with the same key.' },
  'hs-predictable-random': { cwe: 'CWE-338', severity: 'high', family: 'weak-randomness', vuln: 'Predictable random number generator used for a security value', remediation: 'Use `Crypto.Random.getRandomBytes` or `System.Entropy.getEntropy` (OS CSPRNG). `System.Random` is a deterministic PRNG.' },
  'hs-unbounded-request-body': { cwe: 'CWE-770', severity: 'medium', family: 'resource-exhaustion', vuln: 'Request body read without a size limit', remediation: 'Apply `requestSizeLimitMiddleware` (wai-extra) or read a bounded number of chunks with `getRequestBodyChunk`.' },
  'hs-xml-entity-substitution': { cwe: 'CWE-611', severity: 'medium', family: 'xxe', vuln: 'XML parser configured to substitute DTD entities', remediation: 'Disable DTD entity substitution (`withSubstDTDEntities no`) for untrusted XML.' },
  'hs-sensitive-logging': { cwe: 'CWE-532', severity: 'high', family: 'sensitive-logging', vuln: 'Sensitive value written to a log or trace', remediation: 'Do not log credentials or secrets. Log an identifier, or redact the value before it reaches the logger.' },
  'hs-insecure-cookie': { cwe: 'CWE-1004', severity: 'medium', family: 'cookie-attributes', vuln: 'Session cookie without HttpOnly or Secure', remediation: 'Set `setCookieHttpOnly = True`, `setCookieSecure = True` and `setCookieSameSite = Just sameSiteStrict` (or Lax) on a session or token cookie.' },
  'hs-unbounded-input-read': { cwe: 'CWE-770', severity: 'medium', family: 'resource-exhaustion', vuln: 'Whole input read into memory without a size limit', remediation: 'Bound the read (`BL.take n`, `hGetSome`, a request-size limit) before the data is consumed.' },
  'hs-unbounded-allocation': { cwe: 'CWE-770', severity: 'medium', family: 'resource-exhaustion', vuln: 'Allocation sized by parsed caller text without an upper bound', remediation: 'Clamp the size (`min limit n`) before allocating.' },
  'hs-partial-function-on-input': { cwe: 'CWE-248', severity: 'low', family: 'unhandled-exception', vuln: 'Partial function applied to caller-supplied text', remediation: 'Use the total variant (`readMaybe`, `listToMaybe`, pattern matching) and handle the failure.' },
  'hs-tls-validation-disabled': { cwe: 'CWE-295', severity: 'high', family: 'tls-validation', vuln: 'TLS certificate validation is disabled', remediation: 'Do not disable certificate validation. Use the default settings (`tlsManagerSettings`, `TLSSettingsSimple False False False`, `VerifyPeer`) and, for a private certificate authority, add that authority to the trust store instead.' },
  'hs-hardcoded-secret': { cwe: 'CWE-798', severity: 'high', family: 'hardcoded-credentials', vuln: 'Signing or encryption secret written in the source', remediation: 'Read the secret from the environment or a secret store at start-up, and rotate the one that was committed: it is now in the repository history.' },
  'hs-unsafe-io-boundary': { cwe: 'CWE-676', severity: 'low', family: 'unsafe-boundary', vuln: 'Unsafe IO / coercion boundary', remediation: 'Confine `unsafePerformIO`/`unsafeCoerce` to audited, well-tested wrappers.' },
});

// Modelled boundaries and what each does and does NOT claim. Reported verbatim on the finding.
export const BOUNDARIES = Object.freeze({
  unsafePerformIO: 'Runs an IO action as a pure value. Modelled as a code-quality/safety boundary only; no vulnerability class (including CWE-502) is claimed.',
  unsafeInterleaveIO: 'Defers an IO action until demanded. Modelled as a boundary only.',
  unsafeDupablePerformIO: 'Like unsafePerformIO without the thunk lock. Modelled as a boundary only.',
  unsafeCoerce: 'Reinterprets a value as another type without a check. Modelled as a boundary only.',
});

const WEAK_HASH_CALLS = new Set(['Crypto.Hash.MD5.hash', 'Crypto.Hash.MD5.hashlazy', 'Crypto.Hash.SHA1.hash', 'Crypto.Hash.SHA1.hashlazy', 'Data.Digest.Pure.MD5.md5', 'Data.Digest.Pure.MD5.md5DigestBytes', 'Data.Digest.Pure.SHA.sha1', 'Data.Digest.Pure.SHA.sha1Incremental']);
const WEAK_ALGO_CONS = new Set(['MD5', 'MD4', 'MD2', 'SHA1']);
const ANY_HASH_CALLS = new Set([...WEAK_HASH_CALLS, 'Crypto.Hash.hash', 'Crypto.Hash.hashlazy', 'Crypto.Hash.hashWith', 'Crypto.Hash.SHA256.hash', 'Crypto.Hash.SHA256.hashlazy', 'Crypto.Hash.SHA512.hash', 'Crypto.Hash.SHA512.hashlazy', 'Data.Digest.Pure.SHA.sha256', 'Data.Digest.Pure.SHA.sha512']);
const WEAK_CIPHER_MODULES = new Set(['Crypto.Cipher.DES', 'Crypto.Cipher.RC4', 'Crypto.Cipher.RC2', 'Crypto.Cipher.Blowfish']);
const ECB_CALLS = new Set(['Crypto.Cipher.Types.ecbEncrypt', 'Crypto.Cipher.Types.ecbDecrypt']);
const IV_CALLS = new Set(['Crypto.Cipher.Types.makeIV', 'Crypto.Cipher.ChaChaPoly1305.nonce12', 'Crypto.Cipher.ChaChaPoly1305.nonce8']);
const RANDOM_CALLS = new Set(['System.Random.randomRIO', 'System.Random.randomIO', 'System.Random.newStdGen', 'System.Random.getStdGen', 'System.Random.mkStdGen', 'System.Random.randomR', 'System.Random.random', 'System.Random.randoms', 'System.Random.randomRs', 'System.Random.getStdRandom', 'System.Random.uniformR', 'System.Random.uniform', 'System.Random.initStdGen']);
const BODY_CALLS = new Set(['Network.Wai.strictRequestBody', 'Network.Wai.lazyRequestBody', 'Web.Scotty.body', 'Web.Scotty.Trans.body', 'Network.Wai.Conduit.sourceRequestBody']);
const SOCKET_READS = new Set(['Network.Socket.ByteString.recv', 'Network.Socket.ByteString.recvFrom', 'Network.Socket.ByteString.Lazy.recv']);
const SET_COOKIE_HEADER = new Set(['Network.HTTP.Types.Header.hSetCookie', 'Network.HTTP.Types.hSetCookie']);
const REQUEST_LENGTH = new Set(['Network.Wai.requestBodyLength']);
const RELATIONAL = new Set(['<', '<=', '>', '>=']);
const PBKDF2_CALLS = new Set(['Crypto.KDF.PBKDF2.generate', 'Crypto.KDF.PBKDF2.fastPBKDF2_SHA1', 'Crypto.KDF.PBKDF2.fastPBKDF2_SHA256', 'Crypto.KDF.PBKDF2.fastPBKDF2_SHA512']);
const STRONG_KDF = /^(?:Crypto\.KDF\.BCrypt\.|Crypto\.Argon2\.|Crypto\.Scrypt\.|Crypto\.KDF\.Scrypt\.|Crypto\.PasswordStore\.|Crypto\.BCrypt\.)/;
const UNSAFE_CALLS = { 'System.IO.Unsafe.unsafePerformIO': 'unsafePerformIO', 'System.IO.Unsafe.unsafeInterleaveIO': 'unsafeInterleaveIO', 'System.IO.Unsafe.unsafeDupablePerformIO': 'unsafeDupablePerformIO', 'Unsafe.Coerce.unsafeCoerce': 'unsafeCoerce' };

// TLS: the first field of TLSSettingsSimple (Network.Connection) is settingDisableCertificateValidation, and `VerifyNone` (OpenSSL.Session) skips peer verification.
// The IR keeps a constructor's name in `hs.con` but not the module it came from, so a constructor counts only in a file that imports the module defining it.
// Calls whose argument is a key or signing secret.
const SECRET_KEY_CALLS = new Set(['Web.JWT.hmacSecret', 'Web.JWT.secret', 'Servant.Auth.Server.fromSecret', 'Web.ClientSession.initKey']);
const isTrueLit = (e) => !!e && ((e.kind === 'literal' && /^true$/i.test(String(e.value))) || (e.kind === 'ident' && /(?:^|\.)True$/.test(e.name || '')));
const TIME_SOURCES = new Set(['Data.Time.Clock.POSIX.getPOSIXTime', 'Data.Time.Clock.getCurrentTime', 'System.CPUTime.getCPUTime']);
// A salt is deliberately absent: it must be unique, not unpredictable or secret (it is stored beside the hash), so a non-cryptographic generator
// producing one is not a weakness the way it is for a token, nonce or key.
const SECURITY_FN_SUBSTR = /(?:token|nonce|secret|otp|csrf|session|apikey|resetcode|passcode|verification)/i;
// Short credential words that would over-match as substrings (`spin`, `mapping`, `keyboard`): matched as whole camelCase / snake_case words.
const SECURITY_WORDS = new Set(['pin', 'password', 'passwd', 'credential', 'credentials']);
const SECURITY_FN = { test: (name) => SECURITY_FN_SUBSTR.test(name) || String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).some((w) => SECURITY_WORDS.has(w)) };
const INPUT_READS = new Set(['Prelude.getContents', 'System.IO.getContents', 'System.IO.hGetContents', 'Data.ByteString.getContents', 'Data.ByteString.hGetContents', 'Data.ByteString.Char8.getContents', 'Data.ByteString.Char8.hGetContents', 'Data.ByteString.Lazy.getContents', 'Data.ByteString.Lazy.hGetContents', 'Data.ByteString.Lazy.Char8.getContents', 'Data.ByteString.Lazy.Char8.hGetContents', 'Data.Text.IO.getContents', 'Data.Text.IO.hGetContents', 'Data.Text.Lazy.IO.getContents', 'Data.Text.Lazy.IO.hGetContents']);
const BOUNDING = /(?:^|\.)(?:take|takeE|isolate|hGetSome|hGet|splitAt|limit|limitedRead)$/;
// `replicateM n getLine` reads n lines: the count is an allocation (and an input loop) sized by whoever supplied n.
const ALLOCATORS = new Set(['replicate', 'Prelude.replicate', 'Data.List.replicate', 'Data.ByteString.replicate', 'Data.ByteString.Char8.replicate', 'Data.ByteString.Lazy.replicate', 'Data.Text.replicate', 'Data.Vector.replicate', 'Control.Monad.replicateM', 'Control.Monad.replicateM_', 'Data.Vector.replicateM', 'Data.List.genericReplicate']);
const CLAMPS = /^(?:(?:Prelude|Data\.Ord)\.)?(?:min|clamp)$/;
const PARTIAL_NAMES = ['read', 'head', 'tail', 'last', 'init', 'maximum', 'minimum', 'foldr1', 'foldl1', 'maximumBy', 'minimumBy', 'toEnum', 'succ', 'pred', 'fromJust', 'cycle'];
const PARTIAL_MODULES = ['Prelude', 'Data.List', 'Data.Foldable', 'Data.Maybe'];
const PARTIALS = new Set([...PARTIAL_NAMES, ...PARTIAL_NAMES.flatMap((n) => PARTIAL_MODULES.map((m) => `${m}.${n}`)),
  ...['head', 'last', 'tail', 'init', 'maximum', 'minimum', 'index'].map((n) => `Data.Text.${n}`),
  // the Map/Set lookups and extremum selectors that raise on a missing key or an empty container
  ...['Data.Map', 'Data.Map.Strict', 'Data.HashMap.Strict', 'Data.IntMap', 'Data.IntMap.Strict'].map((m) => `${m}.!`),
  ...['Data.Map', 'Data.Map.Strict'].flatMap((m) => ['findMin', 'findMax', 'deleteFindMin', 'elemAt'].map((n) => `${m}.${n}`)), 'Data.Set.findMin', 'Data.Set.findMax', 'Data.Set.elemAt']);
// A call that tests whether a container is empty, a key is present or a value is available: the partial call beside it is conditional on that test.
const EMPTINESS_CHECK = /(?:^|\.)(?:null|notNull|isEmpty|length|size|isJust|isNothing|member|notMember|lookup|elem|notElem|nonEmpty|<match>)$/;
const SESSION_COOKIE = /(?:sess|sid|token|tok|auth|jwt|csrf|login|remember|secret)/i;

// What makes a bound variable security-shaped, and what makes a value sensitive for logging.
const SECURITY_VAR = /^(?:.*(?:token|secret|nonce|otp|csrf|apikey|api_?key|sessionid|session_?key|sessiontoken|resettoken)[a-z0-9_']*|key|iv|sessionId|sid)$/i;
const PASSWORD_VAR = /(?:^|[^a-z])(?:pass(?:word|wd|phrase)?|pwd|pw)(?:[^a-z]|$)|password/i;
const LOW_ENTROPY = /(?:pass(?:word|wd|phrase)?|pwd|ssn|creditcard|cardnumber|cvv|\bpin\b)/i;
export const SENSITIVE = /(?:pass(?:word|wd|phrase)?|pwd|(?:^|[^a-z])pw(?:[^a-z]|$)|secret|token|api_?key|ssn|credit_?card|card_?number|cvv|authorization|bearer|private_?key|session_?id)/i;
const REDACTOR = /(?:^|\.)(?:redact|mask|scrub|obfuscate|anonymi[sz]e|censor|length|null)$|(?:^|\.)(?:redact|mask|scrub|obfuscate|anonymi[sz]e|censor)/i;

const kids = (e) => {
  const out = [];
  for (const k of ['left', 'right', 'object', 'value', 'callee']) if (e[k] && typeof e[k] === 'object') out.push(e[k]);
  for (const k of ['args', 'elements', 'branches', 'parts']) if (Array.isArray(e[k])) out.push(...e[k]);
  if (Array.isArray(e.props)) for (const p of e.props) if (p && p.value) out.push(p.value);
  if (e.hs && e.hs.selector && typeof e.hs.selector === 'object') out.push(e.hs.selector);   // `lookup key t`: the key decides the outcome
  if (e.hs && e.hs.inner && typeof e.hs.inner === 'object') out.push(e.hs.inner);              // `read s :: Int`: a number to the taint engine, still an expression here
  return out;
};

function* walk(e, depth = 0) {
  if (!e || typeof e !== 'object' || depth > 80) return;
  yield e;
  for (const c of kids(e)) yield* walk(c, depth + 1);
}

function names(e, out = new Set()) {
  for (const x of walk(e)) {
    if (x.kind === 'ident' && x.name && !(x.hs && x.hs.functionRef)) out.add(x.name);
    if (x.kind === 'member' && x.prop) out.add(`.${x.prop}`);
  }
  return out;
}

const isLiteralLike = (e, depth = 0) => {
  if (!e || depth > 8) return false;
  if (e.kind === 'literal') return true;
  if (e.kind === 'array') return e.elements.length > 0 && e.elements.every((x) => isLiteralLike(x, depth + 1));
  // B.pack "lit", fromString "lit", replicate n lit, T.encodeUtf8 "lit": a conversion of constants is a constant
  if (e.kind === 'call' && /(?:^|\.)(?:pack|fromString|replicate|encodeUtf8|fromStrict|toStrict|singleton)$/.test(e.callee || '')) return (e.args || []).length > 0 && e.args.every((x) => isLiteralLike(x, depth + 1));
  return false;
};

// A concatenation of literals only (`"a=" <> "0" <> "; Path=/"`).
const constantConcat = (e, depth = 0) => {
  if (!e || depth > 12) return false;
  if (e.kind === 'literal') return true;
  if (e.kind === 'binary' && e.hs && e.hs.concat) return constantConcat(e.left, depth + 1) && constantConcat(e.right, depth + 1);
  if (e.kind === 'call' && /(?:^|\.)(?:pack|fromString|encodeUtf8|fromStrict|toStrict)$/.test(e.callee || '') && e.args && e.args.length === 1) return constantConcat(e.args[0], depth + 1);
  return false;
};

function fnNodes(fn) { return Object.values(fn.cfg.nodes); }

// The text a concatenation spells out, in order, skipping the parts that are not literals (`"session_id=" <> sid <> "; Path=/"` -> `session_id=; Path=/`).
function literalTextOf(e, depth = 0) {
  if (!e || depth > 12) return '';
  if (e.kind === 'literal' && typeof e.value === 'string') return e.value;
  if (e.kind === 'binary' && e.hs && e.hs.concat) return literalTextOf(e.left, depth + 1) + literalTextOf(e.right, depth + 1);
  if (e.kind === 'call' && /(?:^|\.)(?:pack|fromString|encodeUtf8|fromStrict|toStrict)$/.test(e.callee || '') && e.args && e.args.length === 1) return literalTextOf(e.args[0], depth + 1);
  return '';
}

function snippetOf(text, line) {
  if (!text || !Number.isInteger(line) || line < 1) return '';
  const l = text.split('\n')[line - 1];
  return typeof l === 'string' ? codeOfLine(l).slice(0, 240) : '';
}

// An unbounded read is a resource-exhaustion finding when the party that fills the input is not the operator. A handle opened on a
// local file, a child process's pipe or a handle passed in is the operator's own (a file's size is what the file system says); a
// socket or connection handle is filled by the peer. A read of standard input is the operator's in a program's own control flow, and
// the caller's only in an entry point nothing in the analysed code calls (a library function handing back whatever its caller pipes in).
const NETWORK_HANDLE_CALL = /(?:^|\.)(?:socketToHandle|connectTo|accept|acceptOn|openTCPConnection)$/;

/**
 * Are this function's callers outside the analysed code? With no project-reachability verdict, or an `unknown` one, the answer is exactly what it
 * has always been (nothing in the analysed code calls or references it). A function no caller can reach (`unreachable-in-project`) has none. One
 * reached from an entry point takes its parameters from that path, EXCEPT a root nothing in the analysed code calls (a framework handler, a foreign
 * export, code the parser withheld): its caller is outside.
 *
 * A function of an exposed module (`external-api`) is DELIBERATELY answered as today: the plan for this change said "a public API's callers are
 * external, so true", but for an exposed function that something in the project also calls that turns on the partial-function and unbounded-read
 * rules for every such function, and on the development set it added seven flagged sites and no true positive (precision 35.7% -> 23.8%). The
 * status is still recorded and still keeps the taint finding at full severity; it just does not widen these two rules. Flipping it is the one line
 * below, with that measurement as the cost.
 */
export function callersUnknown(fn) {
  const hs = (fn && fn.hs) || {};
  const r = hs.reachability || null;
  if (!r || r.status === 'unknown' || r.status === 'external-api') return !hs.reached;
  if (r.status === 'entrypoint-reachable') return !hs.reached && r.rootKind !== 'main';
  return false;
}
function readsOutsideInput(fn, callee, args, importsNetwork) {
  const h = args && args[0];
  const isStdin = !!h && h.kind === 'ident' && /(?:^|\.)stdin$/.test(h.name || '');
  const handleRead = /hGetContents$/.test(callee) && !isStdin;
  // the networking packages are not all in the model registry, so a call keeps its bare name; the module imports say which library it is
  if (handleRead) return !!importsNetwork && (fn.calls || []).some((x) => typeof x.callee === 'string' && NETWORK_HANDLE_CALL.test(x.callee));
  const hs = fn.hs || {};
  return callersUnknown(fn) && !/(?:^|\.)main$/.test(fn.name || '');
}

const EQUALITY_OPS = new Set(['==', '/=', '!=']);
const VERIFY_CALL = /(?:^|\.)(?:constEq|secureCompare|verify\w*|authenticate\w*|checkPassword|validate\w*|hmac\w*|sign\w*|jwt\w*|encode(?:Signed)?)$/i;
// Whole camelCase / snake_case words: `sig` must not match `design`, `mac` must not match `machine`.
const CREDENTIAL_WORDS = new Set(['token', 'secret', 'nonce', 'otp', 'csrf', 'apikey', 'session', 'signature', 'sig', 'mac', 'hmac', 'credential', 'credentials', 'auth', 'cookie', 'passcode', 'cert', 'fingerprint']);
const CREDENTIAL_NAME = { test: (name) => String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).some((w) => CREDENTIAL_WORDS.has(w)) };

/**
 * Why a weak-hash call is a security matter: the list is empty when the digest is only an identifier or its use is not visible.
 * Everything is read from the function's own IR (a value compared, bound to a credential-shaped name, hashing a secret-shaped value,
 * handed to a signing or verifying call); nothing is read from comments or from the file's name.
 */
function weakDigestUse(fn, node, hashCall, hashArgs, fnBase) {
  const reasons = [];
  const nodes = Object.values(fn.cfg.nodes);
  const exprsOf = (n) => [n.source, n.value, n.cond, ...(n.args || [])].filter(Boolean);
  const hasNode = (x, target) => { for (const y of walk(x)) if (y === target) return true; return false; };
  // 1. what is hashed
  const hashed = (hashArgs || []).flatMap((a) => [...names(a)]).map((n) => n.replace(/^\./, ''));
  if (hashed.some((n) => SENSITIVE.test(n) && !PASSWORD_VAR.test(n))) reasons.push('hashes a secret-shaped value');
  // 2. values carrying the digest: the assignment target and everything derived from it
  const carriers = new Set();
  // the digest travels through formatting (`show`, `pack`, hex encoding, concatenation), not through an arbitrary call that merely receives it
  const FORMAT = /(?:^|\.)(?:show|pack|unpack|take|drop|toLower|toUpper|showDigest|convertToBase|encode\w*|decode\w*|fromStrict|toStrict|toString|fromString|digestToHexByteString|toHex|hexlify|concat|append|map|fmap|fromText|toText)$/;
  const flowsFrom = (e, depth = 0) => {
    if (!e || depth > 10) return false;
    if (e === hashCall) return true;
    if (e.kind === 'ident') return carriers.has(e.name);
    if (e.kind === 'binary' && e.hs && e.hs.concat) return flowsFrom(e.left, depth + 1) || flowsFrom(e.right, depth + 1);
    if (e.kind === 'call' && typeof e.callee === 'string' && FORMAT.test(e.callee)) return (e.args || []).some((a) => flowsFrom(a, depth + 1));
    if (e.kind === 'call' && e === hashCall) return true;
    return false;
  };
  if (node.kind === 'assign' && node.target && node.source && flowsFrom(node.source)) carriers.add(node.target);
  for (let round = 0; round < 8; round++) {
    let grew = false;
    for (const n of nodes) if (n.kind === 'assign' && n.target && n.source && !carriers.has(n.target) && flowsFrom(n.source)) { carriers.add(n.target); grew = true; }
    if (!grew) break;
  }
  const carries = (x) => !!x && (flowsFrom(x) || [...names(x)].some((y) => carriers.has(y)));
  let compared = false; let signed = false;
  for (const n of nodes) {
    for (const root of exprsOf(n)) {
      for (const x of walk(root)) {
        if (x.kind === 'binary' && EQUALITY_OPS.has(x.op) && (carries(x.left) || carries(x.right))) compared = true;
        if (x.kind === 'call' && typeof x.callee === 'string' && VERIFY_CALL.test(x.callee) && (x.args || []).some((a) => carries(a))) signed = true;
      }
    }
  }
  if (compared) reasons.push('the digest is compared with another value');
  if (signed) reasons.push('the digest is passed to a verifying or signing call');
  // 3. what it becomes: a credential-shaped binding, or the result of a credential-shaped function
  const bound = [...carriers].find((c) => CREDENTIAL_NAME.test(c) || SECURITY_VAR.test(c));
  if (bound) reasons.push(`the digest is bound to \`${bound}\``);
  const returned = nodes.some((n) => n.kind === 'return' && n.value && carries(n.value));
  if (returned && (SECURITY_FN.test(fnBase) || CREDENTIAL_NAME.test(fnBase))) reasons.push(`the digest is the result of \`${fnBase}\``);
  return reasons;
}

/**
 * @param {Record<string,string>} files path -> source (only Haskell files are read)
 * @param {object} [opts]
 * @param {Record<string,string>} [opts.packageVersions] package name -> resolved version, when known
 * @returns {{findings: object[], controls: object[], notes: object[]}}
 */
export function analyzeHaskellRules(files, opts = {}) {
  const hs = {};
  for (const [f, t] of Object.entries(files || {})) if (/\.hs$/i.test(f) && typeof t === 'string') hs[f] = t;
  const findings = [];
  const controls = [];
  const notes = [];
  if (!Object.keys(hs).length) return { findings, controls, notes };

  const ir = buildHaskellIR(hs, opts.reachability || {});

  // project-level facts
  let requestLimit = null;
  for (const [file, text] of Object.entries(hs)) {
    if (/import\s+(?:qualified\s+)?Network\.Wai\.Middleware\.RequestSizeLimit\b/.test(text) || /\brequestSizeLimitMiddleware\b/.test(text)) { requestLimit = { file, line: (text.split('\n').findIndex((l) => /RequestSizeLimit|requestSizeLimitMiddleware/.test(l)) + 1) || 1 }; break; }
  }

  const emit = (rule, file, line, extra = {}) => {
    const r = RULES[rule];
    const sev = extra.severity || r.severity;
    const f = {
      id: `hs-rule:${rule}:${file}:${line}`, severity: sev, file, line, vuln: extra.vuln || r.vuln, cwe: r.cwe,
      description: `${extra.vuln || r.vuln}${extra.detail ? `: ${extra.detail}` : ''}`,
      remediation: r.remediation, parser: 'HS-RULES', family: r.family,
      language: 'haskell', capability: 'sast', analysisKind: 'application', evidenceKind: 'source',
      originalLocation: { file, line, column: 0 }, snippet: snippetOf(hs[file], line),
      confidence: extra.confidence ?? 0.8, rule, ruleVersion: 1, rulesetVersion: HS_RULES_VERSION, modelVersion: HS_MODEL_VERSION,
      ...(extra.uncertainty ? { uncertainty: extra.uncertainty } : {}),
      ...(extra.modelNote ? { modelNote: extra.modelNote } : {}),
      ...(extra.evidence ? { evidence: extra.evidence } : {}),
    };
    findings.push(f);
    return f;
  };

  for (const [file, fir] of Object.entries(ir.perFile)) {
    const importsNetwork = (fir.imports || []).some((im) => /^Network(?:\.|$)/.test(im.module));
    // imports of obsolete primitives (type-directed use is not resolved: disclosed on the finding)
    for (const imp of fir.imports || []) {
      if (WEAK_CIPHER_MODULES.has(imp.module)) {
        emit('hs-weak-cipher', file, imp.line, { vuln: `Broken or obsolete cipher module imported (${imp.module})`, confidence: 0.6, detail: 'the cipher type is selected by type, which is not resolved: the import is the evidence', evidence: { module: imp.module } });
      }
    }
    for (const fn of fir.functions) {
      if (fn.name.endsWith('.<module>')) continue;
      const bound = new Map();   // target var -> {callee, line}
      const sensitive = new Map(); // var -> {class:'low'|'high', hashed:boolean, line}

      const fnBase = fn.name.replace(/^.*\./, '');
      // text-typed parameters of an exported function, and every local value derived from them
      // A parameter a web framework hands to a handler IS request input wherever the handler is registered. Any other exported
      // function's text parameter is "caller-supplied" only while nothing in the analysed code calls the function: once something does,
      // its parameters take the values those callers pass (a check the taint engine makes per call), and a rule that does not follow
      // calls cannot say the text comes from outside.
      const fnHs = fn.hs || {};
      const strongParam = new Set((fnHs.paramSources || []).filter((p) => /^hs:handler-param:/.test(p.decorator || '')).map((p) => p.name));
      const entryLike = callersUnknown(fn);
      const derivedText = new Set([...(fnHs.textParams || []).filter((n) => strongParam.has(n) || entryLike), ...(entryLike ? (fnHs.inputParams || []) : [])]);
      if (derivedText.size) {
        for (let round = 0; round < 8; round++) {
          let grew = false;
          for (const n of fnNodes(fn)) if (n.kind === 'assign' && n.target && n.source && !derivedText.has(n.target) && [...names(n.source)].some((x) => derivedText.has(x))) { derivedText.add(n.target); grew = true; }
          if (!grew) break;
        }
      }
      const mentionsText = (e) => [...names(e)].some((x) => derivedText.has(x));
      const callsIn = (e) => { const out = []; for (const x of walk(e)) if (x.kind === 'call' && typeof x.callee === 'string') out.push(x); return out; };
      const fnReturns = fnNodes(fn).filter((n) => n.kind === 'return' && n.value);
      const bounded = fnNodes(fn).some((n) => [n.value, n.source, ...(n.args || [])].some((e) => e && callsIn(e).some((c) => BOUNDING.test(c.callee))));

      // Values a condition in this function tests for emptiness or presence (`null ws`, `M.member k t`, `xs /= []`, a pattern match on it) and,
      // transitively, the values they were built from: a partial call on one of them is the other branch of that test.
      const assignSources = new Map();
      for (const n of fnNodes(fn)) if (n.kind === 'assign' && n.target && n.source) assignSources.set(n.target, [...(assignSources.get(n.target) || []), ...names(n.source)]);
      const withOrigins = (seed) => { const out = new Set(seed); const queue = [...seed]; while (queue.length) { const v = queue.pop(); for (const o of assignSources.get(v) || []) if (!out.has(o)) { out.add(o); queue.push(o); } } return out; };
      const testedVars = new Set();
      for (const n of fnNodes(fn)) {
        if (n.kind !== 'if' || !n.cond) continue;
        for (const x of walk(n.cond)) {
          if (x.kind === 'call' && typeof x.callee === 'string' && EMPTINESS_CHECK.test(x.callee)) for (const nm of names(x)) testedVars.add(nm);
          if (x.kind === 'binary' && ['==', '/=', '!='].includes(x.op) && [x.left, x.right].some((side) => side && side.kind === 'array' && side.elements.length === 0)) for (const nm of names(x)) testedVars.add(nm);
        }
      }
      const testedAll = withOrigins(testedVars);
      const isTested = (args) => { const mine = withOrigins([...args.flatMap((a) => [...names(a)])]); for (const v of mine) if (testedAll.has(v) && derivedText.has(v)) return true; return false; };

      // A relational test against a number or a length (`total >= limit`, `size <= 65536`) in this function: the evidence that a read or a body is capped.
      const hasSizeTest = fnNodes(fn).some((n) => n.kind === 'if' && n.cond && [...walk(n.cond)].some((x) => x.kind === 'binary' && RELATIONAL.has(x.op)));
      const readsRequestLength = fnNodes(fn).some((n) => [n.value, n.source, n.cond, ...(n.args || [])].some((ex) => ex && [...walk(ex)].some((x) => (x.kind === 'ident' && REQUEST_LENGTH.has(x.name)) || (x.kind === 'call' && REQUEST_LENGTH.has(x.callee)))));
      const sizeChecked = hasSizeTest && readsRequestLength;
      // One predictable-random finding per function: a clock reading that seeds a generator in a token-shaped function is a single flaw,
      // however many of its steps (the clock, the seed, the generator) the rule can see.
      let randomEmitted = false;
      const emitRandom = (line, extra) => { if (randomEmitted) return; randomEmitted = true; emit('hs-predictable-random', file, line, extra); };

      const seeds = (e) => { for (const n of names(e)) if (SENSITIVE.test(n.replace(/^\./, ''))) return n.replace(/^\./, ''); return null; };

      // pass over nodes in program order
      for (const node of fnNodes(fn)) {
        const exprs = [];
        if (node.kind === 'assign' && node.source) exprs.push(node.source);
        if (node.kind === 'return' && node.value) exprs.push(node.value);
        if (node.kind === 'call') exprs.push({ kind: 'call', callee: node.callee, args: node.args || [], line: node.line });
        if (node.kind === 'if' && node.cond) exprs.push(node.cond);

        for (const root of exprs) {
          for (const e of walk(root)) {
            if (e.kind === 'ident') {
              if (e.name === 'Crypto.Cipher.Types.nullIV') emit('hs-static-iv', file, node.line, { vuln: 'Static IV (nullIV)', detail: 'nullIV is a constant all-zero IV' });
              // a clock reading used as the value of a security-shaped function (a "nonce" that is the time)
              if (TIME_SOURCES.has(e.name) && SECURITY_FN.test(fnBase)) emitRandom(node.line, { vuln: 'Clock value used as a security value', detail: `${e.name} feeds \`${fnBase}\``, evidence: { function: fnBase, source: e.name } });
              // a generator named as the whole value of a security-shaped action (`newCsrfToken = randomIO`): no call is written, the name is the call
              if (RANDOM_CALLS.has(e.name) && SECURITY_FN.test(fnBase) && !(e.hs && e.hs.functionRef)) emitRandom(node.line, { detail: `${e.name} feeds \`${fnBase}\``, evidence: { function: fnBase, source: e.name } });
              if (INPUT_READS.has(e.name) && !bounded && readsOutsideInput(fn, e.name, [], importsNetwork)) emit('hs-unbounded-input-read', file, node.line, { detail: `${e.name} reads everything`, confidence: 0.6 });
              continue;
            }
            // a Set-Cookie header written by hand: `(hSetCookie, "session_id=" <> sid <> "; Path=/")`
            if (e.kind === 'array' && e.hs && e.hs.tuple && e.elements.length === 2) {
              const [k, v] = e.elements;
              const isSetCookie = k && ((k.kind === 'ident' && SET_COOKIE_HEADER.has(k.name)) || (k.kind === 'literal' && /^set-cookie$/i.test(String(k.value))) || (k.kind === 'call' && /(?:^|\.)(?:pack|fromString)$/.test(k.callee || '') && k.args && k.args[0] && k.args[0].kind === 'literal' && /^set-cookie$/i.test(String(k.args[0].value))));
              if (isSetCookie && v) {
                const text = literalTextOf(v);
                const nm = /^\s*([^=;\s]+)\s*=/.exec(text);
                const sessionLike = !nm || SESSION_COOKIE.test(nm[1]);
                const secure = /;\s*Secure\b/i.test(text); const httpOnly = /;\s*HttpOnly\b/i.test(text);
                // an attribute string that is not written here (a rendered cookie value) cannot be judged: only a cookie whose text is visible is
                // a header value that is entirely constant text (`authn=0` written to clear a login) carries no per-user credential
                if (text && sessionLike && !isLiteralLike(v) && !constantConcat(v) && (!secure || !httpOnly)) emit('hs-insecure-cookie', file, e.line || node.line, { detail: `${!httpOnly ? 'HttpOnly missing' : ''}${!httpOnly && !secure ? ', ' : ''}${!secure ? 'Secure missing' : ''}`, evidence: { httpOnly, secure, cookie: nm ? nm[1] : null } });
              }
            }
            if (e.kind === 'object' && e.hs && e.hs.update && Array.isArray(e.props)) {
              const prop = (k) => e.props.find((p) => p && p.key === k);
              // servant-auth: `cookieIsSecure = NotSecure` sends the session cookie over plain HTTP too
              const secureSetting = prop('cookieIsSecure');
              if (secureSetting && secureSetting.value && /(?:^|\.)NotSecure$/.test(String(secureSetting.value.value || secureSetting.value.name || '')) && (fir.imports || []).some((im) => im.module === 'Servant.Auth.Server')) {
                emit('hs-insecure-cookie', file, e.line || node.line, { vuln: 'Session cookie sent without the Secure attribute', detail: 'cookieIsSecure = NotSecure', evidence: { setting: 'cookieIsSecure', value: 'NotSecure' } });
              }
              if (prop('setCookieName')) {
                const nm = prop('setCookieName').value;
                const sessionLike = !nm || nm.kind !== 'literal' || SESSION_COOKIE.test(String(nm.value));
                const isTrue = (p) => p && p.value && ((p.value.kind === 'literal' && /^true$/i.test(String(p.value.value))) || (p.value.kind === 'ident' && /\.True$/.test(p.value.name)));
                const httpOnly = isTrue(prop('setCookieHttpOnly')); const secure = isTrue(prop('setCookieSecure'));
                if (sessionLike && (!httpOnly || !secure)) {
                  emit('hs-insecure-cookie', file, node.line, { detail: `${!httpOnly ? 'HttpOnly missing' : ''}${!httpOnly && !secure ? ', ' : ''}${!secure ? 'Secure missing' : ''}`, evidence: { httpOnly, secure, sameSite: !!prop('setCookieSameSite') } });
                }
              }
              continue;
            }
            // TLS certificate validation switched off, by constructor
            if (e.hs && e.hs.con) {
              const importsFrom = (mods) => (fir.imports || []).some((im) => mods.includes(im.module));
              if (e.hs.con === 'TLSSettingsSimple' && importsFrom(['Network.Connection', 'Network.Connection.Types'])) {
                const positional = e.kind === 'array' && isTrueLit(e.elements[0]);
                const named = e.kind === 'object' && (e.props || []).some((p) => p && p.key === 'settingDisableCertificateValidation' && isTrueLit(p.value));
                if (positional || named) emit('hs-tls-validation-disabled', file, e.line || node.line, { detail: 'TLSSettingsSimple with settingDisableCertificateValidation = True', evidence: { setting: 'settingDisableCertificateValidation' } });
              }
              if (e.hs.con === 'VerifyNone' && e.kind === 'literal' && importsFrom(['OpenSSL.Session'])) emit('hs-tls-validation-disabled', file, e.line || node.line, { detail: 'OpenSSL verification mode VerifyNone', evidence: { mode: 'VerifyNone' } });
            }
            // `xs !! n` raises on a short list: a partial function, written as an operator, applied to caller-supplied text
            if (e.kind === 'binary' && e.op === '!!' && e.left && mentionsText(e.left) && !isTested([e.left])) {
              emit('hs-partial-function-on-input', file, e.line || node.line, { detail: '!! on a caller-supplied list', evidence: { partial: '!!' } });
              continue;
            }
            if (e.kind !== 'call' || typeof e.callee !== 'string') continue;
            const c = e.callee;
            const line = e.line || node.line;
            const args = e.args || [];

            // scotty-cookie's helpers build a cookie that carries neither Secure nor HttpOnly
            if ((c === 'Web.Scotty.Cookie.setSimpleCookie' || c === 'Web.Scotty.Cookie.makeSimpleCookie') && args[0]) {
              const nm = args[0];
              if (nm.kind !== 'literal' || SESSION_COOKIE.test(String(nm.value))) emit('hs-insecure-cookie', file, line, { detail: 'HttpOnly missing, Secure missing', evidence: { httpOnly: false, secure: false, helper: c } });
            }
            // a socket read repeated by a recursive loop, with no size test anywhere in it
            if (SOCKET_READS.has(c) && !hasSizeTest && !bounded && fn.calls.some((x) => x.callee === fn.name && x.hs && x.hs.target === fn.qid)) {
              emit('hs-unbounded-input-read', file, line, { detail: `${c} is repeated by a loop that never compares the amount read with a limit`, confidence: 0.6, evidence: { read: c, loop: fnBase } });
            }
            // TLS certificate validation switched off
            // a signing/encryption secret that is a constant in the source
            if (SECRET_KEY_CALLS.has(c) && args[0] && isLiteralLike(args[0]) && !(args[0].kind === 'literal' && String(args[0].value).length < 8)) emit('hs-hardcoded-secret', file, line, { detail: `${c} given a constant`, confidence: 0.85, evidence: { call: c } });
            // weak hash
            if (WEAK_HASH_CALLS.has(c) || (c === 'Crypto.Hash.hashWith' && args[0] && args[0].kind === 'literal' && WEAK_ALGO_CONS.has(args[0].value))) {
              const pw = args.some((a) => [...names(a)].some((n) => PASSWORD_VAR.test(n)));
              // MD5 and SHA-1 are broken for collision and preimage resistance, which only matters where an attacker gains from a
              // collision: a digest that is VERIFIED (compared with an expected value), that authenticates or signs, that hashes a
              // secret, or that is a credential. A digest that only NAMES something (a file name, a cache key, a bookmark, an ETag) is
              // an identifier, and a hash helper handed on to callers says nothing about its use: neither is a finding.
              if (!pw) {
                const use = weakDigestUse(fn, node, e, args, fnBase);
                // The API identity is always reported (a reviewer wants to know where MD5/SHA-1 is computed); it is a vulnerability
                // finding only where a use that depends on the hash's strength is visible. Otherwise it is an `info` note.
                if (use.length) emit('hs-weak-hash', file, line, { detail: `${c}: ${use.join('; ')}`, evidence: { call: c, use } });
                else emit('hs-weak-hash', file, line, { severity: 'info', confidence: 0.4, detail: `${c}: no use that depends on the digest's collision or preimage resistance is visible (it may only name or key something)`, evidence: { call: c, use: [] } });
              }
            }
            // password hashed with a fast hash
            if (ANY_HASH_CALLS.has(c) && !STRONG_KDF.test(c) && args.some((a) => [...names(a)].some((n) => PASSWORD_VAR.test(n.replace(/^\./, ''))))) {
              emit('hs-fast-password-hash', file, line, { detail: `${c} applied to a password-shaped value` });
            }
            if (PBKDF2_CALLS.has(c)) {
              for (const a of args) for (const x of walk(a)) if (x.kind === 'object') for (const p of x.props || []) if (p.key === 'iterCounts' && p.value && p.value.kind === 'literal' && typeof p.value.value === 'number' && p.value.value < 10000) {
                emit('hs-pbkdf2-low-iterations', file, line, { detail: `iterCounts = ${p.value.value}`, evidence: { iterations: p.value.value, threshold: 10000 } });
              }
            }
            // cipher mode / IV
            if (ECB_CALLS.has(c)) emit('hs-ecb-mode', file, line, { detail: c });
            if (IV_CALLS.has(c) && args[0] && isLiteralLike(args[0])) emit('hs-static-iv', file, line, { detail: `${c} of a constant value` });
            // randomness bound to a security-shaped name
            if (RANDOM_CALLS.has(c) && node.kind === 'assign' && SECURITY_VAR.test(node.target || '')) {
              emitRandom(line, { detail: `${c} result bound to \`${node.target}\``, evidence: { binding: node.target } });
            }
            if (RANDOM_CALLS.has(c) && SECURITY_FN.test(fnBase) && node.kind !== 'assign') {
              emitRandom(line, { detail: `${c} feeds \`${fnBase}\``, evidence: { function: fnBase, source: c } });
            }
            if (TIME_SOURCES.has(c) && SECURITY_FN.test(fnBase)) emitRandom(line, { vuln: 'Clock value used as a security value', detail: `${c} feeds \`${fnBase}\``, evidence: { function: fnBase, source: c } });
            if (INPUT_READS.has(c) && !bounded && readsOutsideInput(fn, c, args, importsNetwork)) emit('hs-unbounded-input-read', file, line, { detail: `${c} reads everything`, confidence: 0.6 });
            // an allocation whose size is parsed caller text and is not clamped
            if (ALLOCATORS.has(c) && args[0] && mentionsText(args[0]) && callsIn(args[0]).some((x) => /(?:^|\.)(?:read|readMaybe|readEither)$/.test(x.callee)) && !callsIn(args[0]).some((x) => CLAMPS.test(x.callee))) {
              emit('hs-unbounded-allocation', file, line, { detail: `${c} sized by parsed caller text`, evidence: { allocator: c } });
            }
            // a partial function applied to caller text: one malformed value raises an uncaught exception
            if (PARTIALS.has(c) && args.some((a) => mentionsText(a)) && !isTested(args)) emit('hs-partial-function-on-input', file, line, { detail: `${c} on caller-supplied input`, evidence: { partial: c } });
            // a session/token cookie assembled without HttpOnly or Secure
            if (c === 'Web.Cookie.defaultSetCookie') { /* handled on the record update below */ }
            // unbounded body
            if (BODY_CALLS.has(c) && !sizeChecked && !(c === 'Network.Wai.Conduit.sourceRequestBody' && bounded)) {
              if (requestLimit) {
                controls.push({ kind: 'request-size-limit', file: requestLimit.file, line: requestLimit.line, appliesTo: `${file}:${line}`, verified: false });
                emit('hs-unbounded-request-body', file, line, { severity: 'low', confidence: 0.4, detail: c, uncertainty: [{ kind: 'unresolved-import', detail: `a request-size-limit middleware exists (${requestLimit.file}:${requestLimit.line}); that it wraps this handler is not verified` }] });
              } else emit('hs-unbounded-request-body', file, line, { detail: c });
            }
            // XML entity substitution (explicit opt-in only)
            if (c === 'Text.XML.HXT.Core.withSubstDTDEntities' && args[0]) {
              const a = args[0];
              const yes = (a.kind === 'ident' && /\.yes$/.test(a.name)) || (a.kind === 'literal' && /^true$/i.test(String(a.value)));
              if (yes) emit('hs-xml-entity-substitution', file, line, { detail: 'withSubstDTDEntities yes' });
            }
            // boundaries
            if (Object.hasOwn(UNSAFE_CALLS, c)) {
              const b = UNSAFE_CALLS[c];
              emit('hs-unsafe-io-boundary', file, line, { vuln: `Unsafe boundary: ${b}`, confidence: 0.5, modelNote: BOUNDARIES[b], detail: BOUNDARIES[b] });
            }
          }
        }

        // ── sensitive logging: forward propagation through assignments and conversions ──
        if (node.kind === 'assign' && node.source) {
          const src = node.source;
          const srcNames = names(src);
          let cls = null; let hashed = false;
          const seed = seeds(src);
          if (seed) cls = { name: seed, low: LOW_ENTROPY.test(seed) };
          for (const n of srcNames) if (sensitive.has(n)) { const s = sensitive.get(n); cls = { name: s.name, low: s.low }; hashed = hashed || s.hashed; }
          if (cls) {
            let cleared = false;
            for (const x of walk(src)) {
              if (x.kind !== 'call' || typeof x.callee !== 'string') continue;
              if (REDACTOR.test(x.callee)) cleared = true;
              if (STRONG_KDF.test(x.callee)) cleared = true;
              if (ANY_HASH_CALLS.has(x.callee) && !STRONG_KDF.test(x.callee)) { if (cls.low) hashed = true; else cleared = true; }
              if (x.callee === 'const') cleared = true;
            }
            if (!cleared) sensitive.set(node.target, { name: cls.name, low: cls.low, hashed, line: node.line });
            else sensitive.delete(node.target);
          } else if (sensitive.has(node.target)) sensitive.delete(node.target);
        }
        for (const root of exprs) {
          for (const e of walk(root)) {
            if (e.kind !== 'call' || typeof e.callee !== 'string') continue;
            const sink = HS_LOG_SINKS.find((s) => `${s.module}.${s.name}` === e.callee);
            if (!sink) continue;
            // a variadic log call (printf) interpolates every argument after the format into the message: each is judged on its own, so one
            // redacted value never clears a credential passed beside it
            const argList = sink.argFrom !== undefined ? (e.args || []).slice(sink.argFrom) : [(e.args || [])[sink.argIndex]];
            if (!argList.length || argList.every((a) => !a)) continue;
            // a file append is a log only when its path says so (a log, audit or trace file)
            if (sink.channel === 'file') { const p = (e.args || [])[0]; if (!(p && p.kind === 'literal' && /(?:log|audit|trace|journal)/i.test(String(p.value)))) continue; }
            const isRedacted = (a) => { for (const x of walk(a)) if (x.kind === 'call' && typeof x.callee === 'string' && (REDACTOR.test(x.callee) || STRONG_KDF.test(x.callee) || x.callee === 'const')) return true; return false; };
            for (const arg of argList) {
              if (!arg) continue;
              let hit = null;
              // a labelled value: a literal that names a credential ("token=", "password: ") followed by a non-literal operand
              for (const x of walk(arg)) {
                if (x.kind === 'binary' && x.hs && x.hs.concat && x.left && x.left.kind === 'literal' && typeof x.left.value === 'string' && /^\s*[\w .-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api_?key|authorization|bearer|private_?key|session_?id)[\w .-]*\s*[=:]\s*$/i.test(x.left.value) && x.right && x.right.kind !== 'literal') {
                  const lab = x.left.value.replace(/[=:\s]+$/, '').trim();
                  hit = { name: lab, low: LOW_ENTROPY.test(lab), hashed: false, var: lab };
                  break;
                }
              }
              for (const n of names(arg)) {
                if (hit) break;
                const bare = n.replace(/^\./, '');
                if (sensitive.has(n)) hit = { ...sensitive.get(n), var: n };
                else if (SENSITIVE.test(bare) && !/^[A-Z][A-Za-z0-9_.]*\./.test(n)) hit = { name: bare, low: LOW_ENTROPY.test(bare), hashed: false, var: n };
                if (hit) break;
              }
              if (hit && !isRedacted(arg)) {
                emit('hs-sensitive-logging', file, e.line || node.line, {
                  severity: hit.hashed ? 'low' : 'high',
                  detail: hit.hashed ? `a fast hash of low-entropy \`${hit.name}\` reaches ${e.callee}` : `\`${hit.name}\` reaches ${e.callee}`,
                  evidence: { value: hit.name, via: hit.var, channel: sink.channel, hashed: hit.hashed },
                });
                break;
              }
            }
          }
        }
      }
    }
  }

  // de-duplicate (a call visited through both a node and its parent expression)
  const seen = new Set();
  const out = [];
  for (const f of findings) { if (seen.has(f.id)) continue; seen.add(f.id); out.push(f); }
  void notes; void opts;
  return { findings: out, controls, notes };
}
