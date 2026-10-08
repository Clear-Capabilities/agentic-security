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
  'hs-unsafe-io-boundary': { cwe: 'CWE-676', severity: 'low', family: 'unsafe-boundary', vuln: 'Unsafe IO / coercion boundary', remediation: 'Confine `unsafePerformIO`/`unsafeCoerce` to audited, well-tested wrappers.' },
});

// Modelled boundaries and what each does and does NOT claim. Reported verbatim on the finding.
export const BOUNDARIES = Object.freeze({
  unsafePerformIO: 'Runs an IO action as a pure value. Modelled as a code-quality/safety boundary only; no vulnerability class (including CWE-502) is claimed.',
  unsafeInterleaveIO: 'Defers an IO action until demanded. Modelled as a boundary only.',
  unsafeDupablePerformIO: 'Like unsafePerformIO without the thunk lock. Modelled as a boundary only.',
  unsafeCoerce: 'Reinterprets a value as another type without a check. Modelled as a boundary only.',
});

const WEAK_HASH_CALLS = new Set(['Crypto.Hash.MD5.hash', 'Crypto.Hash.MD5.hashlazy', 'Crypto.Hash.SHA1.hash', 'Crypto.Hash.SHA1.hashlazy', 'Data.Digest.Pure.MD5.md5', 'Data.Digest.Pure.SHA.sha1']);
const WEAK_ALGO_CONS = new Set(['MD5', 'MD4', 'MD2', 'SHA1']);
const ANY_HASH_CALLS = new Set([...WEAK_HASH_CALLS, 'Crypto.Hash.hash', 'Crypto.Hash.hashlazy', 'Crypto.Hash.hashWith', 'Crypto.Hash.SHA256.hash', 'Crypto.Hash.SHA256.hashlazy', 'Crypto.Hash.SHA512.hash', 'Crypto.Hash.SHA512.hashlazy', 'Data.Digest.Pure.SHA.sha256', 'Data.Digest.Pure.SHA.sha512']);
const WEAK_CIPHER_MODULES = new Set(['Crypto.Cipher.DES', 'Crypto.Cipher.RC4', 'Crypto.Cipher.RC2', 'Crypto.Cipher.Blowfish']);
const ECB_CALLS = new Set(['Crypto.Cipher.Types.ecbEncrypt', 'Crypto.Cipher.Types.ecbDecrypt']);
const IV_CALLS = new Set(['Crypto.Cipher.Types.makeIV', 'Crypto.Cipher.ChaChaPoly1305.nonce12', 'Crypto.Cipher.ChaChaPoly1305.nonce8']);
const RANDOM_CALLS = new Set(['System.Random.randomRIO', 'System.Random.randomIO', 'System.Random.newStdGen', 'System.Random.getStdGen', 'System.Random.mkStdGen', 'System.Random.randomR', 'System.Random.random', 'System.Random.randoms', 'System.Random.randomRs']);
const BODY_CALLS = new Set(['Network.Wai.strictRequestBody', 'Network.Wai.lazyRequestBody', 'Web.Scotty.body', 'Web.Scotty.Trans.body']);
const PBKDF2_CALLS = new Set(['Crypto.KDF.PBKDF2.generate', 'Crypto.KDF.PBKDF2.fastPBKDF2_SHA1', 'Crypto.KDF.PBKDF2.fastPBKDF2_SHA256', 'Crypto.KDF.PBKDF2.fastPBKDF2_SHA512']);
const STRONG_KDF = /^(?:Crypto\.KDF\.BCrypt\.|Crypto\.Argon2\.|Crypto\.Scrypt\.|Crypto\.KDF\.Scrypt\.|Crypto\.PasswordStore\.|Crypto\.BCrypt\.)/;
const UNSAFE_CALLS = { 'System.IO.Unsafe.unsafePerformIO': 'unsafePerformIO', 'System.IO.Unsafe.unsafeInterleaveIO': 'unsafeInterleaveIO', 'System.IO.Unsafe.unsafeDupablePerformIO': 'unsafeDupablePerformIO', 'Unsafe.Coerce.unsafeCoerce': 'unsafeCoerce' };

const TIME_SOURCES = new Set(['Data.Time.Clock.POSIX.getPOSIXTime', 'Data.Time.Clock.getCurrentTime', 'System.CPUTime.getCPUTime']);
const SECURITY_FN_SUBSTR = /(?:token|nonce|secret|otp|csrf|session|salt|apikey|resetcode|passcode|verification)/i;
// Short credential words that would over-match as substrings (`spin`, `mapping`, `keyboard`): matched as whole camelCase / snake_case words.
const SECURITY_WORDS = new Set(['pin', 'password', 'passwd', 'credential', 'credentials']);
const SECURITY_FN = { test: (name) => SECURITY_FN_SUBSTR.test(name) || String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).some((w) => SECURITY_WORDS.has(w)) };
const INPUT_READS = new Set(['Prelude.getContents', 'System.IO.getContents', 'System.IO.hGetContents', 'Data.ByteString.getContents', 'Data.ByteString.hGetContents', 'Data.ByteString.Char8.getContents', 'Data.ByteString.Char8.hGetContents', 'Data.ByteString.Lazy.getContents', 'Data.ByteString.Lazy.hGetContents', 'Data.ByteString.Lazy.Char8.getContents', 'Data.ByteString.Lazy.Char8.hGetContents', 'Data.Text.IO.getContents', 'Data.Text.IO.hGetContents', 'Data.Text.Lazy.IO.getContents', 'Data.Text.Lazy.IO.hGetContents']);
const BOUNDING = /(?:^|\.)(?:take|hGetSome|hGet|splitAt|limit|limitedRead)$/;
// `replicateM n getLine` reads n lines: the count is an allocation (and an input loop) sized by whoever supplied n.
const ALLOCATORS = new Set(['replicate', 'Prelude.replicate', 'Data.List.replicate', 'Data.ByteString.replicate', 'Data.ByteString.Char8.replicate', 'Data.ByteString.Lazy.replicate', 'Data.Text.replicate', 'Data.Vector.replicate', 'Control.Monad.replicateM', 'Control.Monad.replicateM_', 'Data.Vector.replicateM', 'Data.List.genericReplicate']);
const CLAMPS = /^(?:(?:Prelude|Data\.Ord)\.)?(?:min|clamp)$/;
const PARTIALS = new Set(['read', 'Prelude.read', 'head', 'Prelude.head', 'Data.List.head', 'tail', 'Prelude.tail', 'Data.List.tail', 'last', 'Prelude.last', 'Data.List.last', 'init', 'Prelude.init', 'Data.List.init', 'Data.Maybe.fromJust', 'fromJust']);
const SESSION_COOKIE = /(?:sess|sid|token|tok|auth|jwt|csrf|login|remember|secret)/i;

// What makes a bound variable security-shaped, and what makes a value sensitive for logging.
const SECURITY_VAR = /^(?:.*(?:token|secret|nonce|salt|otp|csrf|apikey|api_?key|sessionid|session_?key|sessiontoken|resettoken)[a-z0-9_']*|key|iv|sessionId|sid)$/i;
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

function fnNodes(fn) { return Object.values(fn.cfg.nodes); }

function snippetOf(text, line) {
  if (!text || !Number.isInteger(line) || line < 1) return '';
  const l = text.split('\n')[line - 1];
  return typeof l === 'string' ? l.trim().slice(0, 240) : '';
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

  const ir = buildHaskellIR(hs);

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
      const derivedText = new Set((fn.hs && fn.hs.textParams) || []);
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
              if (TIME_SOURCES.has(e.name) && SECURITY_FN.test(fnBase)) emit('hs-predictable-random', file, node.line, { vuln: 'Clock value used as a security value', detail: `${e.name} feeds \`${fnBase}\``, evidence: { function: fnBase, source: e.name } });
              if (INPUT_READS.has(e.name) && !bounded) emit('hs-unbounded-input-read', file, node.line, { detail: `${e.name} reads everything`, confidence: 0.6 });
              continue;
            }
            if (e.kind === 'object' && e.hs && e.hs.update && Array.isArray(e.props)) {
              const prop = (k) => e.props.find((p) => p && p.key === k);
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
            // `xs !! n` raises on a short list: a partial function, written as an operator, applied to caller-supplied text
            if (e.kind === 'binary' && e.op === '!!' && e.left && mentionsText(e.left)) {
              emit('hs-partial-function-on-input', file, e.line || node.line, { detail: '!! on a caller-supplied list', evidence: { partial: '!!' } });
              continue;
            }
            if (e.kind !== 'call' || typeof e.callee !== 'string') continue;
            const c = e.callee;
            const line = e.line || node.line;
            const args = e.args || [];

            // weak hash
            if (WEAK_HASH_CALLS.has(c) || (c === 'Crypto.Hash.hashWith' && args[0] && args[0].kind === 'literal' && WEAK_ALGO_CONS.has(args[0].value))) {
              const pw = args.some((a) => [...names(a)].some((n) => PASSWORD_VAR.test(n)));
              if (!pw) emit('hs-weak-hash', file, line, { detail: c });
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
              emit('hs-predictable-random', file, line, { detail: `${c} result bound to \`${node.target}\``, evidence: { binding: node.target } });
            }
            if (RANDOM_CALLS.has(c) && SECURITY_FN.test(fnBase) && node.kind !== 'assign') {
              emit('hs-predictable-random', file, line, { detail: `${c} feeds \`${fnBase}\``, evidence: { function: fnBase, source: c } });
            }
            if (TIME_SOURCES.has(c) && SECURITY_FN.test(fnBase)) emit('hs-predictable-random', file, line, { vuln: 'Clock value used as a security value', detail: `${c} feeds \`${fnBase}\``, evidence: { function: fnBase, source: c } });
            if (INPUT_READS.has(c) && !bounded) emit('hs-unbounded-input-read', file, line, { detail: `${c} reads everything`, confidence: 0.6 });
            // an allocation whose size is parsed caller text and is not clamped
            if (ALLOCATORS.has(c) && args[0] && mentionsText(args[0]) && callsIn(args[0]).some((x) => /(?:^|\.)(?:read|readMaybe|readEither)$/.test(x.callee)) && !callsIn(args[0]).some((x) => CLAMPS.test(x.callee))) {
              emit('hs-unbounded-allocation', file, line, { detail: `${c} sized by parsed caller text`, evidence: { allocator: c } });
            }
            // a partial function applied to caller text: one malformed value raises an uncaught exception
            if (PARTIALS.has(c) && args.some((a) => mentionsText(a))) emit('hs-partial-function-on-input', file, line, { detail: `${c} on caller-supplied text`, evidence: { partial: c } });
            // a session/token cookie assembled without HttpOnly or Secure
            if (c === 'Web.Cookie.defaultSetCookie') { /* handled on the record update below */ }
            // unbounded body
            if (BODY_CALLS.has(c)) {
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
            if (UNSAFE_CALLS[c]) {
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
            const arg = (e.args || [])[sink.argIndex];
            if (!arg) continue;
            // a file append is a log only when its path says so (a log, audit or trace file)
            if (sink.channel === 'file') { const p = (e.args || [])[0]; if (!(p && p.kind === 'literal' && /(?:log|audit|trace|journal)/i.test(String(p.value)))) continue; }
            let hit = null;
            // a labelled value: a literal that names a credential ("token=", "password: ") followed by a non-literal operand
            if (!hit) {
              for (const x of walk(arg)) {
                if (x.kind === 'binary' && x.hs && x.hs.concat && x.left && x.left.kind === 'literal' && typeof x.left.value === 'string' && /^\s*[\w .-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api_?key|authorization|bearer|private_?key|session_?id)[\w .-]*\s*[=:]\s*$/i.test(x.left.value) && x.right && x.right.kind !== 'literal') {
                  const lab = x.left.value.replace(/[=:\s]+$/, '').trim();
                  hit = { name: lab, low: LOW_ENTROPY.test(lab), hashed: false, var: lab };
                  break;
                }
              }
            }
            for (const n of names(arg)) {
              if (hit) break;
              const bare = n.replace(/^\./, '');
              if (sensitive.has(n)) hit = { ...sensitive.get(n), var: n };
              else if (SENSITIVE.test(bare) && !/^[A-Z][A-Za-z0-9_.]*\./.test(n)) hit = { name: bare, low: LOW_ENTROPY.test(bare), hashed: false, var: n };
              if (hit) break;
            }
            // redaction applied inline at the call site
            let inlineCleared = false;
            for (const x of walk(arg)) if (x.kind === 'call' && typeof x.callee === 'string' && (REDACTOR.test(x.callee) || STRONG_KDF.test(x.callee) || x.callee === 'const')) inlineCleared = true;
            if (hit && !inlineCleared) {
              emit('hs-sensitive-logging', file, e.line || node.line, {
                severity: hit.hashed ? 'low' : 'high',
                detail: hit.hashed ? `a fast hash of low-entropy \`${hit.name}\` reaches ${e.callee}` : `\`${hit.name}\` reaches ${e.callee}`,
                evidence: { value: hit.name, via: hit.var, channel: sink.channel, hashed: hit.hashed },
              });
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
