// Deterministic fix synthesis: for the narrow set of cases where the right transformation is decidable from the code itself, produce a
// full-file replacement from the current file content. No LLM, no guessing. Every patch is still gated by the central verifier before
// anything writes it.
//
// Verified-remediation PRD FR-01 (GAP-01). The weak-hash rule used to accept CWE-916 and swap md5/sha1 for sha256 everywhere in the file.
// For a password that is the wrong mechanism (a fast hash is not a password KDF), and for a checksum another system recomputes it breaks
// compatibility. So the transformation is now chosen by the PURPOSE of the one operation the finding names:
//
//   password-storage                 a salted password KDF (scrypt, which Node's crypto and Python's hashlib ship) PLUS a verify function
//                                    that still accepts the legacy format and says when to rehash, and the file's comparisons of the old
//                                    hash rewritten to call it. Only for a recognised shape; anything else is needs-review.
//   non-password-integrity           a SHA-256 substitution at that one call site, and only when nothing marks the digest as persisted or
//                                    compared with a stored value.
//   signature, protocol-compatibility, externally-persisted-identifier, unknown
//                                    no automatic transformation: needs-review, with the missing facts named.
//
// Purpose comes from the enclosing function (name, parameters, body) and the statement itself, never from the file name or the CWE.
// A CWE-916 finding is a claim that the hash protects a password; it is checked against the code like any other signal and never by
// itself selects a fast-hash swap.
//
// Edits are scoped to the operation at the finding's line. Every other similar token in the file is left alone.
//
// planDeterministicFix returns the decision (patch or needs-review, purpose, scope, required obligations); synthesizeDeterministicPatch is
// the legacy entry point and returns { patch, ruleId, ... } or null, so a needs-review case is never mistaken for a fix.
import { jsSymbols, pySymbols, heuristicSymbols } from '../fix/patch-scope.js';

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_EXT = /\.py$/i;
const JAVA_EXT = /\.java$/i;

// One weak-hash call per language, with enough structure to locate exactly one operation.
const WEAK_CALL = {
  js: /\bcreateHash\s*\(\s*(['"`])(md5|sha1)\1\s*\)/gi,
  py: /\bhashlib\s*\.\s*(md5|sha1)\s*\(/g,
  java: /\bMessageDigest\s*\.\s*getInstance\s*\(\s*"(MD5|SHA-?1)"\s*\)/gi,
};
const langOf = (file) => (JS_EXT.test(file) ? 'js' : PY_EXT.test(file) ? 'py' : JAVA_EXT.test(file) ? 'java' : null);

const PASSWORD = /\b(?:\w*_)?(?:pass(?:word|wd|phrase)?|pwd|pw|credential)s?(?:_\w*)?\b|(?:[a-z](?:Pass(?:word|wd|phrase)?|Pwd|Credential)s?\b)|\bhash_?pw\b/i;
const SIGNATURE = /\b(?:hmac|createHmac|sign(?:ature)?|verify_?sig\w*|mac)\b/i;
const PROTOCOL = /Content-MD5|\bETag\b|\betag\b|\bs3\b|webdav|\bgit\b|Sec-WebSocket|258EAFA5|oauth|HMAC-SHA1|\b[th]otp\b|WWW-Authenticate|\bdigest auth|\blegacy\b|\bcompat\w*|\binterop\w*|\bwire\b|\bprotocol\b|\brfc\s*\d+/i;
const PERSIST = /\b(?:save|insert|update|upsert|store|persist|write\w*|db|database|redis|cache_?key|filename|file_?name|path|url|primary_?key|uuid|guid|\.set\s*\(|==|===|!=|!==|equals\s*\(|compare\w*)\b|==|!=/i;
const INTEGRITY = /\b(?:checksum|integrity|fingerprint|dedup\w*|content_?hash|digest_?of|hash_?of|cache|memo\w*|bucket|shard|etag)\b/i;

/** Text of the innermost symbol enclosing `line`, its name and parameters; the file when nothing encloses it. */
function enclosing(content, file, line) {
  const lang = langOf(file);
  const syms = lang === 'js' ? (jsSymbols(content, file) || []) : lang === 'py' ? pySymbols(content) : heuristicSymbols(content);
  const fns = syms.filter((s) => line >= s.start && line <= s.end && s.kind !== 'class').sort((a, b) => (a.end - a.start) - (b.end - b.start));
  const lines = content.split('\n');
  if (!fns.length) return { name: null, text: lines[line - 1] || '', start: line, end: line, header: '' };
  const s = fns[0];
  return { name: s.name, text: lines.slice(s.start - 1, s.end).join('\n'), start: s.start, end: s.end, header: lines[s.start - 1] || '' };
}

/**
 * Classify the purpose of the weak-hash operation at `line`.
 * @returns {{purpose:string, signals:string[], missingFacts:string[]}}
 */
export function classifyHashPurpose(content, file, line) {
  const ctx = enclosing(content, file, line);
  const stmt = content.split('\n')[line - 1] || '';
  const signals = [];
  const where = `${ctx.name || ''}\n${ctx.header}\n${stmt}`;
  const password = PASSWORD.test(where) || (PASSWORD.test(ctx.text) && /\bhash\w*|digest/i.test(ctx.name || ''));
  if (password) signals.push(`password vocabulary in ${ctx.name ? `the enclosing function ${ctx.name}` : 'the statement'}`);
  if (SIGNATURE.test(where)) signals.push('signature or MAC vocabulary');
  if (PROTOCOL.test(ctx.text)) signals.push('a protocol or compatibility marker in the enclosing code');
  // persistence: the digest is compared with something or written somewhere in the same function
  // the hash API's own chain (.update / .digest / .hexdigest) is not persistence
  const chainless = (t) => t.replace(/\.\s*(?:update|digest|hexdigest)\s*\(/g, '.(');
  const persisted = PERSIST.test(chainless(ctx.text.replace(stmt, ''))) || PERSIST.test(chainless(stmt.replace(WEAK_CALL[langOf(file)] || /$^/, '')));
  if (persisted) signals.push('the digest is compared, stored or used as an identifier in the enclosing code');
  const integrity = INTEGRITY.test(where) || INTEGRITY.test(ctx.text);
  if (integrity) signals.push('integrity or cache vocabulary');
  if (password) return { purpose: 'password-storage', signals, missingFacts: [] };
  if (SIGNATURE.test(where)) return { purpose: 'signature', signals, missingFacts: ['which verifier checks this signature, and whether it can move to HMAC-SHA-256 or a modern signature scheme at the same time'] };
  if (PROTOCOL.test(ctx.text)) return { purpose: 'protocol-compatibility', signals, missingFacts: ['whether the peer or protocol accepts a different digest algorithm', 'whether both sides can be changed together'] };
  if (integrity && !persisted) return { purpose: 'non-password-integrity', signals, missingFacts: [] };
  if (persisted) return { purpose: 'externally-persisted-identifier', signals, missingFacts: ['where the digest is stored or compared, and how existing stored values are migrated or recomputed'] };
  return { purpose: 'unknown', signals, missingFacts: ['what the digest protects (password storage, integrity check, signature or identifier)', 'whether any stored value or external system depends on the current algorithm'] };
}

// Locate the weak call to edit: the one on the finding's line; without a line, the only one in the file.
function locateWeakCall(content, file, line) {
  const lang = langOf(file); if (!lang) return { error: 'no weak-hash transformation for this file type' };
  const re = new RegExp(WEAK_CALL[lang].source, WEAK_CALL[lang].flags);
  const hits = [];
  for (const m of content.matchAll(re)) hits.push({ index: m.index, text: m[0], line: content.slice(0, m.index).split('\n').length, algo: (m[2] || m[1]).toLowerCase() });
  if (!hits.length) return { error: 'the weak hash call is not literally present' };
  const onLine = Number.isInteger(line) ? hits.filter((h) => h.line === line) : hits;
  if (onLine.length === 1) return { hit: onLine[0], lang, others: hits.length - 1 };
  if (!onLine.length) return { error: `no weak hash call on line ${line}`, ambiguous: false };
  return { error: `${onLine.length} weak hash calls ${Number.isInteger(line) ? `on line ${line}` : 'in the file and no line to choose one'}`, ambiguous: true };
}

const swapAt = (content, hit, replacement) => content.slice(0, hit.index) + replacement + content.slice(hit.index + hit.text.length);
function sha256Call(hit, lang) {
  if (lang === 'js') return hit.text.replace(/(md5|sha1)/i, 'sha256');
  if (lang === 'py') return hit.text.replace(/(md5|sha1)/, 'sha256');
  return hit.text.replace(/"(?:MD5|SHA-?1)"/i, '"SHA-256"');
}

// ── Password-storage recipes ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// Recognised shape (Python): `def NAME(PARAM):` whose body is a single `return hashlib.md5(PARAM.encode(...)).hexdigest()`.
// Recognised shape (JS): `function NAME(PARAM) { return crypto.createHash('md5').update(PARAM).digest('hex'); }`, or the arrow/assigned
// equivalent. Anything else (a salt or pepper composed into the input, several statements, bytes output) is needs-review: the legacy
// verifier must recompute the old value EXACTLY, and the recipe only does that for the shape it understands.
const PY_SHAPE = /^([ \t]*)def\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*(?:->\s*\w+\s*)?:\s*\n\1[ \t]+return\s+hashlib\s*\.\s*(md5|sha1)\s*\(\s*\3\s*\.\s*encode\s*\(\s*(?:(['"])[\w-]+\5)?\s*\)\s*\)\s*\.\s*hexdigest\s*\(\s*\)[ \t]*\n/m;
const JS_SHAPE = /^([ \t]*)(?:(?:export\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{\s*return\s+|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*(?:\{\s*return\s+)?)([A-Za-z_$][\w$]*)\s*\.\s*createHash\s*\(\s*(['"`])(md5|sha1)\7\s*\)\s*\.\s*update\s*\(\s*([A-Za-z_$][\w$]*)\s*(?:,\s*(['"`])utf-?8\10\s*)?\)\s*\.\s*digest\s*\(\s*(['"`])hex\11\s*\)\s*;?\s*(\}\s*;?)?[ \t]*\n/m;

function rewriteComparisons(content, name, verify, lang) {
  // NAME(x) == y, y == NAME(x), and the negations; JS also === and !==. Arguments are simple expressions (no nested parentheses).
  const arg = lang === 'py' ? '[A-Za-z_][\\w.\\[\\]\'"]*' : '[A-Za-z_$][\\w$.\\[\\]\'"]*';
  const eq = lang === 'py' ? '(==|!=)' : '(===?|!==?)';
  const notOf = (op, call) => (/!/.test(op) ? (lang === 'py' ? `not ${call}` : `!${call}`) : call);
  let n = 0;
  let out = content.replace(new RegExp(`\\b${name}\\s*\\(\\s*(${arg})\\s*\\)\\s*${eq}\\s*(${arg})`, 'g'), (_, a, op, b) => { n++; return notOf(op, `${verify}(${a}, ${b})`); });
  out = out.replace(new RegExp(`(${arg})\\s*${eq}\\s*\\b${name}\\s*\\(\\s*(${arg})\\s*\\)`, 'g'), (_, b, op, a) => { n++; return notOf(op, `${verify}(${a}, ${b})`); });
  return { out, n };
}

// Remaining uses of NAME( after the rewrite that are not a definition, an assignment or a return of a NEW hash.
function unrecognisedUses(content, name, lang) {
  const lines = content.split('\n'); const bad = [];
  lines.forEach((l, i) => {
    if (!new RegExp(`\\b${name}\\s*\\(`).test(l) || /^\s*(?:#|\/\/|\*)/.test(l)) return;
    if (lang === 'py' ? new RegExp(`^\\s*def\\s+${name}\\b`).test(l) : new RegExp(`\\bfunction\\s+${name}\\b|\\b(?:const|let|var)\\s+${name}\\s*=`).test(l)) return;
    if (new RegExp(`(?:(?:^|[\\s(,])(?:[\\w.\\[\\]'"]+\\s*=(?!=)|return)|:)\\s*(?:await\\s+)?${name}\\s*\\(`).test(l)) return; // stored or returned: writes the new format
    if (new RegExp(`(?:exports\\.\\w+|module\\.exports)\\s*=|export\\s*\\{[^}]*\\b${name}\\b`).test(l)) return;
    bad.push(i + 1);
  });
  return bad;
}

function passwordRecipe(content, file, finding) {
  const lang = langOf(file);
  const facts = [];
  if (lang === 'py') {
    const m = content.match(PY_SHAPE);
    if (!m) return { missingFacts: ['the password hash is not the single-statement `return hashlib.<md5|sha1>(<param>.encode()).hexdigest()` shape the recipe can migrate exactly; the legacy format must be recomputed exactly to keep existing logins working'] };
    const [whole, ind, name, param, algo, q] = m;
    const enc = q ? `${param}.encode(${q}utf-8${q})` : `${param}.encode()`;
    const body = `${ind}    `;
    const repl = [
      `${ind}def ${name}(${param}):`,
      `${body}# Password storage uses a salted, memory-hard KDF (scrypt). Stored format: scrypt$N$r$p$<salt hex>$<key hex>.`,
      `${body}salt = os.urandom(16)`,
      `${body}key = hashlib.scrypt(${enc}, salt=salt, n=2 ** 14, r=8, p=1, dklen=32)`,
      `${body}return 'scrypt$16384$8$1$' + salt.hex() + '$' + key.hex()`,
      '',
      '',
      `${ind}def verify_password(${param}, stored):`,
      `${body}# New format: recompute the scrypt key with the stored parameters. Legacy format: the previous unsalted ${algo} hex digest,`,
      `${body}# still accepted so existing accounts can log in; password_needs_rehash tells the caller to store ${name}(${param}) afterwards.`,
      `${body}if isinstance(stored, str) and stored.startswith('scrypt$'):`,
      `${body}    try:`,
      `${body}        _, n, r, p, salt_hex, key_hex = stored.split('$')`,
      `${body}        key = hashlib.scrypt(${enc}, salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=len(key_hex) // 2)`,
      `${body}    except (ValueError, TypeError):`,
      `${body}        return False`,
      `${body}    return hmac.compare_digest(key.hex(), key_hex)`,
      `${body}return isinstance(stored, str) and hmac.compare_digest(hashlib.${algo}(${enc}).hexdigest(), stored)`,
      '',
      '',
      `${ind}def password_needs_rehash(stored):`,
      `${body}return not (isinstance(stored, str) and stored.startswith('scrypt$'))`,
      '',
    ].join('\n');
    if (/\bdef\s+verify_password\b|\bdef\s+password_needs_rehash\b/.test(content)) return { missingFacts: ['the file already defines verify_password or password_needs_rehash; merging two verifiers needs review'] };
    const MARK = '\u0000AS_RECIPE\u0000';
    const cmp = rewriteComparisons(content.replace(whole, MARK), name, 'verify_password', 'py');
    const bad = unrecognisedUses(cmp.out, name, 'py');
    let out = cmp.out.replace(MARK, () => repl + '\n');
    if (bad.length) return { missingFacts: [`${name}() is used on line(s) ${bad.join(', ')} in a way the recipe cannot classify as storing a new hash or checking a password`] };
    for (const mod of ['hmac', 'os']) if (!new RegExp(`^\\s*import\\s+(?:[\\w, ]*\\b)?${mod}\\b`, 'm').test(out)) out = out.replace(/^(\s*import\s+hashlib\b[^\n]*\n)/m, `$1import ${mod}\n`);
    if (!/^\s*import\s+(?:[\w, ]*\b)?os\b/m.test(out) || !/^\s*import\s+(?:[\w, ]*\b)?hmac\b/m.test(out)) return { missingFacts: ['could not place the os/hmac imports next to `import hashlib`'] };
    facts.push(`${cmp.n} comparison(s) of ${name}() rewritten to verify_password`);
    return { patch: out, recipe: 'password-kdf-scrypt-python', notes: facts, entry: { hash: name, verify: 'verify_password', needsRehash: 'password_needs_rehash' } };
  }
  if (lang === 'js') {
    const m = content.match(JS_SHAPE);
    if (!m) return { missingFacts: ['the password hash is not the single-statement `return crypto.createHash(<md5|sha1>).update(<param>).digest(\'hex\')` shape the recipe can migrate exactly'] };
    const [whole, ind, fnName, fnParam, constName, constParam, cryptoId, , algo, updated] = m;
    const name = fnName || constName; const param = fnParam || constParam;
    if (updated !== param) return { missingFacts: [`the hash input (${updated}) is not the function parameter (${param}); the legacy value cannot be recomputed exactly`] };
    if (/\bfunction\s+verifyPassword\b|\bverifyPassword\s*=|\bpasswordNeedsRehash\b/.test(content)) return { missingFacts: ['the file already defines verifyPassword or passwordNeedsRehash; merging two verifiers needs review'] };
    const b = `${ind}  `;
    const repl = [
      `${ind}// Password storage uses a salted, memory-hard KDF (scrypt). Stored format: scrypt$N$r$p$<salt hex>$<key hex>.`,
      `${ind}function ${name}(${param}) {`,
      `${b}const salt = ${cryptoId}.randomBytes(16);`,
      `${b}const key = ${cryptoId}.scryptSync(String(${param}), salt, 32, { N: 16384, r: 8, p: 1 });`,
      `${b}return \`scrypt$16384$8$1$\${salt.toString('hex')}$\${key.toString('hex')}\`;`,
      `${ind}}`,
      '',
      `${ind}// New format: recompute with the stored parameters. Legacy format: the previous unsalted ${algo} hex digest, still accepted so`,
      `${ind}// existing accounts can log in; passwordNeedsRehash tells the caller to store ${name}(${param}) afterwards.`,
      `${ind}function verifyPassword(${param}, stored) {`,
      `${b}if (typeof stored !== 'string') return false;`,
      `${b}if (stored.startsWith('scrypt$')) {`,
      `${b}  const parts = stored.split('$');`,
      `${b}  if (parts.length !== 6) return false;`,
      `${b}  const [, n, r, p, saltHex, keyHex] = parts;`,
      `${b}  let key;`,
      `${b}  try { key = ${cryptoId}.scryptSync(String(${param}), Buffer.from(saltHex, 'hex'), keyHex.length / 2, { N: Number(n), r: Number(r), p: Number(p) }); } catch { return false; }`,
      `${b}  const want = Buffer.from(keyHex, 'hex');`,
      `${b}  return want.length === key.length && ${cryptoId}.timingSafeEqual(key, want);`,
      `${b}}`,
      `${b}const legacy = Buffer.from(${cryptoId}.createHash('${algo}').update(String(${param})).digest('hex'));`,
      `${b}const want = Buffer.from(stored);`,
      `${b}return legacy.length === want.length && ${cryptoId}.timingSafeEqual(legacy, want);`,
      `${ind}}`,
      '',
      `${ind}function passwordNeedsRehash(stored) {`,
      `${b}return !(typeof stored === 'string' && stored.startsWith('scrypt$'));`,
      `${ind}}`,
      '',
    ].join('\n');
    const MARK = '\u0000AS_RECIPE\u0000';
    const cmp = rewriteComparisons(content.replace(whole, MARK), name, 'verifyPassword', 'js');
    const bad = unrecognisedUses(cmp.out, name, 'js');
    let out = cmp.out.replace(MARK, () => repl);
    if (bad.length) return { missingFacts: [`${name}() is used on line(s) ${bad.join(', ')} in a way the recipe cannot classify as storing a new hash or checking a password`] };
    // export the two new functions wherever the hash function is exported, CommonJS style
    if (new RegExp(`module\\.exports\\s*=\\s*\\{[^}]*\\b${name}\\b`).test(out)) out = out.replace(new RegExp(`(module\\.exports\\s*=\\s*\\{[^}]*\\b${name}\\b)`), '$1, verifyPassword, passwordNeedsRehash');
    else if (new RegExp(`exports\\.${name}\\s*=`).test(out)) out += '\nexports.verifyPassword = verifyPassword;\nexports.passwordNeedsRehash = passwordNeedsRehash;\n';
    facts.push(`${cmp.n} comparison(s) of ${name}() rewritten to verifyPassword`);
    return { patch: out, recipe: 'password-kdf-scrypt-js', notes: facts, entry: { hash: name, verify: 'verifyPassword', needsRehash: 'passwordNeedsRehash' } };
  }
  return { missingFacts: ['no password-KDF migration recipe for this language; a person must choose the framework password API and the legacy-verification path'] };
}

// The obligations a deterministic repair must pass before it is more than a proposal. Registered kinds only (see repair/contracts.js).
const OBLIGATIONS = {
  'password-storage': ['password-legacy-login-preserved', 'password-new-format-written', 'password-wrong-rejected', 'rescan-original-absent'],
  'non-password-integrity': ['rescan-original-absent', 'project-tests'],
  tls: ['tls-trusted-endpoint-accepted', 'tls-untrusted-endpoint-rejected', 'rescan-original-absent'],
};

/**
 * @returns {{disposition:'proposed'|'needs-review'|'not-applicable', ruleId:string|null, patch?:Record<string,string>, purpose?:string,
 *   signals?:string[], missingFacts?:string[], scope?:{line:number, otherOccurrencesLeftAlone:number}, recipe?:string,
 *   requiredObligations?:string[], notes?:string[]}}
 */
export function planDeterministicFix(finding, fileContent) {
  if (!finding || typeof fileContent !== 'string' || !finding.file) return { disposition: 'not-applicable', ruleId: null };
  const cwe = String(finding.cwe || '');
  const fam = String(finding.family || '');
  const weakHash = /CWE-(?:327|328|916|759|760)\b/.test(cwe) || /weak.?(?:hash|crypto)|password.?hash/i.test(fam);
  if (weakHash) {
    const loc = locateWeakCall(fileContent, finding.file, finding.line);
    if (loc.error && !loc.ambiguous) return { disposition: 'not-applicable', ruleId: 'weak-hash', reason: loc.error };
    if (loc.error) return { disposition: 'needs-review', ruleId: 'weak-hash', missingFacts: [`which weak hash call the finding names (${loc.error})`] };
    const cls = classifyHashPurpose(fileContent, finding.file, loc.hit.line);
    if (cls.purpose === 'password-storage') {
      const r = passwordRecipe(fileContent, finding.file, finding);
      if (!r.patch) return { disposition: 'needs-review', ruleId: 'weak-hash-password-kdf', purpose: cls.purpose, signals: cls.signals, missingFacts: r.missingFacts };
      return { disposition: 'proposed', ruleId: 'weak-hash-password-kdf', recipe: r.recipe, purpose: cls.purpose, signals: cls.signals, patch: { [finding.file]: r.patch }, scope: { line: loc.hit.line, otherOccurrencesLeftAlone: loc.others }, requiredObligations: OBLIGATIONS['password-storage'], entry: r.entry, notes: r.notes };
    }
    // CWE-916 is a password claim: if the code does not bear it out, no fast-hash swap is a completed password repair.
    if (/CWE-(?:916|759|760)\b/.test(cwe)) return { disposition: 'needs-review', ruleId: 'weak-hash', purpose: cls.purpose, signals: cls.signals, missingFacts: ['the finding says this hash stores a password (CWE-916) but the code does not show which value is the password; a fast hash is never a password repair', ...cls.missingFacts] };
    if (cls.purpose === 'non-password-integrity') {
      return { disposition: 'proposed', ruleId: 'weak-hash-sha256', purpose: cls.purpose, signals: cls.signals, patch: { [finding.file]: swapAt(fileContent, loc.hit, sha256Call(loc.hit, loc.lang)) }, scope: { line: loc.hit.line, otherOccurrencesLeftAlone: loc.others }, requiredObligations: OBLIGATIONS['non-password-integrity'] };
    }
    return { disposition: 'needs-review', ruleId: 'weak-hash', purpose: cls.purpose, signals: cls.signals, missingFacts: cls.missingFacts };
  }
  const tls = /CWE-295\b/.test(cwe) || /tls.?no.?verify|cert.?(?:none|verify)/i.test(fam);
  if (tls) {
    const lang = langOf(finding.file);
    const re = lang === 'js' ? /(\brejectUnauthorized\s*:\s*)false\b/g : lang === 'py' ? /(\bverify\s*=\s*)False\b/g : null;
    if (!re) return { disposition: 'not-applicable', ruleId: 'tls-verify-on', reason: 'no TLS transformation for this file type' };
    const hits = [...fileContent.matchAll(re)].map((m) => ({ index: m.index, text: m[0], line: fileContent.slice(0, m.index).split('\n').length }));
    if (!hits.length) return { disposition: 'not-applicable', ruleId: 'tls-verify-on', reason: 'verification is not literally disabled' };
    const pick = Number.isInteger(finding.line) ? hits.filter((h) => h.line === finding.line) : (hits.length === 1 ? hits : []);
    if (pick.length !== 1) return { disposition: 'needs-review', ruleId: 'tls-verify-on', missingFacts: [`which disabled-verification setting the finding names (${hits.length} in the file${Number.isInteger(finding.line) ? `, ${pick.length} on line ${finding.line}` : ''})`] };
    const h = pick[0];
    const on = h.text.replace(/false$/, 'true').replace(/False$/, 'True');
    // A private CA the code already declares (ca / cafile / verify=<path>) is kept as-is; the repair only turns verification back on.
    const lines = fileContent.split('\n');
    const near = lines.slice(Math.max(0, h.line - 6), h.line + 5).join('\n');
    const declaresCa = /\bca\s*:|\bcafile\b|\bcapath\b|NODE_EXTRA_CA_CERTS|REQUESTS_CA_BUNDLE|SSL_CERT_FILE/.test(near);
    return { disposition: 'proposed', ruleId: 'tls-verify-on', purpose: 'transport-authentication', patch: { [finding.file]: fileContent.slice(0, h.index) + on + fileContent.slice(h.index + h.text.length) }, scope: { line: h.line, otherOccurrencesLeftAlone: hits.length - 1 }, requiredObligations: OBLIGATIONS.tls, compatibility: declaresCa ? 'the declared CA next to the setting is preserved' : 'no private CA is declared next to the setting: an endpoint that relied on an unverified private certificate needs its CA declared (ca / verify=<bundle>), or the handshake obligation fails' };
  }
  return { disposition: 'not-applicable', ruleId: null };
}

/** Legacy entry point: the patch when the plan is a proposal, else null. A needs-review plan never reads as a fix. */
export function synthesizeDeterministicPatch(finding, fileContent) {
  try {
    const plan = planDeterministicFix(finding, fileContent);
    if (plan.disposition !== 'proposed' || !plan.patch) return null;
    return { patch: plan.patch, ruleId: plan.ruleId, purpose: plan.purpose, scope: plan.scope, requiredObligations: plan.requiredObligations, ...(plan.recipe ? { recipe: plan.recipe } : {}) };
  } catch { return null; }
}
