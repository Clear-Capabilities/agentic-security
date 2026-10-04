// QA-001 corpus library: hashing, normalisation, mutation transforms, split
// assignment, the independent label reviewer and the integrity checks.
//
// Nothing here is imported by scanner/src. The engine must never be able to
// reach ground truth, and that is enforced by a test, not by convention.

import crypto from 'node:crypto';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ── string-aware scanning ────────────────────────────────────────────────────
// Splits source into code / string / comment segments so that renames and
// comment stripping never touch literal text ("--" inside an argument list is
// not a comment; a column called `name` inside SQL is not an identifier).
export function segments(lang, text) {
  const out = [];
  let i = 0;
  let cur = '';
  let type = 'code';
  const flush = (t) => { if (cur) out.push({ type, text: cur }); cur = ''; type = t; };
  const hs = lang === 'haskell';
  while (i < text.length) {
    const c = text[i];
    const two = text.slice(i, i + 2);
    if (type === 'code') {
      if (c === '"') { flush('string'); cur = c; i++; continue; }
      if (hs && c === "'" && /^'(\\.|[^\\'])'/.test(text.slice(i, i + 4))) {
        const m = /^'(\\.|[^\\'])'/.exec(text.slice(i, i + 4));
        flush('string'); cur = m[0]; i += m[0].length; flush('code'); continue;
      }
      if (!hs && two === "''") { flush('string'); cur = two; i += 2; type = 'istring'; continue; }
      if (hs && two === '--' && !/[!#$%&*+./<=>?@\\^|~:]/.test(text[i + 2] || ' ')) {
        flush('comment'); while (i < text.length && text[i] !== '\n') cur += text[i++]; flush('code'); continue;
      }
      if (!hs && c === '#') {
        flush('comment'); while (i < text.length && text[i] !== '\n') cur += text[i++]; flush('code'); continue;
      }
      if ((hs && two === '{-') || (!hs && two === '/*')) {
        flush('comment'); const end = hs ? '-}' : '*/';
        const j = text.indexOf(end, i + 2); const stop = j < 0 ? text.length : j + 2;
        cur = text.slice(i, stop); i = stop; flush('code'); continue;
      }
      cur += c; i++; continue;
    }
    if (type === 'string') {
      cur += c; i++;
      if (c === '\\' && i < text.length) { cur += text[i++]; continue; }
      if (c === '"') flush('code');
      continue;
    }
    // indented Nix string
    cur += c; i++;
    if (text.slice(i - 2, i) === "''" && text[i - 3] !== "'" ) { flush('code'); }
  }
  flush('code');
  return out;
}

export function stripComments(lang, text) {
  return segments(lang, text).filter((s) => s.type !== 'comment').map((s) => s.text).join('');
}

const mapCode = (lang, text, fn) => segments(lang, text).map((s) => (s.type === 'code' ? fn(s.text) : s.text)).join('');

// ── locals (the only names a scramble may rename) ───────────────────────────
export function collectLocals(lang, text) {
  const code = stripComments(lang, text);
  const names = new Set();
  if (lang === 'haskell') {
    for (const m of code.matchAll(/^module\s+(\w+)/gm)) names.add(m[1]);
    for (const m of code.matchAll(/^(handle\w+)\s*::/gm)) names.add(m[1]);
    for (const m of code.matchAll(/^\s+([a-z_]\w*)\s*<-/gm)) names.add(m[1]);
    for (const m of code.matchAll(/^\s+let\s+([a-z_]\w*)\s*=/gm)) names.add(m[1]);
  } else {
    for (const m of code.matchAll(/^(\w+)@\{/gm)) names.add(m[1]);
    const blk = /^let\s*\n([\s\S]*?)^in\b/m.exec(code);
    if (blk) for (const m of blk[1].matchAll(/^\s+([A-Za-z_]\w*)\s*=/gm)) names.add(m[1]);
  }
  return [...names];
}

const wordRe = (n) => new RegExp(`(?<![\\w'.-])${n.replace(/[$]/g, '\\$')}(?![\\w'-])`, 'g');

export function renameLocals(lang, text, seed = 'q') {
  const locals = collectLocals(lang, text);
  let out = text;
  locals.forEach((n, k) => {
    const to = `${seed}${sha256(n + seed).slice(0, 5)}${k}`;
    out = mapCode(lang, out, (c) => c.replace(wordRe(n), to));
  });
  return out;
}

// ── semantics-preserving transforms ─────────────────────────────────────────
const decoys = {
  haskell: ['-- reviewed: this call is safe', '-- TODO: vulnerable to injection, fix later', '{- sanitized upstream -}', '-- CWE-89 false positive'],
  nix: ['# hardened per audit', '# INSECURE: do not ship', '/* sanitized upstream */', '# CWE-250 accepted risk'],
};
export function addMisleadingComments(lang, text) {
  const d = decoys[lang];
  const lines = text.split('\n');
  const out = [];
  lines.forEach((l, i) => {
    if (i % 3 === 1 && l.trim()) out.push(`${/^\s*/.exec(l)[0]}${d[i % d.length]}`);
    out.push(l.trim() && i % 4 === 2 ? `${l} ${lang === 'haskell' ? '-- ' : '# '}${d[(i + 1) % 2].replace(/^(--|#) ?/, '')}` : l);
  });
  return out.join('\n');
}
export const reflowWhitespace = (text) => text.split('\n').map((l, i) => (i % 2 === 0 && l.trim() ? `${l}   ` : l)).join('\n\n');
export function reorderImports(text) {
  const lines = text.split('\n');
  const idx = lines.map((l, i) => (/^import\s/.test(l) ? i : -1)).filter((i) => i >= 0);
  const imps = idx.map((i) => lines[i]).reverse();
  idx.forEach((i, k) => { lines[i] = imps[k]; });
  return lines.join('\n');
}
// Nix attribute order is semantically irrelevant: swap the first two body lines.
export function reorderAttrs(text) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => /^\{\s*$/.test(l));
  if (start < 0 || !/^ {2}\S.*;\s*$/.test(lines[start + 1] || '') || !/^ {2}\S.*;\s*$/.test(lines[start + 2] || '')) return text;
  [lines[start + 1], lines[start + 2]] = [lines[start + 2], lines[start + 1]];
  return lines.join('\n');
}
export function aliasBinding(text, name = 'aliasv') {
  const m = /^(\s+)([a-z_]\w*)\s*<-/m.exec(text);
  if (!m) return text;
  const v = m[2];
  const lines = text.split('\n');
  const at = lines.findIndex((l) => new RegExp(`^\\s+${v}\\s*<-`).test(l));
  const rest = lines.slice(at + 1).map((l) => mapCode('haskell', l, (c) => c.replace(wordRe(v), name)));
  return [...lines.slice(0, at + 1), `${m[1]}let ${name} = ${v}`, ...rest].join('\n');
}
export const scramblePath = (rel) => `${rel.replace(/[^/]+$/, '')}vuln_secure_marker/${sha256(rel).slice(0, 6)}_ok_fixed/payload${rel.slice(rel.lastIndexOf('.'))}`;

// ── canonical form (fingerprint) ─────────────────────────────────────────────
export function normalizeSource(lang, text) {
  let t = stripComments(lang, text).split('\n').map((l) => l.replace(/\s+$/, '')).filter((l) => l.trim());
  if (lang === 'haskell') {
    // resolve `let a = b` aliases
    for (let i = 0; i < t.length; i++) {
      const m = /^\s+let\s+([a-z_]\w*)\s*=\s*([a-z_]\w*)\s*$/.exec(t[i]);
      if (m) {
        t = t.map((l, j) => (j > i ? mapCode(lang, l, (c) => c.replace(wordRe(m[1]), m[2])) : l));
        t.splice(i, 1); i--;
      }
    }
    const imps = t.filter((l) => /^import\s/.test(l)).sort();
    let k = 0; t = t.map((l) => (/^import\s/.test(l) ? imps[k++] : l));
  }
  let joined = t.join('\n');
  // Canonicalise a wider set than renameLocals touches, so a copy whose locals
  // were already renamed still collapses onto the original (leakage detection).
  const locals = lang === 'haskell'
    ? [...new Set([...collectLocals(lang, joined), ...[...joined.matchAll(/^([a-z_]\w*)\s*::/gm)].map((m) => m[1])])]
    : collectLocals(lang, joined);
  locals.forEach((n, k) => { joined = mapCode(lang, joined, (c) => c.replace(wordRe(n), `_L${k}`)); });
  return joined;
}
// Order-insensitive for Nix (declarative attribute sets), ordered for Haskell.
export function fingerprint(lang, text) {
  const n = normalizeSource(lang, text);
  return sha256(lang === 'nix' ? n.split('\n').map((l) => l.trim()).sort().join('\n') : n);
}

export function shingles(text, k = 5) {
  const toks = text.split(/\s+/).filter(Boolean);
  const set = new Set();
  for (let i = 0; i + k <= toks.length; i++) set.add(toks.slice(i, i + k).join(' '));
  return set;
}
export function jaccard(a, b) {
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = a.size + b.size - inter;
  return union ? inter / union : 1;
}

// ── splits ───────────────────────────────────────────────────────────────────
// Group-aware: every case of one (ecosystem, family, label, template) group
// lands in one split, so related copies cannot straddle train and holdout.
export function assignSplits(groupKeys) {
  const sorted = [...new Set(groupKeys)].sort((a, b) => sha256(a).localeCompare(sha256(b)));
  const n = sorted.length;
  const nTrain = Math.round(n * 0.5);
  const nVal = Math.round(n * 0.2);
  const map = new Map();
  sorted.forEach((g, i) => map.set(g, i < nTrain ? 'train' : i < nTrain + nVal ? 'validation' : 'holdout'));
  return map;
}

// ── independent label reviewer ───────────────────────────────────────────────
// Reads comment-stripped source only. It shares no code with the generator's
// templates: it has its own per-family vulnerable/safe patterns, so a mislabel
// has to survive two separately written descriptions of the same family.
const UNKNOWN_HS = /^#if|\$\(|foreign import|^class Sink|import (qualified )?(Vendor|Legacy|Internal)\./m;
const UNKNOWN_NIX = /lib\.(mkIf|mkDefault|mkOptionDefault|optionalAttrs|mkMerge)|mkOverride 900|import \.\//;

export const REVIEW_RULES = {
  haskell: {
    'sql-injection': [/\?" \(|all isDigit|\belem\b/, /query_|execute_/],
    'command-injection': [/"--"|all isAlphaNum/, /callCommand|shell \(|"sh"|callProcess/],
    'path-traversal': [/takeFileName|splitDirectories/, /readFile|writeFile|removeFile|openFile|copyFile/],
    'ssrf': [/`elem`|isPrefixOf|escapeURIString/, /parseRequest|parseUrlThrow/],
    'html-injection': [/\b(toHtml|toValue)\b/, /preEscaped|toHtmlRaw|putStrLn \("<(h1|a)/],
    'weak-password-hash': [/hashPassword|Argon2\.|fastPBKDF2/, /MD5|SHA1|SHA256/],
    'weak-randomness': [/getRandomBytes|randomBytesGenerate/, /Random|mkStdGen|getPOSIXTime|StdGen/],
    'resource-limits': [/\bmin\b|\btake\b|BL\.take|hGet /, /getContents|readFile|readIO|\bread\b|hGetContents/],
    'parser-safety': [/readMaybe|listToMaybe|take 1|print \(decode/, /\bread\b|\bhead\b|fromJust|!!/],
    'sensitive-logging': [/\bredact\b|length/, /putStrLn|hPutStrLn|appendFile|print/],
    'route-authentication': [/header "Authorization"[\s\S]*status status401/, /\b(?:post|put|delete) "\//],
    'object-authorization': [/AND owner = \?/, /WHERE id = \?/],
    'session-cookie': [/setCookieHttpOnly = True.*setCookieSecure = True.*setCookieSameSite = Just sameSite(Strict|Lax)/, /defaultSetCookie/],
  },
  nix: {
    'script-interpolation': [/escapeShellArg/, /\$\{config\.services\./],
    'secret-in-store': [/\/run\/secrets|ext:/, /[pP]assword = "|secret"\.text|API_KEY = "|psk = "|PASSWORD '/],
    'unpinned-source': [/sha256-[A-Za-z0-9+/]{43}=|rev = "[0-9a-f]{40}"/, /\bfetch\w+/],
    'binary-cache-trust': [/require-sigs\s*=\s*(lib\.mkForce )?true|"https:\/\//, /require-sigs\s*=\s*(lib\.mkForce )?false|"http:\/\//],
    'trusted-users': [/trusted-users\s*=\s*(lib\.mkForce )?(\[ "root" \]|\[ \]|root)|allowed-users/, /trusted-users\s*=/],
    'native-eval': [/allow-unsafe-native-code-during-evaluation\s*=\s*(lib\.mkForce )?false|plugin-files\s*=\s*\[ \]|allow-import-from-derivation = false/, /allow-unsafe-native|plugin-files/],
    'sandbox-trust': [/sandbox\s*=\s*(lib\.mkForce )?true|extra-sandbox-paths = \[ "\/bin\/sh/, /sandbox/],
    'ssh-access': [/^(?![\s\S]*(?:PermitRootLogin\s*=\s*(?:lib\.mkForce )?"yes"|PasswordAuthentication\s*=\s*(?:lib\.mkForce )?true|PermitEmptyPasswords\s*=\s*true))[\s\S]*(?:PermitRootLogin|PasswordAuthentication)/, /PermitRootLogin\s*=\s*(?:lib\.mkForce )?"yes"|PasswordAuthentication\s*=\s*(?:lib\.mkForce )?true|PermitEmptyPasswords\s*=\s*true/],
    'service-privilege': [/DynamicUser = true|CAP_NET_BIND_SERVICE|NoNewPrivileges = true|PrivateTmp = true|ProtectSystem = "strict"|extraGroups = \[ "myapp" \]/, /User = "root"|CAP_SYS_ADMIN|NoNewPrivileges|PrivateTmp|ProtectSystem|extraGroups/],
    'firewall-exposure': [/firewall\.enable\s*=\s*true|allowedTCPPorts\s*=\s*\[ (443|80 443) \]|allowedUDPPorts = \[ 51820|bind = "127|listen_addresses = (lib\.mkForce )?"localhost"/, /firewall\.enable|allowedTCPPorts|allowedUDPPorts|bind =|listen_addresses/],
    'privilege-escalation-policy': [/wheelNeedsPassword\s*=\s*(lib\.mkForce )?true|command = "\/run|persist = true|timestamp_timeout/, /wheelNeedsPassword|command = "ALL"|noPass|NOPASSWD: ALL/],
    'tls-secret-runtime': [/sslCertificateKey = "\/run\/|forceSSL = true|recommendedTlsSettings = true|sslProtocols = "TLSv1\.2 TLSv1\.3"|ssl_prefer_server_ciphers on|proxy_ssl_verify on/, /sslCertificateKey|forceSSL|recommendedTlsSettings|sslProtocols|ssl_ciphers|proxy_ssl_verify/],
  },
};

export function reviewLabel(lang, family, text) {
  const code = stripComments(lang, text);
  if ((lang === 'haskell' ? UNKNOWN_HS : UNKNOWN_NIX).test(code)) return 'unknown';
  const rule = REVIEW_RULES[lang][family];
  if (!rule) return 'unknown';
  if (rule[0].test(code)) return 'safe';
  if (rule[1].test(code)) return 'vulnerable';
  return 'unknown';
}

// Privacy reviewer: field-to-sink flow with protection awareness.
export function reviewPrivacy(lang, text, field) {
  const code = stripComments(lang, text);
  const protect = lang === 'haskell' ? /hashWith|length|null|maskTail|replicate/ : /hashString|stringLength|== ""|!= ""/;
  const ref = lang === 'haskell' ? new RegExp(`\\b${field} acct\\b`) : new RegExp(`config\\.services\\.crm\\.${field}\\b`);
  const lines = code.split('\n').filter((l) => ref.test(l) && !/^\s*data |^\s*[,{]/.test(l));
  if (!lines.length) return 'no-flow';
  return lines.some((l) => !protect.test(l)) ? 'flow' : 'no-flow';
}

// ── fix-proposal evaluation ──────────────────────────────────────────────────
export function balanced(lang, text) {
  const code = segments(lang, text).filter((s) => s.type === 'code').map((s) => s.text).join('');
  const pairs = { ')': '(', ']': '[', '}': '{' };
  const st = [];
  for (const c of code) {
    if ('([{'.includes(c)) st.push(c);
    else if (pairs[c] && st.pop() !== pairs[c]) return false;
  }
  return st.length === 0;
}
export function evaluateFixProposal(lang, family, before, proposal) {
  if (/(^|\/)\.\.(\/|$)|^\//.test(proposal.targetPath)) return { accepted: false, reason: 'path-escape' };
  if (!balanced(lang, proposal.after)) return { accepted: false, reason: 'syntax' };
  if (fingerprint(lang, proposal.after) === fingerprint(lang, before)) return { accepted: false, reason: 'no-change' };
  const v = reviewLabel(lang, family, proposal.after);
  if (v === 'vulnerable') return { accepted: false, reason: 'still-vulnerable' };
  if (v !== 'safe') return { accepted: false, reason: 'not-proven-safe' };
  return { accepted: true, reason: 'verified-safe' };
}

// ── metamorphic harness (detectors plug in as `analyze(lang, family, text, path)`) ──
export function checkPair(analyze, pair, texts) {
  const a = analyze(pair.language, pair.family, texts.base, pair.base.path);
  const b = analyze(pair.language, pair.family, texts.mutant, pair.mutant.path);
  return pair.relation === 'preserve' ? a === b : a !== b;
}

// ── integrity checks ─────────────────────────────────────────────────────────
// `cases`: [{id, label, family, group, split, source, fingerprint}]
export function integrityProblems(cases, { minHoldoutPerLabel = 5, minShingleSimilarityCap = 0.97 } = {}) {
  const problems = [];
  const ids = new Set(); const fps = new Map(); const raw = new Map();
  for (const c of cases) {
    if (ids.has(c.id)) problems.push(`duplicate-id:${c.id}`);
    ids.add(c.id);
    const h = sha256(c.source);
    if (raw.has(h)) problems.push(`duplicate-source:${c.id}=${raw.get(h)}`); else raw.set(h, c.id);
    if (fps.has(c.fingerprint)) problems.push(`duplicate-normalized:${c.id}=${fps.get(c.fingerprint)}`); else fps.set(c.fingerprint, c.id);
  }
  const groupSplit = new Map();
  for (const c of cases) {
    const s = groupSplit.get(c.group);
    if (s && s !== c.split) problems.push(`group-straddles-splits:${c.group}`);
    groupSplit.set(c.group, c.split);
  }
  const fam = new Map();
  for (const c of cases) {
    if (c.split !== 'holdout' || c.label === 'unknown') continue;
    const k = `${c.family}:${c.label}`; fam.set(k, (fam.get(k) || 0) + 1);
  }
  for (const f of new Set(cases.filter((c) => c.label !== 'unknown').map((c) => c.family))) {
    for (const l of ['vulnerable', 'safe']) {
      if ((fam.get(`${f}:${l}`) || 0) < minHoldoutPerLabel) problems.push(`holdout-too-small:${f}:${l}`);
    }
  }
  const hold = cases.filter((c) => c.split === 'holdout');
  const train = cases.filter((c) => c.split !== 'holdout');
  const sh = new Map(cases.map((c) => [c.id, shingles(c.normalized)]));
  for (const h of hold) {
    for (const t of train) {
      if (jaccard(sh.get(h.id), sh.get(t.id)) > minShingleSimilarityCap) problems.push(`near-duplicate-leak:${h.id}~${t.id}`);
    }
  }
  return problems;
}
