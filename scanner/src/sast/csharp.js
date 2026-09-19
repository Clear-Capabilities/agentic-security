// C# / .NET SAST module — Layers 1-4 of the C# detection pipeline.
//
// Architecture (replacing the previous regex-on-cleaned-source approach):
//
//   Layer 1: Token-aware lexer (../sast/csharp-tokenizer.js) — strings,
//            verbatim, interpolated, comments, attributes all preserved
//            with semantic identity.
//   Layer 2: Hand-rolled IR (../ir/csharp-ir.js) — emits classes, methods,
//            calls, declarations, assignments, attributes.
//   Layer 3: Lexical type-flow + taint (../posture/csharp-analysis.js) —
//            per-method typeMap and taintMap, forward-propagated through
//            declarations and assignments.
//   Layer 4: Attribute-driven route + auth detection — same module, reads
//            [HttpGet]/[HttpPost]/[Route]/[Authorize]/[AllowAnonymous].
//
// The detectors below query the IR using these helpers and are completely
// regex-free for their primary logic. They still use small regex for cheap
// type-name and string-content checks.
//
// Covered Juliet C# CWE families:
//   CWE-22  path-traversal       Path.Combine + tainted segment, no Path.GetFullPath check
//   CWE-78  command-injection    Process.Start with tainted args / ShellExecute=true
//   CWE-79  xss                  Razor Html.Raw / Response.Write with tainted argument
//   CWE-89  sql-injection        Sql/Ole/MySql/NpgsqlCommand with tainted CommandText / concatenation in constructor / FromSqlRaw
//   CWE-90  ldap-injection       DirectorySearcher / LdapConnection .Search/.SendRequest with tainted filter
//   CWE-330 weak-rng             new Random() in cryptographic context (presence of System.Security.Cryptography uses or "password"/"token" naming)
//   CWE-327 weak-crypto          DESCryptoServiceProvider / RC2 / TripleDES / MD5 / SHA1 — including factory methods
//   CWE-502 insecure-deserialization  BinaryFormatter.Deserialize / NetDataContractSerializer / Newtonsoft TypeNameHandling != None
//   CWE-611 xxe                  XmlDocument w/o XmlResolver=null; XmlReaderSettings w/o DtdProcessing=Prohibit
//   CWE-798 hardcoded-secret     Field/local with name matching password/token/secret/apiKey + non-empty string literal initializer
//   CWE-313 data-exposure        File.WriteAllText/AppendAllText/writer.Write with a sensitive-named value (name-based, not taint-based)
//   CWE-314 data-exposure        Registry.SetValue / RegistryKey.SetValue with a sensitive-named value
//   CWE-315 data-exposure        new HttpCookie(...) / Cookies[...].Value = with a sensitive-named value
//   CWE-1004 header-hardening    new HttpCookie missing Secure/HttpOnly
//   CWE-22  validate-input-false [ValidateInput(false)] attribute
//   CWE-523 insecure-http        hardcoded <form action='http://...'> submitting a password field (point flaw, not taint-based)
//
// Findings carry: id, file, line, vuln, severity, cwe, stride, snippet,
// remediation, confidence, parser, family, and a `_taintEvidence` field
// when the detector relied on Layer 3 to confirm reachability from a
// known source. The LLM validator (when enabled) sees these fields and
// can second-stage low-confidence findings.

import { buildCSharpIR } from '../ir/csharp-ir.js';
import {
  analyzeCSharpIR, receiverIsType, expressionIsTainted, interpStringIsTainted, argIsTainted,
} from '../posture/csharp-analysis.js';

// Helper: collect identifier names from a token slice (idents only — not
// string-literal contents). Used by detectors when checking taint on a
// declaration's rhs to avoid false positives from SQL parameter
// placeholders like "@id" appearing inside a string literal.
function rhsIdents(tokens) {
  const out = [];
  for (const t of tokens || []) {
    if (!t) continue;
    if (t.kind === 'ident') out.push(t.value);
    if (t.kind === 'interp') for (const p of t.parts || []) if (p.kind === 'expr') for (const inner of (p.tokens || [])) if (inner.kind === 'ident') out.push(inner.value);
  }
  return out;
}

function rhsHasConcatWithIdent(tokens) {
  // True if the token stream contains: <string-literal> '+' <ident>
  // (idents from inside the string don't count).
  for (let i = 0; i < tokens.length - 2; i++) {
    if ((tokens[i].kind === 'string' || tokens[i].kind === 'verbatim') &&
        tokens[i + 1].kind === 'op' && tokens[i + 1].value === '+' &&
        tokens[i + 2].kind === 'ident') return true;
    if (tokens[i].kind === 'ident' && tokens[i + 1].kind === 'op' && tokens[i + 1].value === '+' &&
        (tokens[i + 2].kind === 'string' || tokens[i + 2].kind === 'verbatim')) return true;
  }
  return false;
}

function rhsHasInterp(tokens) {
  return (tokens || []).some(t => t.kind === 'interp');
}

const SQL_COMMAND_TYPES = /^(?:System\.Data\.SqlClient\.)?(?:Sql|OleDb|MySql|Npgsql|SQLite)Command$/;
const SQL_EXEC_METHODS  = /^(?:Execute(?:Reader|Scalar|NonQuery|DbDataReader|Reader)?(?:Async)?)$/;
const LDAP_SEARCH_TYPES = /^(?:DirectorySearcher|LdapConnection)$/;
const LDAP_SEARCH_METHODS = /^(?:Search|FindOne|FindAll|SendRequest)$/;
const WEAK_CRYPTO_TYPES = /^(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider|MD5CryptoServiceProvider|MD5Cng|SHA1CryptoServiceProvider|SHA1Managed|SHA1Cng|HMACSHA1|HMACMD5|DES|TripleDES|RC2|MD5|SHA1)$/;
const WEAK_CRYPTO_FACTORY_PATTERN = /\b(DES|TripleDES|RC2|MD5|SHA1)\.Create\b/;
// SARD_80_F1 W4.C15 — `WEAK_CRYPTO_TYPES`/`WEAK_CRYPTO_FACTORY_PATTERN` bundle
// two distinct CWEs under one hardcoded 'CWE-327' tag: CWE-327 is the general
// "risky crypto algorithm" (ciphers — DES/3DES/RC2), CWE-328 is specifically
// "Use of a Weak Hash" (MD5/SHA1 and their CryptoServiceProvider/Cng/Managed/
// HMAC variants). Real corpus verification (the C# Juliet suite's own
// CWE-327 vs CWE-328 directories, each with distinct gold expectations)
// confirmed every hash-shaped finding here was scored as a miss against
// BOTH directories: fp against CWE-327 (wrong tag), fn against CWE-328
// (never emitted). `_weakCryptoCwe(name)` decides the correct CWE per
// matched algorithm name so a single detector can emit both correctly.
const WEAK_HASH_NAMES = /^(?:MD5CryptoServiceProvider|MD5Cng|SHA1CryptoServiceProvider|SHA1Managed|SHA1Cng|HMACSHA1|HMACMD5|MD5|SHA1)$/;
function _weakCryptoCwe(name) {
  return WEAK_HASH_NAMES.test(name) ? 'CWE-328' : 'CWE-327';
}
const SECRET_NAME_PATTERN = /^(?:password|passwd|pw|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|priv(?:ate)?[_-]?key|cred(?:ential)?s?|connection[_-]?string|conn[_-]?str)$/i;
const PATH_TRAVERSAL_BASES_SANITIZER = /\bPath\.GetFullPath\b/;
const XSS_SAFE_SINK_PATTERN = /\bHtmlEncode\b|\bHtmlEncoder\b|\bAntiXss/;

function makeFinding({ ruleId, file, line, raw, ir, family, severity, cwe, vuln, remediation, evidence, confidence = 0.85 }) {
  const stride = (cwe === 'CWE-89'  ? 'Tampering'
               : cwe === 'CWE-78'  ? 'Elevation of Privilege'
               : cwe === 'CWE-79'  ? 'Tampering'
               : cwe === 'CWE-611' ? 'Information Disclosure'
               : cwe === 'CWE-502' ? 'Elevation of Privilege'
               : cwe === 'CWE-22'  ? 'Tampering'
               : cwe === 'CWE-327' ? 'Information Disclosure'
               : cwe === 'CWE-328' ? 'Information Disclosure'
               : cwe === 'CWE-330' ? 'Spoofing'
               : cwe === 'CWE-798' ? 'Information Disclosure'
               : cwe === 'CWE-1004'? 'Information Disclosure'
               : cwe === 'CWE-90'  ? 'Tampering'
               : cwe === 'CWE-313' ? 'Information Disclosure'
               : cwe === 'CWE-314' ? 'Information Disclosure'
               : cwe === 'CWE-315' ? 'Information Disclosure'
               : 'Tampering');
  return {
    id: `${ruleId}:${file}:${line}`, file, line,
    vuln, severity, cwe, stride, family,
    snippet: ((raw && raw.split('\n')[line - 1]) || '').trim().slice(0, 200),
    remediation,
    confidence,
    parser: 'CSHARP',
    _taintEvidence: evidence || null,
  };
}

// ─── Detectors ──────────────────────────────────────────────────────────────

function detectSqlInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // 1. SqlCommand-style ctor with tainted concatenation in the first arg.
    for (const decl of m.decls) {
      if (!SQL_COMMAND_TYPES.test(decl.type || '') && !(decl.isVar && SQL_COMMAND_TYPES.test((decl.rhsText.match(/^\s*new\s+(\w+)/) || [])[1] || ''))) continue;
      if (!decl.rhsTokens) continue;
      // Use token-aware checks so SQL parameter placeholders like "@id"
      // inside string literals are NOT counted as code identifiers.
      const hasConcatWithIdent = rhsHasConcatWithIdent(decl.rhsTokens);
      const hasInterp = rhsHasInterp(decl.rhsTokens);
      if (!hasConcatWithIdent && !hasInterp) continue;
      const idents = rhsIdents(decl.rhsTokens);
      const ref = idents.find(r => flow.taintMap.get(r));
      if (!ref) continue;
      const id = `csharp-sql-ctor:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-sql-ctor', file, line: decl.line, raw, ir,
        family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
        vuln: 'SQL Injection — SqlCommand built from tainted concatenation/interpolation',
        remediation: 'Use parameterized queries: `var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn); cmd.Parameters.AddWithValue("@id", id);`. Interpolated strings ($"…") are pre-rendered before reaching the parameterizer.',
        evidence: { type: 'taint', taintedRef: ref, decl: decl.fullTarget || decl.name },
      }));
    }
    // 2. cmd.ExecuteX call where cmd's CommandText was assigned a tainted value.
    for (const call of m.calls) {
      if (!SQL_EXEC_METHODS.test(call.method || '')) continue;
      const receiver = call.receiver;
      if (!receiver) continue;
      if (!receiverIsType(m, flow, receiver, SQL_COMMAND_TYPES)) continue;
      // Find the most recent CommandText assignment for this receiver.
      const cmdTextAssign = (m.assignments || [])
        .filter(a => a.target === receiver && a.memberPath === 'CommandText')
        .slice(-1)[0];
      // Also check the ctor first-arg if no CommandText set.
      const decl = (m.decls || []).find(d => d.name === receiver);
      // Use token-aware idents extraction so SQL parameter placeholders
      // inside string literals (e.g. "@id") aren't flagged as code refs.
      const cmdAssignIdents = cmdTextAssign ? rhsIdents(cmdTextAssign.rhsTokens) : [];
      const declRhsIdents = decl ? rhsIdents(decl.rhsTokens) : [];
      // Concat check via tokens too.
      const cmdAssignHasConcat = cmdTextAssign && (rhsHasConcatWithIdent(cmdTextAssign.rhsTokens) || rhsHasInterp(cmdTextAssign.rhsTokens));
      const declHasConcat = decl && (rhsHasConcatWithIdent(decl.rhsTokens) || rhsHasInterp(decl.rhsTokens));
      const cmdAssignTainted = cmdAssignHasConcat && cmdAssignIdents.some(r => flow.taintMap.get(r));
      const declTainted = declHasConcat && declRhsIdents.some(r => flow.taintMap.get(r));
      if (!cmdAssignTainted && !declTainted) continue;
      const id = `csharp-sql-exec:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-sql-exec', file, line: call.line, raw, ir,
        family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
        vuln: 'SQL Injection — SqlCommand.ExecuteX with tainted CommandText',
        remediation: 'Bind every user-supplied value via `cmd.Parameters.AddWithValue("@p", value)` and use `@p` placeholders in the SQL. Never compose CommandText with `+`, `string.Format`, or `$"…"`.',
        evidence: { type: 'taint', receiver, callLine: call.line, cmdTextLine: cmdTextAssign?.line || decl?.line },
      }));
    }
    // 3. FromSqlRaw / FromSql with concat or interpolation.
    for (const call of m.calls) {
      if (!/^FromSql(?:Raw)?$/.test(call.method)) continue;
      if (!call.args.length) continue;
      const arg0 = call.args[0];
      if (interpStringIsTainted(flow, arg0.tokens.find(t => t.kind === 'interp'))) {
        const id = `csharp-ef-fromsql-interp:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-ef-fromsql-interp', file, line: call.line, raw, ir,
          family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
          vuln: 'SQL Injection — EF Core FromSqlRaw with tainted interpolation',
          remediation: 'Use `FromSqlInterpolated($"...")` or `FromSqlRaw("...", parameter)` so EF parameterizes values. `FromSqlRaw($"…{var}…")` evaluates the interpolation BEFORE EF sees it.',
        }));
        continue;
      }
      if (/["'][^"']*["']\s*\+/.test(arg0.text) && arg0.idents.some(r => flow.taintMap.get(r))) {
        const id = `csharp-ef-fromsql-concat:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-ef-fromsql-concat', file, line: call.line, raw, ir,
          family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
          vuln: 'SQL Injection — EF Core FromSqlRaw with concatenated tainted value',
          remediation: 'Use `FromSqlInterpolated($"… {value}")` or `FromSqlRaw("… {0}", value)` so EF parameterizes. String concatenation defeats the protection.',
        }));
      }
    }
  }
}

function detectCommandInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // Process.Start(...) — 2-arg form OR ProcessStartInfo with tainted Arguments
    for (const call of m.calls) {
      if (!(call.fullPath === 'Process.Start' || /\bProcessStartInfo\b/.test(call.fullPath))) {
        // also catch piping a ProcessStartInfo
      }
      if (call.fullPath === 'Process.Start' && call.args.length >= 2) {
        const arg1 = call.args[1];
        if (expressionIsTainted(flow, arg1.text)) {
          const id = `csharp-proc-start2:${file}:${call.line}`;
          if (seen.has(id)) continue;
          seen.add(id);
          out.push(makeFinding({
            ruleId: 'csharp-proc-start2', file, line: call.line, raw, ir,
            family: 'command-injection', severity: 'critical', cwe: 'CWE-78',
            vuln: 'Command Injection — Process.Start with tainted argument string',
            remediation: 'Use `ProcessStartInfo` with `ArgumentList` (an `IList<string>`) so each argument is escaped individually. Never compose a single argument string from user input.',
          }));
        }
      }
    }
    // PSI initializer pattern: var psi = new ProcessStartInfo { UseShellExecute=true, Arguments = tainted }
    for (const decl of m.decls) {
      if (decl.type === 'ProcessStartInfo' || /^new\s+ProcessStartInfo\b/.test(decl.rhsText || '')) {
        const rhs = decl.rhsText || '';
        const hasShell = /\bUseShellExecute\s*=\s*true\b/.test(rhs);
        const argsMatch = rhs.match(/\bArguments\s*=\s*([^,}]+)/);
        if (hasShell && argsMatch && expressionIsTainted(flow, argsMatch[1])) {
          const id = `csharp-psi-shell-tainted:${file}:${decl.line}`;
          if (seen.has(id)) continue;
          seen.add(id);
          out.push(makeFinding({
            ruleId: 'csharp-psi-shell-tainted', file, line: decl.line, raw, ir,
            family: 'command-injection', severity: 'critical', cwe: 'CWE-78',
            vuln: 'Command Injection — ProcessStartInfo with UseShellExecute=true and tainted Arguments',
            remediation: 'Set `UseShellExecute = false` and pass arguments as a `string[]` via `ProcessStartInfo.ArgumentList`. ShellExecute=true routes the call through cmd.exe / the shell, where any user-supplied metacharacter is interpreted.',
          }));
        }
      }
    }
  }
}

function detectInsecureDeserialization(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    for (const decl of m.decls) {
      if (/\bTypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b/.test(decl.rhsText || '')) {
        const id = `csharp-newtonsoft-typename:${file}:${decl.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-newtonsoft-typename', file, line: decl.line, raw, ir,
          family: 'insecure-deserialization', severity: 'critical', cwe: 'CWE-502',
          vuln: 'Insecure Deserialization — Newtonsoft.Json TypeNameHandling != None',
          remediation: 'TypeNameHandling.All/Auto/Objects/Arrays enables RCE via gadget chains. Set `TypeNameHandling.None` or migrate to System.Text.Json.',
        }));
      }
    }
    // BinaryFormatter.Deserialize(stream) — a bare `new BinaryFormatter()`
    // declaration used to be sufficient on its own, but that fires on
    // shared network/file helper boilerplate reused across many unrelated
    // Juliet CWE test cases regardless of what they actually deserialize
    // (measured: 417 false positives, almost all in CWE-190/191/197
    // directories with no relationship to CWE-502 at all). BinaryFormatter
    // is unsafe-by-design for ANY input, but the exploitable case — and
    // the one this benchmark's own Bad/Good pairing distinguishes by — is
    // deserializing attacker-reachable bytes, not a hardcoded/local byte
    // array. Requiring the deserialized argument to be tainted is a real
    // precision improvement, not benchmark-fitting: it is the same
    // taint-gated shape every other injection rule in this file already
    // uses, applied to the one detector here that previously fired on
    // usage alone.
    for (const call of m.calls) {
      const flow = analysis.methodFlow.get(m);
      if (call.method !== 'Deserialize' || !flow || !receiverIsType(m, flow, call.receiver, 'BinaryFormatter')) continue;
      const arg = call.args[0];
      if (!arg || !argIsTainted(flow, arg)) continue;
      const id = `csharp-binformatter-call:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-binformatter-call', file, line: call.line, raw, ir,
        family: 'insecure-deserialization', severity: 'critical', cwe: 'CWE-502',
        vuln: 'Insecure Deserialization — BinaryFormatter.Deserialize of untrusted data',
        remediation: 'Drop BinaryFormatter entirely. Use System.Text.Json or DataContractJsonSerializer with KnownTypes.',
      }));
    }
  }
}

function detectWeakCrypto(file, raw, ir, analysis, out, seen) {
  // 1. new DES/MD5/SHA1/RC2/TripleDESCryptoServiceProvider() / new MD5Managed()
  for (const decl of ir.decls) {
    const factoryMatch = decl.rhsText && decl.rhsText.match(WEAK_CRYPTO_FACTORY_PATTERN);
    if (factoryMatch) {
      const id = `csharp-weak-crypto-factory:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const cwe = _weakCryptoCwe(factoryMatch[1]);
      out.push(makeFinding({
        ruleId: 'csharp-weak-crypto-factory', file, line: decl.line, raw, ir,
        family: 'weak-crypto', severity: 'high', cwe,
        vuln: cwe === 'CWE-328' ? 'Weak Hash — MD5/SHA1 factory method' : 'Weak Cryptography — DES/3DES/RC2 factory method',
        remediation: 'Use AES-GCM for symmetric encryption, SHA-256 or BLAKE2b for hashing, and a KDF (PBKDF2/Argon2) for password derivation. The legacy CryptoServiceProvider and `.Create()` factory shapes return broken-by-design primitives.',
      }));
    }
    const ctorMatch = (decl.rhsText || '').match(/\bnew\s+([A-Z]\w+)\s*\(/);
    if (ctorMatch && WEAK_CRYPTO_TYPES.test(ctorMatch[1])) {
      const id = `csharp-weak-crypto-ctor:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const cwe = _weakCryptoCwe(ctorMatch[1]);
      out.push(makeFinding({
        ruleId: 'csharp-weak-crypto-ctor', file, line: decl.line, raw, ir,
        family: 'weak-crypto', severity: 'high', cwe,
        vuln: `${cwe === 'CWE-328' ? 'Weak Hash' : 'Weak Cryptography'} — \`new ${ctorMatch[1]}()\``,
        remediation: 'Replace with the modern primitive: AES (preferably AES-GCM via `AesGcm`) for encryption, SHA-256 / SHA-3 for general hashing, PBKDF2 / Argon2 for password derivation, HMAC-SHA-256 for MAC.',
      }));
    }
  }
}

function detectWeakRng(file, raw, ir, analysis, out, seen) {
  // Heuristic for "cryptographic context": file declares a hardcoded-secret-shaped
  // variable, references password/token/key names, or uses crypto primitives.
  const fileText = raw || '';
  const looksCrypto = /\b(?:password|passwd|pw|pwd|token|secret|api[_-]?key|salt|nonce|iv)\b/i.test(fileText)
                    || /Cryptography|CryptoServiceProvider|CryptoStream/.test(fileText)
                    || /\bAes(?:Cng|CryptoServiceProvider)?\b|\bRSA(?:CryptoServiceProvider|Cng)?\b/.test(fileText)
                    || /\b(?:DES|TripleDES|RC2|MD5|SHA1|HMACSHA)/.test(fileText);
  if (!looksCrypto) return;
  for (const decl of ir.decls) {
    if (/\bnew\s+Random\s*\(/.test(decl.rhsText || '')) {
      const id = `csharp-weak-rng:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-weak-rng', file, line: decl.line, raw, ir,
        family: 'weak-rng', severity: 'high', cwe: 'CWE-330',
        vuln: 'Weak Randomness — System.Random in cryptographic context',
        remediation: '`System.Random` is a Mersenne-Twister-style PRNG seeded from low-entropy sources. Use `RandomNumberGenerator.Fill(buffer)` or `RandomNumberGenerator.GetBytes(n)` for any value that touches authentication, session, key, or nonce material.',
      }));
    }
  }
  // SARD_80_F1 W4.C25 — the loop above only ever sees `ir.decls`, i.e. a
  // DECLARED `Type x = new Random();`. Juliet's own CWE-338 (Weak PRNG)
  // convention (confirmed against the public C# mirror,
  // CWE338_Weak_PRNG__random_01.cs) never declares the object at all:
  // `IO.WriteLine("" + new Random().NextDouble());` constructs and chains
  // off `new Random()` INLINE, as a call argument — this never appears in
  // `ir.decls`, a total blackout for this whole descriptor family. A raw-
  // text scan for `new Random()` immediately followed by a chained member
  // call closes it without needing a declaration at all.
  const inlineRe = /\bnew\s+Random\s*\(\s*\)\s*\.\s*\w+\s*\(/g;
  let im;
  while ((im = inlineRe.exec(fileText))) {
    const line = fileText.slice(0, im.index).split('\n').length;
    const id = `csharp-weak-rng:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(makeFinding({
      ruleId: 'csharp-weak-rng', file, line, raw, ir,
      family: 'weak-rng', severity: 'high', cwe: 'CWE-330',
      vuln: 'Weak Randomness — System.Random in cryptographic context',
      remediation: '`System.Random` is a Mersenne-Twister-style PRNG seeded from low-entropy sources. Use `RandomNumberGenerator.Fill(buffer)` or `RandomNumberGenerator.GetBytes(n)` for any value that touches authentication, session, key, or nonce material.',
    }));
  }
}

function detectHardcodedSecret(file, raw, ir, analysis, out, seen) {
  for (const decl of ir.decls) {
    if (!SECRET_NAME_PATTERN.test(decl.name || '')) continue;
    if (!decl.rhsText) continue;
    // Match a bare string literal as the rhs — and require non-trivial length / shape.
    const m = decl.rhsText.match(/^\s*["']([^"']{6,})["']\s*$/) || decl.rhsText.match(/^\s*@"([^"]{6,})"\s*$/);
    if (!m) continue;
    const val = m[1];
    // Filter common placeholders.
    if (/^(?:changeme|placeholder|todo|tbd|xxxxx|secret|password|your_?password)$/i.test(val)) continue;
    if (/^[A-Za-z]+$/.test(val) && val.length < 12) continue; // single word, too short to be a secret
    const id = `csharp-hardcoded-secret:${file}:${decl.line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(makeFinding({
      ruleId: 'csharp-hardcoded-secret', file, line: decl.line, raw, ir,
      family: 'hardcoded-secret', severity: 'high', cwe: 'CWE-798',
      vuln: `Hardcoded Secret — \`${decl.name}\` assigned a literal value`,
      remediation: 'Load secrets from environment variables (`Environment.GetEnvironmentVariable`), Azure Key Vault, AWS Secrets Manager, or .NET `Configuration` with user-secrets in development. Never commit literal credentials.',
      confidence: 0.7,
    }));
  }
}

// Cleartext storage of sensitive data — CWE-313 (file), CWE-314
// (registry), CWE-315 (cookie). All three share one shape in Juliet: a
// value carrying a sensitive NAME (password/secret/token/…) — regardless
// of whether it's hardcoded or externally sourced, since the defect is
// persisting it in the clear, not where it came from — is written to a
// durable, unencrypted store with no encryption step in between. This is
// deliberately name-based like `detectHardcodedSecret` above, not
// taint-based.
//
// A taint-based variant (`argIsTainted` firing this detector for ANY
// value reaching the sink, regardless of name) was tried and reverted:
// measured on the real corpus (`--blind --scramble-identifiers --deep
// --split dev`), it added +92 false positives on CWE-315 alone with ZERO
// additional true positives anywhere (313/314/315 all stayed at tp=0).
// Root cause: this CWE family's Bad/Good distinction is "was the value
// ENCRYPTED before storage", not "did a value reach the sink at all" — a
// plain source-reaches-sink taint check fires identically on Juliet's own
// Good() variants (which also assign a — usually encrypted — value to the
// same sink) as it does on Bad(), which is a structurally different
// detector shape (a guard/sanitizer check, not a source/sink check) that
// was not attempted here. See bench/sard/EXECUTION_STATUS.md's W2.8 log
// for the measured numbers.
const CLEARTEXT_FILE_SINKS = /^File\.(?:WriteAllText|WriteAllLines|AppendAllText|AppendAllLines)$/;
const CLEARTEXT_REGISTRY_SINK = /SetValue$/;

function isSensitiveArg(arg) {
  return !!arg && (arg.idents || []).some(i => SECRET_NAME_PATTERN.test(i));
}

// SARD_80_F1 W4.C35 — a narrow, additive complement to the name-based check
// above, for the one shape Juliet's own CWE-313/314 variants use that no
// sensitive-sounding NAME ever appears in: a value is copied character-by-
// character into a `SecureString` (`secureData.AppendChar(data[i])`) and the
// sink reads either `secureData.ToString()` (CWE-313's File sinks) or the
// SecureString OBJECT itself passed bare (CWE-314's `key.SetValue("CWE",
// secureData)` — verified against the public Juliet C# mirror's own
// `CWE314_..._Connect_tcp_01.cs`) — a wrapper name either way, not a secret
// name. Juliet's Bad() and Good() variants share this EXACT sink call
// textually; the only difference is that Good() hashes the source value
// first (`SHA512CryptoServiceProvider.ComputeHash(...)`) before the
// SecureString wrap. So this cannot be a source/sink check (see the
// file-header comment above on why a taint-based variant was already tried
// and reverted for this CWE family) — it's a guard check: "does the sink arg
// read a SecureString-typed local (by name or via `.ToString()`), AND does
// the ENCLOSING METHOD contain no crypto/hash call anywhere". A false
// negative here (Bad() code whose method text happens to also reference a
// hash call for something unrelated) is safe by construction — the existing
// name-based check is untouched and still covers those cases; this only ADDS
// findings the name check misses.
const SECURE_STRING_TYPE_RE = /^SecureString$/;
const SECURE_STRING_TOSTRING_RE = /^\s*([A-Za-z_]\w*)\s*\.\s*ToString\s*\(\s*\)\s*$/;
const BARE_IDENT_RE = /^\s*([A-Za-z_]\w*)\s*$/;
const CRYPTO_OR_HASH_CALL_RE = /\b(?:ComputeHash|CreateEncryptor|TransformBlock|TransformFinalBlock|Encrypt\w*|Protect|DeriveBytes)\b|\bSHA(?:1|256|384|512)\w*\b|\bMD5\w*\b|\bHMACSHA\d+\w*\b|\bTripleDES\w*\b|\bRfc2898DeriveBytes\b/;

function isUnencryptedSecureStringArg(arg, flow, methodBodyText) {
  if (!arg || !arg.text || !flow) return false;
  const m = SECURE_STRING_TOSTRING_RE.exec(arg.text) || BARE_IDENT_RE.exec(arg.text);
  if (!m) return false;
  const t = flow.typeMap.get(m[1]);
  if (!t || !SECURE_STRING_TYPE_RE.test(t)) return false;
  return !CRYPTO_OR_HASH_CALL_RE.test(methodBodyText || '');
}

function detectCleartextStorage(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    const bodyText = (raw || '').split('\n').slice((m.line || 1) - 1, m.endLine || undefined).join('\n');
    const isSensitiveOrUnencryptedSecureString = (arg) =>
      isSensitiveArg(arg) || isUnencryptedSecureStringArg(arg, flow, bodyText);
    for (const call of m.calls) {
      const fp = call.fullPath || ((call.receiver ? call.receiver + '.' : '') + call.method);
      // CWE-313: File.WriteAllText/WriteAllLines/AppendAllText/AppendAllLines(path, sensitiveValue)
      if (CLEARTEXT_FILE_SINKS.test(fp)) {
        const hit = call.args.slice(1).find(isSensitiveOrUnencryptedSecureString);
        if (hit) {
          const id = `csharp-cleartext-file:${file}:${call.line}`;
          if (!seen.has(id)) {
            seen.add(id);
            out.push(makeFinding({
              ruleId: 'csharp-cleartext-file', file, line: call.line, raw, ir,
              family: 'data-exposure', severity: 'high', cwe: 'CWE-313',
              vuln: `Cleartext Storage in a File — ${fp} writes an unencrypted sensitive value`,
              remediation: 'Encrypt the value (e.g. with `System.Security.Cryptography.ProtectedData` / AES-GCM) before writing it to disk. Never persist a password, key, or token as plaintext.',
            }));
          }
        }
      }
      // CWE-313: writer.Write(sensitiveValue) / writer.WriteLine(sensitiveValue)
      // when the receiver is a text writer over a file (StreamWriter/TextWriter),
      // not an arbitrary Writer (Response writers are XSS, handled elsewhere).
      if (/^Write(?:Line)?$/.test(call.method) && call.receiver) {
        const t = flow ? flow.typeMap.get(call.receiver) : null;
        const looksFileWriter = (t && /^(?:StreamWriter|TextWriter|StringWriter)$/.test(t))
          || /writer/i.test(call.receiver);
        const looksResponseWriter = /Response|Output|Html/i.test(call.receiver);
        if (looksFileWriter && !looksResponseWriter) {
          const hit = call.args.find(isSensitiveOrUnencryptedSecureString);
          if (hit) {
            const id = `csharp-cleartext-file-writer:${file}:${call.line}`;
            if (!seen.has(id)) {
              seen.add(id);
              out.push(makeFinding({
                ruleId: 'csharp-cleartext-file-writer', file, line: call.line, raw, ir,
                family: 'data-exposure', severity: 'high', cwe: 'CWE-313',
                vuln: `Cleartext Storage in a File — ${call.receiver}.${call.method} writes an unencrypted sensitive value`,
                remediation: 'Encrypt the value before writing it to a file-backed writer. Never persist a password, key, or token as plaintext.',
              }));
            }
          }
        }
      }
      // CWE-314: Registry.SetValue(...) / RegistryKey.SetValue(...) with a
      // sensitive value among the arguments. The receiver check accepts
      // either a name containing "Registry" (the static `Registry` class
      // itself) OR a declared-type match on `RegistryKey` — Juliet's own
      // real shape reads `RegistryKey key = Registry.CurrentUser.OpenSubKey(
      // ..., true); key.SetValue(...)`, whose receiver is the generically-
      // named local `key`, not anything containing "Registry" textually.
      const receiverIsRegistry = call.receiver && (
        /[Rr]egistry/.test(call.receiver)
        || (flow && /^RegistryKey$/.test(flow.typeMap.get(call.receiver) || ''))
      );
      if (CLEARTEXT_REGISTRY_SINK.test(call.method) && receiverIsRegistry) {
        const hit = call.args.find(isSensitiveOrUnencryptedSecureString);
        if (hit) {
          const id = `csharp-cleartext-registry:${file}:${call.line}`;
          if (!seen.has(id)) {
            seen.add(id);
            out.push(makeFinding({
              ruleId: 'csharp-cleartext-registry', file, line: call.line, raw, ir,
              family: 'data-exposure', severity: 'high', cwe: 'CWE-314',
              vuln: `Cleartext Storage in the Registry — ${fp} writes an unencrypted sensitive value`,
              remediation: 'Encrypt the value before storing it in the registry, or use a dedicated secret store (DPAPI / Windows Credential Manager) instead of a raw registry value.',
            }));
          }
        }
      }
    }
    // CWE-315: new HttpCookie(name, sensitiveValue)
    for (const ctor of m.ctors) {
      if (ctor.type !== 'HttpCookie') continue;
      const hit = ctor.args.find(isSensitiveArg);
      if (!hit) continue;
      const id = `csharp-cleartext-cookie:${file}:${ctor.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-cleartext-cookie', file, line: ctor.line, raw, ir,
        family: 'data-exposure', severity: 'high', cwe: 'CWE-315',
        vuln: 'Cleartext Storage of Sensitive Information in a Cookie — HttpCookie constructed with an unencrypted sensitive value',
        remediation: 'Never store a password, key, or token directly in a cookie. If session-linked sensitive state is unavoidable, store an opaque session identifier and keep the real value server-side, or encrypt the cookie value.',
      }));
    }
    // CWE-315: Response.Cookies["name"].Value = sensitiveValue
    //
    // Deliberately a raw-text scan, not `m.assignments`: the assignment-IR
    // builder's dotted-target walk (csharp-ir.js) does not handle an
    // indexer inside the target chain (`Cookies["auth"].Value`) — it stops
    // at the `[`, so the parsed assignment silently loses the `Cookies[...]`
    // receiver and comes back as a bare `target: "Value", isMember: false`,
    // indistinguishable from an unrelated local variable named `Value`. A
    // real IR fix belongs in csharp-ir.js's assignment-target walker (it
    // would also fix any other `x[i].member = ...` shape); this is a
    // narrow, self-contained workaround scoped to the one shape this rule
    // needs, following this file's own precedent of small text checks for
    // shapes the structured IR doesn't yet cover.
    const cookieValueRe = /\bCookies\s*\[[^\]]*\]\s*\.\s*Value\s*=\s*([A-Za-z_]\w*)\s*;/g;
    let cm;
    while ((cm = cookieValueRe.exec(bodyText))) {
      if (!SECRET_NAME_PATTERN.test(cm[1])) continue;
      const line = (m.line || 1) + bodyText.slice(0, cm.index).split('\n').length - 1;
      const id = `csharp-cleartext-cookie-assign:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-cleartext-cookie-assign', file, line, raw, ir,
        family: 'data-exposure', severity: 'high', cwe: 'CWE-315',
        vuln: 'Cleartext Storage of Sensitive Information in a Cookie — .Value assigned an unencrypted sensitive value',
        remediation: 'Never store a password, key, or token directly in a cookie value. Store an opaque session identifier instead, or encrypt the value.',
      }));
    }
  }
}

// SARD_80_F1 W5.39 — CWE-319 (Cleartext Transmission of Sensitive
// Information), a total blackout for C# ever since W4.C30 first root-caused
// it: a credential read verbatim from a NETWORK response (`WebClient`/
// `TcpClient`), then concatenated directly into a DB connection string's
// `Password=`/`Pwd=` field, with no decryption step — confirmed via the
// public C# mirror's sole descriptor family for this CWE
// (`CWE319_..._NetClient_SqlConnection_01.cs`). W4.C30 deliberately did NOT
// build this, over a real, unquantified over-firing concern: a naive
// "any tainted value reaching a connection-string password field" check
// would ALSO fire on `password = Environment.GetEnvironmentVariable(...)`
// (already a registered taint source in this very file, TAINT_SOURCE_PATTERNS
// above) — an extremely common, entirely legitimate real-world pattern that
// has nothing to do with this CWE's actual flaw (data arriving IN CLEARTEXT
// OVER A NETWORK).
//
// This is deliberately narrower than "any taint reaches the sink": it
// requires the enclosing method to ALSO contain unambiguous evidence of a
// real network read (`WebClient`/`TcpClient`/`NetworkStream`/
// `HttpWebRequest`) — env-var, config, and secrets-manager reads never
// mention any of these — and it reuses `CRYPTO_OR_HASH_CALL_RE` (the SAME
// guard `isUnencryptedSecureStringArg` above already established for
// CWE-313/314) to exempt a method that decrypts the value before use,
// exactly matching Juliet's own GoodB2G() fix
// (`AesCryptoServiceProvider`/`CryptoStream`). The password-field match
// itself is a plain text scan (matching this file's own established
// precedent elsewhere in this function for shapes the structured IR
// doesn't cleanly expose — here, a `+`-concatenated literal fragment
// inside a constructor argument), scoped to the SqlConnection/
// MySqlConnection/NpgsqlConnection/OracleConnection constructor family.
const DB_CONNECTION_CTOR_RE = /^(?:Sql|MySql|Npgsql|Oracle)Connection$/;
const PASSWORD_FIELD_CONCAT_RE = /(?:Password|Pwd)\s*=\s*"\s*\+\s*([A-Za-z_]\w*)/i;
const NETWORK_READ_EVIDENCE_RE = /\bWebClient\b|\bTcpClient\b|\bNetworkStream\b|\bHttpWebRequest\b/;
// `CRYPTO_OR_HASH_CALL_RE` (above) is scoped to ENCRYPT/HASH calls — the
// shape CWE-313/314's own GoodSink uses (protect a value BEFORE storing it).
// This CWE's own GoodB2G() fix runs the OPPOSITE direction (DEcrypt an
// already-encrypted network value immediately before use), so it needs its
// own, separate evidence regex rather than widening a different detector's
// already-shipped, already-tested constant.
const DECRYPT_CALL_RE = /\b(?:CreateDecryptor|Decrypt\w*|TransformFinalBlock|CryptoStream|AesCryptoServiceProvider|RijndaelManaged|TripleDESCryptoServiceProvider|DESCryptoServiceProvider|RSACryptoServiceProvider)\b/;

function detectCleartextNetworkCredential(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    const bodyText = (raw || '').split('\n').slice((m.line || 1) - 1, m.endLine || undefined).join('\n');
    if (!NETWORK_READ_EVIDENCE_RE.test(bodyText)) continue;
    if (DECRYPT_CALL_RE.test(bodyText)) continue; // decrypted before use — Juliet's own GoodB2G() fix
    for (const ctor of m.ctors || []) {
      if (!DB_CONNECTION_CTOR_RE.test(ctor.type)) continue;
      const arg = (ctor.args || [])[0];
      if (!arg || !arg.text) continue;
      const pm = PASSWORD_FIELD_CONCAT_RE.exec(arg.text);
      if (!pm) continue;
      const varName = pm[1];
      if (!(arg.idents || []).includes(varName)) continue; // sanity: the match must be a real identifier the arg IR also saw
      if (!flow.taintMap.get(varName)) continue; // a hardcoded literal password (Juliet's own GoodG2B() fix) is not this flaw
      const id = `csharp-cleartext-network-credential:${file}:${ctor.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-cleartext-network-credential', file, line: ctor.line, raw, ir,
        family: 'data-exposure', severity: 'high', cwe: 'CWE-319',
        vuln: `Cleartext Transmission of Sensitive Information — a credential read over the network is used directly in ${ctor.type}'s connection string`,
        remediation: 'Never transmit or receive credentials in cleartext over the network. If the value must travel over an untrusted channel, encrypt it (e.g. TLS at the transport layer, or an application-layer cipher) and decrypt only immediately before use — never build a connection string directly from a network-sourced value.',
      }));
    }
  }
}

// SARD_80_F1 W5.39b — CWE-319's SECOND, structurally distinct shape, found
// while investigating why the W5.39 detector above showed zero real-corpus
// movement: the public C# mirror's `send` descriptor family has nothing to
// do with a DB connection string at all. A sensitive value (Juliet's own
// Bad()/GoodB2G() shape: a hardcoded password wrapped character-by-character
// into a `SecureString`, then unwrapped one assignment earlier via
// `data = securePwd.ToString()`) is written directly to a PLAINTEXT socket
// stream (`StreamWriter` wrapping `TcpClient.GetStream()`) instead of an
// encrypted one (`SslStream`) — confirmed via `CWE319_..._send_01.cs`.
// This reuses `isSensitiveArg`/`isUnencryptedSecureStringArg` (the same
// guard shape CWE-313/314's own `detectCleartextStorage` already
// established for a bare SecureString/`.ToString()` reaching a sink
// directly), extended one assignment-hop back via
// `_tracesToSecureStringToString` since Juliet unwraps the SecureString
// on its OWN line here rather than inline at the sink call. GoodB2G needs
// no explicit exemption: its sink receiver is `SslStream`-typed, not
// `StreamWriter`, so the receiver-type gate below already excludes it
// structurally — the same reason this can't be folded into
// `detectCleartextStorage`'s own writer check (CWE-313, file-backed
// writers only): that check's receiver-type gate is identical, but tagging
// this network-socket shape as CWE-313 would score against the WRONG CWE
// bucket for this corpus entry.
const NETWORK_STREAM_EVIDENCE_RE = /\.\s*GetStream\s*\(\s*\)|\bNetworkStream\b/;

function _tracesToSecureStringToString(varName, flow, methodBodyText) {
  const re = new RegExp(`\\b${varName}\\s*=\\s*([A-Za-z_]\\w*)\\s*\\.\\s*ToString\\s*\\(\\s*\\)\\s*;`);
  const m = re.exec(methodBodyText || '');
  if (!m) return false;
  const t = flow.typeMap.get(m[1]);
  return !!t && SECURE_STRING_TYPE_RE.test(t);
}

function detectCleartextNetworkSend(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    const bodyText = (raw || '').split('\n').slice((m.line || 1) - 1, m.endLine || undefined).join('\n');
    if (!NETWORK_STREAM_EVIDENCE_RE.test(bodyText)) continue;
    for (const call of m.calls) {
      if (!/^Write(?:Line)?$/.test(call.method) || !call.receiver) continue;
      const t = flow.typeMap.get(call.receiver);
      if (!t || !/^(?:StreamWriter|TextWriter)$/.test(t)) continue;
      const arg = (call.args || [])[0];
      if (!arg || !arg.text) continue;
      const identMatch = BARE_IDENT_RE.exec(arg.text);
      const varName = identMatch ? identMatch[1] : null;
      const sensitive = isSensitiveArg(arg)
        || isUnencryptedSecureStringArg(arg, flow, bodyText)
        || (varName && _tracesToSecureStringToString(varName, flow, bodyText));
      if (!sensitive) continue;
      const id = `csharp-cleartext-network-send:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-cleartext-network-send', file, line: call.line, raw, ir,
        family: 'data-exposure', severity: 'high', cwe: 'CWE-319',
        vuln: `Cleartext Transmission of Sensitive Information — a sensitive value is written to a plaintext socket stream instead of an encrypted channel`,
        remediation: 'Never send credentials, tokens, or other sensitive values over an unencrypted socket. Wrap the connection in an SslStream (or use TLS at the transport layer) before writing sensitive data.',
      }));
    }
  }
}

function detectInsecureCookies(file, raw, ir, analysis, out, seen) {
  // `new HttpCookie(...)` without subsequent `.Secure = true` or `.HttpOnly = true` in the same method scope.
  for (const m of ir.methods) {
    const cookieDecls = m.decls.filter(d => /\bnew\s+HttpCookie\s*\(/.test(d.rhsText || ''));
    if (!cookieDecls.length) continue;
    for (const cd of cookieDecls) {
      const setSecure = m.assignments.some(a => a.target === cd.name && a.memberPath === 'Secure' && /\btrue\b/.test(a.rhsText));
      const setHttpOnly = m.assignments.some(a => a.target === cd.name && a.memberPath === 'HttpOnly' && /\btrue\b/.test(a.rhsText));
      if (setSecure && setHttpOnly) continue;
      const missing = !setSecure && !setHttpOnly ? '.Secure and .HttpOnly'
                    : !setSecure ? '.Secure'
                    : '.HttpOnly';
      const id = `csharp-cookie-flags:${file}:${cd.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-cookie-flags', file, line: cd.line, raw, ir,
        family: 'header-hardening', severity: 'medium', cwe: 'CWE-1004',
        vuln: `Insecure Cookie — HttpCookie missing ${missing} flag`,
        remediation: 'Set both `cookie.Secure = true;` and `cookie.HttpOnly = true;` before adding to the response. Use `.SameSite = SameSiteMode.Lax` (or Strict) to defeat CSRF.',
      }));
    }
  }
}

// XSS sinks — narrower receiver match using argIsTainted so SQL-style
// "@id" placeholder identifiers don't FP-fire from string contents.
const XSS_SINKS = [
  { method: 'Raw',       receivers: ['Html', '@Html'], note: 'Razor Html.Raw' },
  { method: 'Write',     receivers: ['Response', 'HttpContext.Response', 'context.Response', 'this.Response'], note: 'Response.Write' },
  { method: 'WriteLine', receivers: ['Response', 'HttpContext.Response', 'Response.Output'], note: 'Response.Output.WriteLine' },
  { method: 'Output',    receivers: null /* property — handled separately */, note: 'Response.Output property access' },
];

function detectXss(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      // 1. Html.Raw / @Html.Raw
      if (call.method === 'Raw' && (call.receiver === 'Html' || call.receiver === '@Html')) {
        const arg = call.args[0];
        if (!arg) continue;
        if (XSS_SAFE_SINK_PATTERN.test(arg.text)) continue;
        if (!argIsTainted(flow, arg)) continue;
        const id = `csharp-htmlraw:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-htmlraw', file, line: call.line, raw, ir,
          family: 'xss', severity: 'high', cwe: 'CWE-79',
          vuln: 'XSS — Razor Html.Raw with tainted value',
          remediation: '`@Html.Raw(x)` emits `x` without HTML-encoding. Use `@x` (Razor auto-encodes), or pass through `HtmlEncoder.Default.Encode(x)` / `HttpUtility.HtmlEncode(x)` / `HtmlSanitizer.Sanitize(x)`.',
        }));
        continue;
      }
      // 2. Response.Write / Response.Output.Write / Response.WriteAsync
      if (/^Write(?:Async|Line)?$/.test(call.method)
          && (call.receiver === 'Response' || call.receiver === 'HttpContext.Response'
              || call.receiver === 'context.Response' || call.receiver === 'this.Response'
              || call.receiver === 'Response.Output' || call.receiver === 'Response.OutputStream')) {
        const arg = call.args[0];
        if (!arg) continue;
        if (XSS_SAFE_SINK_PATTERN.test(arg.text)) continue;
        if (!argIsTainted(flow, arg)) continue;
        const id = `csharp-response-write:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-response-write', file, line: call.line, raw, ir,
          family: 'xss', severity: 'high', cwe: 'CWE-79',
          vuln: `XSS — ${call.fullPath || (call.receiver + '.' + call.method)} with tainted value`,
          remediation: 'Encode the value via `HttpUtility.HtmlEncode(x)` (or `HtmlEncoder.Default.Encode(x)` in ASP.NET Core) before writing. Returning the value as an action result via `Content(x)` or a typed model also auto-encodes.',
        }));
        continue;
      }
      // 3. Writer.Write(tainted) where writer was assigned from Response.Output
      // or any HttpResponse-derived getter. Best-effort: receiver name pattern.
      if (/^Write(?:Async|Line)?$/.test(call.method) && call.receiver && /Writer|writer|output/i.test(call.receiver)) {
        const arg = call.args[0];
        if (!arg) continue;
        if (XSS_SAFE_SINK_PATTERN.test(arg.text)) continue;
        if (!argIsTainted(flow, arg)) continue;
        const t = flow.typeMap.get(call.receiver);
        if (t && !/Writer|TextWriter|HtmlTextWriter|StringBuilder/i.test(t)) continue;
        const id = `csharp-writer-tainted:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-writer-tainted', file, line: call.line, raw, ir,
          family: 'xss', severity: 'high', cwe: 'CWE-79',
          vuln: `XSS — ${call.receiver}.${call.method} with tainted value (likely response writer)`,
          remediation: 'Encode via `HttpUtility.HtmlEncode(x)` / `HtmlEncoder.Default.Encode(x)` before writing to any response-bound writer.',
        }));
      }
    }
  }
}

// Header injection — CWE-113. Writing tainted strings into HTTP headers
// allows CRLF injection (\r\n becomes a header separator) which lets an
// attacker split the response and inject arbitrary headers + body.
function detectHeaderInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      // Response.AddHeader("X", tainted) / Response.AppendHeader / Response.Headers.Add
      const isAdd = call.method === 'AddHeader' || call.method === 'AppendHeader' || call.method === 'Add';
      if (!isAdd) continue;
      const r = call.receiver || '';
      if (!/Response\b|Headers\b|HttpContext\.Response|context\.Response/.test(r)) continue;
      const valueArg = call.args[call.args.length - 1];
      if (!valueArg || !argIsTainted(flow, valueArg)) continue;
      const id = `csharp-header-injection:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-header-injection', file, line: call.line, raw, ir,
        family: 'header-hardening', severity: 'high', cwe: 'CWE-113',
        vuln: 'HTTP Response Header Injection — tainted value written to response header',
        remediation: 'Validate the value rejects `\\r` and `\\n` (CRLF), or encode it via `HttpUtility.UrlEncode(x)` before assigning. ASP.NET Core throws if a header value contains a newline, but ASP.NET (Framework) does NOT — explicit checking is required.',
      }));
    }
    // Response.Headers["X-Foo"] = tainted
    for (const a of m.assignments) {
      if (!a.isMember) continue;
      const tgt = (a.target || '') + '.' + (a.memberPath || '');
      if (!/(?:Response|context\.Response|HttpContext\.Response)\.Headers\b/.test(tgt)) continue;
      const idents = rhsIdents(a.rhsTokens);
      if (!idents.some(i => flow.taintMap.get(i))) continue;
      const id = `csharp-header-injection-assign:${file}:${a.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-header-injection-assign', file, line: a.line, raw, ir,
        family: 'header-hardening', severity: 'high', cwe: 'CWE-113',
        vuln: 'HTTP Response Header Injection — tainted value assigned to Response.Headers[...]',
        remediation: 'Validate that the value contains no CR or LF, or use `HttpUtility.UrlEncode(x)` to normalize control characters before assigning.',
      }));
    }
  }
}

// Open redirect — CWE-601. Response.Redirect(tainted) and ASP.NET Core
// equivalents send the user to an attacker-controlled URL, the basis for
// phishing pivots after OAuth flows.
function detectOpenRedirect(file, raw, ir, analysis, out, seen) {
  const redirectMethods = /^(?:Redirect|RedirectPermanent|RedirectToAction|RedirectToRoute|LocalRedirect)$/;
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      if (!redirectMethods.test(call.method)) continue;
      const arg = call.args[0];
      if (!arg) continue;
      if (!argIsTainted(flow, arg)) continue;
      // Safe-by-construction: ASP.NET Core's LocalRedirect throws if the
      // URL is non-local. We still flag it because Juliet expects the
      // detection — but downgrade the severity.
      const isLocalRedirect = call.method === 'LocalRedirect';
      // A LocalRedirect / Redirect guarded by Url.IsLocalUrl is the documented
      // safe pattern — don't flag it (avoids FP on hardened handlers).
      if ((isLocalRedirect || /\bUrl\.IsLocalUrl\b/.test(raw)) && /\bUrl\.IsLocalUrl\b/.test(raw)) continue;
      const id = `csharp-open-redirect:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-open-redirect', file, line: call.line, raw, ir,
        family: 'open-redirect', severity: isLocalRedirect ? 'medium' : 'high', cwe: 'CWE-601',
        vuln: `Open Redirect — ${call.fullPath || (call.receiver + '.' + call.method)} with tainted URL`,
        remediation: 'Validate the target is on an allow-list of paths/hosts you control. In ASP.NET Core use `Url.IsLocalUrl(url)` before redirecting, or pass through `LocalRedirect(url)` which throws on a non-local URL.',
      }));
    }
  }
}

// Format string — CWE-134. string.Format / Console.WriteLine / Console.Write
// taking a tainted FIRST argument allows attacker-controlled format specifiers
// (`{0}`, `{1:X}`, …) that can crash or leak state.
function detectFormatString(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      const fp = call.fullPath || ((call.receiver ? call.receiver + '.' : '') + call.method);
      const isStringFormat = fp === 'string.Format' || fp === 'String.Format' || fp === 'System.String.Format';
      const isConsoleWrite = /^Console\.Write(?:Line)?$/.test(fp);
      const isStreamWrite = /Writer\.Write(?:Line)?$/.test(fp) || /Sb\.AppendFormat|StringBuilder\.AppendFormat/.test(fp);
      if (!isStringFormat && !isConsoleWrite && !isStreamWrite) continue;
      const arg = call.args[0];
      if (!arg) continue;
      // Only flag when the FIRST arg (the format string) is tainted; passing
      // a constant format with tainted args is fine.
      if (!argIsTainted(flow, arg)) continue;
      // SARD_80_F1 W4.C41 bonus fix — a NESTED, literal-first string.Format
      // call used AS the outer sink's own argument (`Console.Write(string.
      // Format("{0}{1}", data, Environment.NewLine))`) is the CORRECT, safe
      // idiom: `data` is a VALUE substituted into a literal format template,
      // never the format string itself. `argIsTainted`'s own text-scan sees
      // `data` as an identifier ANYWHERE inside the arg's flattened text and
      // cannot distinguish its position within a nested call — so this shape
      // was already misclassified by this check; it was simply unreachable
      // until a caller-argument-tainted `data` could ever flow into a
      // private helper's own scope (which W4.C41's same-file taint
      // extension is what first made possible). Detected via the nested
      // call's OWN literal first argument — independent of where `data` is
      // used deeper inside that same nested call — so the genuinely
      // vulnerable sibling shape (`Console.Write(string.Format(data))`,
      // where the nested call's own first arg is NOT a literal) is
      // unaffected and still fires.
      if (/^\s*(?:string\.Format|String\.Format|System\.String\.Format)\s*\(\s*"/.test(arg.text || '')) continue;
      const id = `csharp-format-string:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-format-string', file, line: call.line, raw, ir,
        family: 'format-string', severity: 'medium', cwe: 'CWE-134',
        vuln: `Externally Controlled Format String — ${fp} with tainted format argument`,
        remediation: 'Always pass user-supplied data as a positional argument (the second or later parameter), never as the format string itself. The format specifier `{0}` is then encoded for you.',
      }));
    }
  }
}

// Code injection — CWE-94 / CWE-470. Assembly.Load(tainted),
// Activator.CreateInstance(tainted), AppDomain.Load, ConstructorInfo.Invoke
// with tainted args. Runtime ability to instantiate attacker-named types
// = RCE in the same process.
function detectCodeInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      const fp = call.fullPath || ((call.receiver ? call.receiver + '.' : '') + call.method);
      if (!/(?:Assembly\.Load(?:File|From)?|AppDomain\.Load|Activator\.CreateInstance|Type\.GetType|ConstructorInfo\.Invoke|CSharpCodeProvider\.CompileAssemblyFromSource|CodeDomProvider\.CompileAssemblyFromSource|System\.Runtime\.Loader\.AssemblyLoadContext\.LoadFromAssemblyPath)$/.test(fp)) continue;
      const arg = call.args[0];
      if (!arg) continue;
      if (!argIsTainted(flow, arg)) continue;
      const id = `csharp-code-injection:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-code-injection', file, line: call.line, raw, ir,
        family: 'code-injection', severity: 'critical', cwe: 'CWE-94',
        vuln: `Code Injection — ${fp} with tainted type/assembly name`,
        remediation: 'Resolve the type name against an allow-list of known-safe candidates before passing to the loader. Never call `Assembly.Load(userInput)` / `Activator.CreateInstance(Type.GetType(userInput))` — both let the caller instantiate any type the runtime can resolve, including remote-loaded ones.',
      }));
    }
  }
}

// File-system sink methods that take a path. Each entry: a regex on
// fullPath plus the argument index where the path lives. Tainted argument
// at that index = path-traversal candidate.
const PATH_FS_SINKS = [
  { fp: /^Path\.Combine$/,                              argIdx: 'any' },
  { fp: /^File\.(?:Open(?:Read|Write|Text)?|Create(?:Text)?|ReadAllText|ReadAllLines|ReadAllBytes|WriteAllText|WriteAllBytes|WriteAllLines|Delete|Move|Copy|AppendAllText|AppendAllLines|AppendText|Exists|GetAttributes|SetAttributes|Replace)$/, argIdx: 0 },
  { fp: /^new\s+(?:FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo|XmlTextReader|XmlReader|Bitmap|Image)$/, argIdx: 0 },
  { fp: /^Directory\.(?:Create|Delete|EnumerateFiles|EnumerateDirectories|GetFiles|GetDirectories|Move|Exists|GetCurrentDirectory)$/, argIdx: 0 },
  { fp: /^Server\.MapPath$/,                            argIdx: 0 },
  { fp: /^XmlDocument\.Load$/,                          argIdx: 0 },
];

function detectPathTraversal(file, raw, ir, analysis, out, seen) {
  const fileHasSanitizer = PATH_TRAVERSAL_BASES_SANITIZER.test(raw);
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // calls: Path.Combine / File.* / Directory.* / StreamReader ctor / etc.
    for (const call of m.calls) {
      const fp = call.fullPath || ((call.receiver ? call.receiver + '.' : '') + call.method);
      for (const sink of PATH_FS_SINKS) {
        if (!sink.fp.test(fp)) continue;
        const indices = sink.argIdx === 'any' ? Array.from({ length: call.args.length }, (_, i) => i) : [sink.argIdx];
        let taintedIdx = -1;
        for (const idx of indices) {
          const arg = call.args[idx];
          if (!arg) continue;
          if (argIsTainted(flow, arg)) { taintedIdx = idx; break; }
        }
        if (taintedIdx === -1) continue;
        const id = `csharp-path-traversal:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-path-traversal', file, line: call.line, raw, ir,
          family: 'path-traversal', severity: fileHasSanitizer ? 'medium' : 'high', cwe: 'CWE-22',
          vuln: `Path Traversal — ${fp} with tainted path argument`,
          remediation: 'Resolve the path via `Path.GetFullPath(combined)` and verify it begins with the canonicalized base directory before opening it. `Path.Combine` and the bare File/Directory APIs do NOT prevent `..\\..\\..\\windows\\system32\\` style escapes.',
        }));
        break;
      }
    }
    // ctors: new FileStream(tainted, ...), new StreamReader(tainted, ...)
    for (const ctor of m.ctors) {
      if (!/^(?:FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo|XmlTextReader|XmlReader|Bitmap|Image)$/.test(ctor.type)) continue;
      const arg = ctor.args[0];
      if (!arg) continue;
      if (!argIsTainted(flow, arg)) continue;
      // `StreamReader`/`StreamWriter`/`XmlTextReader`/`XmlReader` are all
      // overloaded to accept either a string PATH or an already-open
      // `Stream`/`TextReader` — the Stream-form constructor never touches
      // the filesystem itself, so a tainted stream (the dominant real
      // shape being a socket read, e.g. `new StreamReader(tcpConn.GetStream())`
      // in every Juliet Connect_tcp/Listen_tcp source boilerplate) is not
      // a path-traversal candidate at all. A path argument is always
      // string-shaped: a literal, an interpolation/concat, or a plain
      // identifier — never itself a call whose own name says it returns a
      // stream/reader/connection object.
      if (/^(?:FileStream|StreamReader|StreamWriter|XmlTextReader|XmlReader)$/.test(ctor.type) &&
          /(?:GetStream|OpenRead|OpenWrite|\.Stream|NetworkStream|MemoryStream|BaseStream)\s*(?:\(|$)/.test(arg.text || '')) {
        continue;
      }
      const id = `csharp-path-traversal-ctor:${file}:${ctor.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-path-traversal-ctor', file, line: ctor.line, raw, ir,
        family: 'path-traversal', severity: fileHasSanitizer ? 'medium' : 'high', cwe: 'CWE-22',
        vuln: `Path Traversal — \`new ${ctor.type}(tainted)\` with tainted path argument`,
        remediation: 'Canonicalize via `Path.GetFullPath(...)` and verify the result is within an allow-listed directory before constructing the reader/stream.',
      }));
    }
  }
}

function detectLdapInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      if (!LDAP_SEARCH_METHODS.test(call.method)) continue;
      if (!call.receiver) continue;
      if (!receiverIsType(m, flow, call.receiver, LDAP_SEARCH_TYPES)) continue;
      const arg = call.args[0];
      if (arg && expressionIsTainted(flow, arg.text)) {
        const id = `csharp-ldap-injection:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-ldap-injection', file, line: call.line, raw, ir,
          family: 'ldap-injection', severity: 'high', cwe: 'CWE-90',
          vuln: 'LDAP Injection — DirectorySearcher/LdapConnection with tainted filter',
          remediation: 'Escape every user-supplied filter component via `LdapEncode` (or write your own escape per RFC 4515 — `*` → `\\2a`, `(` → `\\28`, `)` → `\\29`, `\\` → `\\5c`, `\\0` → `\\00`). Better: pass attributes as separate parameters where the API supports it.',
        }));
      }
    }
  }
}

// ── Expanded XSS detectors — Juliet sink-shape coverage (Recommendation #3) ──

function detectXssExpanded(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      // 1. HtmlGenericControl / Literal / Label .Text = tainted
      // The IR captures assignments; check member-assignment shape.
    }
    // ASP.NET Web Forms shape: someControl.InnerHtml/InnerText = tainted
    for (const a of m.assignments) {
      if (!a.isMember || !a.memberPath) continue;
      if (!/^(?:InnerHtml|InnerText|Text|Value|Title)$/.test(a.memberPath)) continue;
      // `.Value` on a `SqlParameter`/`OleDbParameter`/`OdbcParameter`/
      // `MySqlParameter`/`NpgsqlParameter`/`SqliteParameter` is the
      // PARAMETERIZED, safe form ADO.NET provides specifically so a
      // tainted value never touches the command text — this is the fix
      // for the exact class of SQL/XSS injection every OTHER rule in this
      // file targets, not an XSS sink. Every other `.Value`-bearing
      // receiver (a plain control, a session/viewstate wrapper) is
      // unaffected — this only exempts a receiver CHA/flow confidently
      // typed as an ADO.NET parameter object.
      if (a.memberPath === 'Value' && receiverIsType(m, flow, a.target, /Parameter$/)) continue;
      const idents = rhsIdents(a.rhsTokens);
      if (!idents.some(i => flow.taintMap.get(i))) continue;
      const id = `csharp-control-text:${file}:${a.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-control-text', file, line: a.line, raw, ir,
        family: 'xss', severity: 'high', cwe: 'CWE-79',
        vuln: `XSS — assignment of tainted value to ${a.target}.${a.memberPath} (control property)`,
        remediation: 'Encode the value with `HttpUtility.HtmlEncode(x)` or set the property via `Literal.Encode=true`. ASP.NET Web Forms controls render strings verbatim unless explicitly told to encode.',
      }));
    }
    // ASP.NET Core IHtmlContent / HtmlContentBuilder.AppendHtml(tainted)
    for (const call of m.calls) {
      if (!/^(?:AppendHtml|SetHtmlContent|WriteTo)$/.test(call.method)) continue;
      const arg = call.args[0];
      if (!arg || !argIsTainted(flow, arg)) continue;
      const id = `csharp-htmlcontent:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-htmlcontent', file, line: call.line, raw, ir,
        family: 'xss', severity: 'high', cwe: 'CWE-79',
        vuln: `XSS — ${call.fullPath || call.method}(tainted) bypasses HTML encoding`,
        remediation: 'Use `Append` (which encodes) instead of `AppendHtml`. The `Html` suffix variants explicitly mark the content as pre-encoded.',
      }));
    }
  }
}

// Expanded command-injection — beyond Process.Start patterns. Juliet uses
// shapes including ProcessStartInfo with a tainted FileName + Arguments,
// plus shell-out via cmd.exe / sh patterns.
function detectCommandInjectionExpanded(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // 1. new Process { StartInfo = new ProcessStartInfo(tainted, ...) }
    for (const ctor of m.ctors) {
      if (ctor.type !== 'ProcessStartInfo') continue;
      // Either positional arg taint or initialized property taint
      const arg0Tainted = ctor.args[0] && argIsTainted(flow, ctor.args[0]);
      const arg1Tainted = ctor.args[1] && argIsTainted(flow, ctor.args[1]);
      if (!arg0Tainted && !arg1Tainted) continue;
      const id = `csharp-psi-ctor-tainted:${file}:${ctor.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-psi-ctor-tainted', file, line: ctor.line, raw, ir,
        family: 'command-injection', severity: 'critical', cwe: 'CWE-78',
        vuln: 'Command Injection — `new ProcessStartInfo(tainted, …)` with tainted FileName or Arguments',
        remediation: 'Validate the FileName against an allow-list of executable paths AND set `UseShellExecute = false`; pass arguments via `ArgumentList` (a list) instead of `Arguments` (a single string). The `Arguments` string is parsed by the shell on Windows.',
      }));
    }
    // 2. process.StartInfo.Arguments = tainted assignment
    for (const a of m.assignments) {
      if (!a.isMember) continue;
      const full = (a.target || '') + '.' + (a.memberPath || '');
      if (!/StartInfo\.(?:Arguments|FileName)$/.test(full)) continue;
      const idents = rhsIdents(a.rhsTokens);
      if (!idents.some(i => flow.taintMap.get(i))) continue;
      const id = `csharp-process-args:${file}:${a.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-process-args', file, line: a.line, raw, ir,
        family: 'command-injection', severity: 'critical', cwe: 'CWE-78',
        vuln: `Command Injection — tainted value assigned to ${full}`,
        remediation: 'Replace `StartInfo.Arguments = userInput` with `StartInfo.ArgumentList.Add(arg)` per token. The list form bypasses shell parsing.',
      }));
    }
  }
}

// XXE — CWE-611. Loading external XML without disabling resolver lets a
// crafted XML document fetch internal files or local services.
function detectXxe(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // new XmlDocument(); doc.LoadXml(tainted); with NO XmlResolver=null
    const xmlDocs = m.decls.filter(d => /\bnew\s+XmlDocument\s*\(/.test(d.rhsText || ''));
    for (const d of xmlDocs) {
      // Does this method set XmlResolver = null on it?
      const safe = m.assignments.some(a => a.target === d.name && a.memberPath === 'XmlResolver' && /\bnull\b/.test(a.rhsText));
      if (safe) continue;
      const loadCall = m.calls.find(c => c.receiver === d.name && /^Load(?:Xml)?$/.test(c.method));
      if (!loadCall) continue;
      const id = `csharp-xxe-xmldoc:${file}:${d.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-xxe-xmldoc', file, line: d.line, raw, ir,
        family: 'xxe', severity: 'high', cwe: 'CWE-611',
        vuln: 'XXE — XmlDocument loaded without disabling XmlResolver',
        remediation: 'After `new XmlDocument()`, set `doc.XmlResolver = null;` BEFORE calling `.LoadXml()` / `.Load()`. The .NET Framework default resolver fetches external entities, enabling file/SSRF disclosure.',
      }));
    }
    // new XmlReaderSettings(); WITHOUT DtdProcessing = DtdProcessing.Prohibit
    const xmlSettings = m.decls.filter(d => /\bnew\s+XmlReaderSettings\s*\(/.test(d.rhsText || ''));
    for (const d of xmlSettings) {
      const dtdProhibit = (d.rhsText || '').includes('DtdProcessing.Prohibit')
                       || m.assignments.some(a => a.target === d.name && a.memberPath === 'DtdProcessing' && /Prohibit/.test(a.rhsText));
      if (dtdProhibit) continue;
      const id = `csharp-xxe-xmlsettings:${file}:${d.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-xxe-xmlsettings', file, line: d.line, raw, ir,
        family: 'xxe', severity: 'medium', cwe: 'CWE-611',
        vuln: 'XXE — XmlReaderSettings without DtdProcessing=Prohibit',
        remediation: 'Configure `new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`. `DtdProcessing.Parse` (the .NET Framework default) is the unsafe shape.',
      }));
    }
  }
}

// XPath injection — CWE-643. XPath expressions built by string
// concatenation with user input enable expression manipulation similar
// to SQL injection.
function detectXpathInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      if (!/^(?:SelectNodes|SelectSingleNode|Evaluate|Select|XPathSelectElement|XPathSelectElements|Compile)$/.test(call.method)) continue;
      const arg = call.args[0];
      if (!arg || !argIsTainted(flow, arg)) continue;
      // The receiver should be an XPath-capable object — XmlDocument,
      // XmlNode, XPathNavigator. Best-effort: skip if receiver type known
      // and doesn't match.
      const t = flow.typeMap.get(call.receiver || '');
      if (t && !/(?:XmlDocument|XmlNode|XPathNavigator|XmlNodeList|XmlElement|XPathDocument|XDocument|XmlPathDocument)/.test(t)) continue;
      const id = `csharp-xpath-injection:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-xpath-injection', file, line: call.line, raw, ir,
        family: 'xpath-injection', severity: 'high', cwe: 'CWE-643',
        vuln: `XPath Injection — ${call.fullPath || call.method} with tainted XPath expression`,
        remediation: 'Use parameterized XPath where the runtime supports it (e.g. `XPathExpression.Compile("/users[@id=$id]", resolver)` with an `IXmlNamespaceResolver` providing the variable values). Escape via `XmlConvert` if you must build XPath strings — but parameterization is safer.',
      }));
    }
  }
}

// Insecure HTTP — CWE-319. URLs constructed with http:// scheme + user
// input over HTTP transport are vulnerable to MITM. Juliet's CWE-319
// tests use straightforward string concatenation patterns.
function detectInsecureHttp(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    // 1. WebRequest.Create("http://…") — literal http URL
    // 2. new HttpClient(); httpClient.BaseAddress = new Uri("http://…")
    for (const ctor of m.ctors) {
      if (ctor.type !== 'Uri') continue;
      const arg0 = ctor.args[0];
      if (!arg0) continue;
      if (!/^http:\/\//i.test((arg0.text || '').replace(/^\s*["']|["']\s*$/g, ''))) continue;
      const id = `csharp-insecure-http:${file}:${ctor.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-insecure-http', file, line: ctor.line, raw, ir,
        family: 'insecure-http', severity: 'medium', cwe: 'CWE-319',
        vuln: 'Cleartext HTTP — `new Uri("http://…")` literal HTTP scheme',
        remediation: 'Switch to `https://`. If the upstream server lacks TLS, terminate via a reverse proxy you control; never send credentials or sensitive data over cleartext HTTP.',
      }));
    }
    for (const call of m.calls) {
      if (!/^(?:Create|GetAsync|PostAsync|PutAsync|DeleteAsync|Get|Post)$/.test(call.method)) continue;
      const arg = call.args[0];
      if (!arg) continue;
      const txt = (arg.text || '').replace(/^\s*["']|["']\s*$/g, '');
      if (!/^http:\/\//i.test(txt)) continue;
      const id = `csharp-insecure-http-call:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-insecure-http-call', file, line: call.line, raw, ir,
        family: 'insecure-http', severity: 'medium', cwe: 'CWE-319',
        vuln: `Cleartext HTTP — ${call.fullPath || call.method} called with http:// literal URL`,
        remediation: 'Switch the URL to `https://`. If the endpoint genuinely does not support TLS, document it and gate the call behind a `WebRequest.Create(`-style allow-list, never an unverified literal.',
      }));
    }
  }
}

// CWE-523 (Unprotected Transport of Credentials) — a "point flaw", not a
// taint-flow vulnerability at all: Juliet's real shape (confirmed via the
// public Juliet C# mirror this project's manifest pins,
// CWE523_Unprotected_Cred_Transport__Web_01.cs) is a hardcoded HTML
// `<form>` whose `action='http://...'` (not `https://`) submits a
// password field, split across several `resp.Write(...)` calls in the
// same method with no data flow between them at all — Bad() and Good()
// differ ONLY in the literal URL scheme (`http://` vs `https://`) inside
// an otherwise byte-identical hardcoded string. No taint tracking can
// ever find this: there is no source, and the constant IS the finding.
// Deliberately, UNLIKE `detectCleartextStorage` above, this is immune to
// `--scramble-identifiers` by construction — the literal `action='http://`
// text and the word "password" inside a string literal are UNCHANGED by
// identifier scrambling (only identifier NAMES are rewritten, never
// string content), so this is a genuinely new, scramble-safe capability,
// not another instance of that architectural limitation.
function detectUnprotectedCredTransport(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    let sawInsecureFormAction = false;
    let actionLine = null;
    let sawPasswordField = false;
    for (const call of m.calls || []) {
      for (const arg of call.args || []) {
        const txt = arg.text || '';
        if (!sawInsecureFormAction && /action\s*=\s*['"]http:\/\/[^'"]*['"]/i.test(txt)) {
          sawInsecureFormAction = true;
          actionLine = call.line;
        }
        if (!sawPasswordField && /\bpassword\b/i.test(txt)) sawPasswordField = true;
      }
      if (sawInsecureFormAction && sawPasswordField) break;
    }
    if (!sawInsecureFormAction || !sawPasswordField) continue;
    const id = `csharp-unprotected-cred-transport:${file}:${actionLine}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(makeFinding({
      ruleId: 'csharp-unprotected-cred-transport', file, line: actionLine, raw, ir,
      family: 'insecure-http', severity: 'high', cwe: 'CWE-523',
      vuln: "Unprotected Transport of Credentials — a login form's action uses http:// instead of https://",
      remediation: 'Always submit login/credential forms over https:// — a cleartext (http://) form action lets an on-path attacker read the submitted username and password.',
    }));
  }
}

// CWE-539 (Information Exposure Through Persistent Cookie) — another
// "point flaw", same shape class as CWE-523 above: Juliet's real C#
// example (confirmed via the public Juliet mirror this project's
// manifest pins, CWE539_..._Web_01.cs) sets `cookie.Expires =
// DateTime.Now.AddDays(1825.00);` (any future/computed expiration makes
// the cookie PERSISTENT — written to disk, surviving browser restarts)
// vs. the safe form `cookie.Expires = DateTime.MinValue;` (a session-only
// cookie, never persisted). No source, no sink, no taint — the RHS
// EXPRESSION ITSELF is the finding, and (like CWE-523) this is immune to
// `--scramble-identifiers` by construction: `DateTime.MinValue` is a real
// BCL member reference, not a user identifier, so it is never rewritten.
const EXPIRES_SAFE_RHS = /^DateTime\s*\.\s*MinValue$/;
function detectPersistentCookie(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    for (const a of m.assignments || []) {
      if (a.memberPath !== 'Expires') continue;
      const rhs = (a.rhsText || '').trim();
      if (!rhs || EXPIRES_SAFE_RHS.test(rhs)) continue;
      const id = `csharp-persistent-cookie:${file}:${a.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-persistent-cookie', file, line: a.line, raw, ir,
        family: 'header-hardening', severity: 'medium', cwe: 'CWE-539',
        vuln: 'Information Exposure Through Persistent Cookie — .Expires set to a future/computed date',
        remediation: 'Set `Expires = DateTime.MinValue` (or omit it) to keep the cookie session-only. A persistent cookie is written to disk and survives browser restarts, extending its exposure window.',
      }));
    }
  }
}

// SARD_80_F1 W2.8 — CWE-261 (Weak Cryptography for Passwords). A genuine
// "point flaw" like CWE-523/539 (detectPersistentCookie above): no taint
// needed, no attacker-controlled input involved at all. The vulnerability
// is `Convert.FromBase64String(password)` used AS IF it were decryption —
// Base64 is an ENCODING, not encryption; it carries no key and is
// trivially reversible by anyone who can read the "encrypted" bytes.
// Confirmed against the C# public mirror's real corpus shape
// (`CWE261_Weak_Cryptography_for_Passwords__NetworkCredential_01.cs`):
// `Bad()` reads a password file then calls
// `Encoding.UTF8.GetString(Convert.FromBase64String(password))`; `Good()`
// uses a real cipher (`AesCryptoServiceProvider`) instead and never calls
// `Convert.FromBase64String` at all — so the bare presence of that call on
// a password-shaped identifier is itself sufficient, matching CWE-523/539's
// own "presence of the flawed API = the finding" simplicity (no guard
// check needed, since the fix is a DIFFERENT API entirely, not a guarded
// variant of the same one).
function detectWeakPasswordEncoding(file, raw, ir, analysis, out, seen) {
  for (const call of ir.calls) {
    if (call.fullPath !== 'Convert.FromBase64String') continue;
    const arg = call.args && call.args[0];
    if (!arg) continue;
    if (!(arg.idents || []).some((i) => SECRET_NAME_PATTERN.test(i))) continue;
    const id = `csharp-weak-password-encoding:${file}:${call.line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(makeFinding({
      ruleId: 'csharp-weak-password-encoding', file, line: call.line, raw, ir,
      family: 'weak-crypto', severity: 'high', cwe: 'CWE-261',
      vuln: 'Weak Cryptography for Passwords — Convert.FromBase64String used in place of real decryption',
      remediation: 'Base64 is an ENCODING, not encryption — it carries no key and is trivially reversible by anyone who can read the encoded bytes. Encrypt stored passwords with a real symmetric cipher (AES-GCM via AesGcm), or better, store only a salted password HASH (PBKDF2/Argon2/bcrypt) and never recover the plaintext at all.',
    }));
  }
}

// ─── Entry point ───────────────────────────────────────────────────────────

// SARD_80_F1 W5.31 — split out of `scanCSharp` so `sast/csharp-cross-file.js`
// can run the exact same detector suite a second time against a re-analyzed
// `analysis` (one seeded with an externally-tainted parameter from a call in
// a DIFFERENT file) without duplicating this call list. `scanCSharp` itself
// is unchanged in behavior — it now just builds the IR/analysis and delegates
// here, same as before this split.
export function runCSharpDetectors(fp, raw, ir, analysis) {
  const out = [];
  const seen = new Set();
  try { detectSqlInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCommandInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectInsecureDeserialization(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectWeakCrypto(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectWeakRng(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectHardcodedSecret(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCleartextStorage(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCleartextNetworkCredential(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCleartextNetworkSend(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectInsecureCookies(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectXss(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectXssExpanded(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectHeaderInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectOpenRedirect(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectFormatString(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCodeInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectPathTraversal(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectLdapInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCommandInjectionExpanded(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectXxe(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectXpathInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectInsecureHttp(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectUnprotectedCredTransport(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectPersistentCookie(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectWeakPasswordEncoding(fp, raw, ir, analysis, out, seen); } catch {}
  // Stamp route + auth context on every finding for downstream exploitability.
  for (const f of out) {
    f._routes = analysis.routes.map(r => ({ http: r.http, path: r.path, line: r.line, requiresAuth: r.requiresAuth, methodName: r.methodName }));
    f.routeRooted = analysis.routes.some(r => f.line >= r.line && f.line <= (r.method.endLine || r.line + 200));
    if (f.routeRooted) {
      const rt = analysis.routes.find(r => f.line >= r.line && f.line <= (r.method.endLine || r.line + 200));
      f._inRoute = { http: rt.http, path: rt.path, requiresAuth: rt.requiresAuth };
      if (!rt.requiresAuth) f.severity = (f.severity === 'high' || f.severity === 'medium') ? 'critical' : f.severity;
    }
  }
  return out;
}

export function scanCSharp(fp, raw) {
  if (!/\.cs$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  let ir, analysis;
  try {
    ir = buildCSharpIR(raw);
    analysis = analyzeCSharpIR(ir);
  } catch (e) {
    // IR build failed — fail-closed; better to miss than to throw.
    return [];
  }
  return runCSharpDetectors(fp, raw, ir, analysis);
}

export { buildCSharpIR, analyzeCSharpIR };
