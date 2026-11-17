// Credential repair (verified-remediation PRD FR-15, M4-04): source removal, replacement wiring and the lifecycle a source change cannot
// complete on its own.
//
// The leaked value is never stored. A contract records its LOCATION (file and line) and length; the verifier reads the value from the
// original source snapshot when it checks a revision, and every message names only the form it found, never the value.
//
//   checkRemoval   the `credential-removed` obligation over a revision's files: the value must not appear in any application file, nor
//                  any re-encoding of it this module can recognise: base64 and base64url (with or without padding), hex in either case,
//                  the value reversed, the value percent-encoded, the value split into adjacent string literals joined with `+` or in a
//                  template, and the value as character codes (`String.fromCharCode(...)`, a numeric array). Re-encoding is not
//                  removal (AC-15.1). An encoding outside that list (a custom cipher, a value fetched at runtime from a file the
//                  candidate adds) is not recognised: that is a stated limit, and the behaviour obligation still requires the
//                  replacement credential from the environment.
//   lifecycle      what the record states beyond the source: replacement distribution and old-credential revocation are external.
//                  Revocation is `verified` only from a connector the OPERATOR invoked with its own credentials that returned a receipt;
//                  a connector error is `failed` (AC-15.3), no connector is `unavailable`, and nothing in a project file can invoke one
//                  (AC-15.5). A source repair with revocation required and not verified is `lifecycle incomplete` (AC-15.2).

/** The longest string literal on the given line of the original text: the leaked value, read at check time and never stored. */
export function extractCredential(text, line) {
  const l = String(text || '').split('\n')[line - 1] || '';
  const lits = [...l.matchAll(/(['"`])((?:\\.|(?!\1)[^\\\n])*)\1/g)].map((m) => m[2]);
  const best = lits.sort((a, b) => b.length - a.length)[0];
  return best && best.length >= 12 ? best : null;
}

const joined = (t) => String(t)
  .replace(/(['"`])\s*\+\s*(['"`])/g, '')
  .replace(/\$\{\s*(['"])((?:\\.|(?!\1)[^\\\n])*)\1\s*\}/g, '$2');

function charCodeRuns(t) {
  const out = [];
  for (const m of String(t).matchAll(/(?:fromCharCode\s*\(|\[)\s*((?:\d{1,5}\s*,\s*){7,}\d{1,5})\s*[\])]/g)) {
    const codes = m[1].split(',').map((x) => Number(x.trim()));
    if (codes.every((c) => c >= 0 && c < 0x110000)) out.push(String.fromCodePoint(...codes));
  }
  return out;
}

/** Which recognised forms of the value appear in which files. Messages name forms and files only. */
export function checkRemoval(value, files) {
  if (!value) return { ok: false, found: [{ file: null, form: 'the leaked value could not be read from the original source at the declared line' }] };
  const b64 = Buffer.from(value, 'utf8').toString('base64');
  const forms = [
    ['the value', value], ['base64', b64], ['base64 without padding', b64.replace(/=+$/, '')],
    ['base64url', Buffer.from(value, 'utf8').toString('base64url')], ['hex', Buffer.from(value, 'utf8').toString('hex')],
    ['upper-case hex', Buffer.from(value, 'utf8').toString('hex').toUpperCase()], ['the value reversed', [...value].reverse().join('')],
    ...(encodeURIComponent(value) !== value ? [['the value percent-encoded', encodeURIComponent(value)]] : []),
  ];
  const found = [];
  for (const [file, text] of Object.entries(files || {})) {
    if (typeof text !== 'string') continue;
    for (const [form, v] of forms) if (text.includes(v)) found.push({ file, form });
    if (!found.some((f) => f.file === file) && joined(text).includes(value)) found.push({ file, form: 'the value split into joined string literals' });
    if (charCodeRuns(text).some((s) => s.includes(value))) found.push({ file, form: 'the value as character codes' });
  }
  return { ok: found.length === 0, found };
}

/** Revocation through an operator-invoked connector. Never throws; only a returned receipt is `verified`. */
export async function revoke(connector, request) {
  if (!connector || typeof connector.revoke !== 'function') return { status: 'unavailable', reason: 'no revocation connector was invoked by the operator' };
  try {
    const r = await connector.revoke(request);
    if (r && r.ok === true && typeof r.receipt === 'string' && r.receipt.length) return { status: 'verified', receipt: r.receipt.slice(0, 200), connector: String(connector.id || 'connector').slice(0, 80) };
    return { status: 'failed', reason: String(r?.reason || 'the connector did not return a receipt').slice(0, 200), connector: String(connector.id || 'connector').slice(0, 80) };
  } catch (e) {
    return { status: 'failed', reason: `the connector failed: ${String(e?.message || e).slice(0, 160)}`, connector: String(connector.id || 'connector').slice(0, 80) };
  }
}

/** Every recognised form of the value, for redaction. */
export function formsOf(value) {
  if (!value) return [];
  const b64 = Buffer.from(value, 'utf8').toString('base64');
  return [value, b64, b64.replace(/=+$/, ''), Buffer.from(value, 'utf8').toString('base64url'), Buffer.from(value, 'utf8').toString('hex'), Buffer.from(value, 'utf8').toString('hex').toUpperCase(), [...value].reverse().join(''), encodeURIComponent(value)];
}

/** Replace every recognised form of the value in every string of `obj`, in place. Records carry source lines (scope signals). */
export function redactValue(obj, value) {
  const forms = formsOf(value).filter((f) => f.length >= 8);
  if (!forms.length) return obj;
  const walk = (o) => {
    if (!o || typeof o !== 'object') return;
    for (const [k, v] of Object.entries(o)) {
      if (typeof v === 'string') { let s = v; for (const f of forms) s = s.split(f).join('[credential redacted]'); if (s !== v) o[k] = s; }
      else walk(v);
    }
  };
  walk(obj);
  return obj;
}
