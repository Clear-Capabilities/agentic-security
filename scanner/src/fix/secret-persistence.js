// Did the patch REMOVE a hard-coded secret, or only change how it is written? (E3-08)
//
// Moving `const k = 'abc123...'` to `const k = atob('YWJjMTIz...')`, splitting it in two literals, reversing it or hex-encoding it all
// make a pattern-based scanner stop seeing a secret that is still in the source. This looks for the original literal after the patch in
// the forms a lazy "fix" uses. It cannot catch encryption with a key kept next to it or other transformations; it says what it checked.
const MIN_LEN = 8;

const literalsOnLines = (text, lines) => {
  const out = new Set();
  const all = String(text).split('\n');
  for (const n of lines) {
    const l = all[n - 1];
    if (!l) continue;
    for (const m of l.matchAll(/(["'`])((?:\\.|(?!\1).){8,})\1/g)) out.add(m[2]);
  }
  return [...out].filter((s) => s.length >= MIN_LEN);
};
const squash = (t) => String(t).replace(/["'`+\s]/g, '');
const forms = (v) => {
  const b64 = Buffer.from(v).toString('base64');
  return [v, [...v].reverse().join(''), Buffer.from(v).toString('hex'), b64, b64.replace(/=+$/, ''), encodeURIComponent(v)].filter((x) => x.length >= MIN_LEN);
};

/**
 * @param {{before:string, after:string, line:number|null}} o
 * @returns {{status:'passed'|'failed'|'not_run', reason:string|null, checked:number}}
 */
export function checkSecretPersistence({ before, after, line }) {
  if (!Number.isInteger(line) || line < 1) return { status: 'not_run', reason: 'the finding has no line, so the secret literal cannot be located', checked: 0 };
  const lits = literalsOnLines(before, [line - 1, line, line + 1].filter((n) => n >= 1));
  if (!lits.length) return { status: 'not_run', reason: 'no string literal of 8 or more characters near the finding line', checked: 0 };
  const flat = squash(after);
  for (const lit of lits) {
    for (const f of forms(lit)) {
      if (String(after).includes(f) || flat.includes(squash(f))) return { status: 'failed', reason: `the secret is still in the source (${f === lit ? 'unchanged' : 'as a re-encoded or split form'}); moving or encoding it does not remove it`, checked: lits.length };
    }
  }
  return { status: 'passed', reason: null, checked: lits.length };
}
