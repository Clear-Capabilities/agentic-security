import { blankComments } from './_comment-strip.js';
// JS/TS prototype pollution.
//
// The dangerous shapes:
//   1. Recursive merge / deep-extend / set-by-path with a user-controlled key
//      ( __proto__, constructor.prototype, prototype ) that walks Object.proto.
//   2. lodash.set(obj, userKey, userVal)  ·  _.merge(target, userInput)
//   3. Object.assign({}, userInput)  is safe (writes onto fresh obj) — we
//      flag the dangerous variants only:  Object.assign(target, userInput).
//
// Heuristic: a function-shaped merge/assign with one of these literal sink
// names + a request-shape source, OR a hand-rolled deep merge that
// dereferences `target[key]` with `key` straight from input.

const SINK_HINTS = [
  /\b_\s*\.\s*(?:merge|set|setWith|defaultsDeep|mergeWith)\s*\(/g,
  /\blodash\.\s*(?:merge|set|setWith|defaultsDeep|mergeWith)\s*\(/g,
  /\bObject\s*\.\s*assign\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g,
  /\bdeepExtend\s*\(/g,
  /\bdefaultsDeep\s*\(/g,
];

const HAND_ROLLED_MERGE = /for\s*\(\s*(?:const|let|var)?\s*(\w+)\s+in\s+(\w+)\s*\)\s*\{[^}]{0,200}\b\1\s*\[\s*\w+\s*\]\s*=\s*\2\s*\[\s*\w+\s*\]/g;

const PROTO_LITERAL_WRITES = [
  /\[\s*['"`]__proto__['"`]\s*\]/g,
  /\.\s*__proto__\b/g,
  /\.\s*constructor\s*\.\s*prototype\b/g,
];

const USER_INPUT_RE = /\b(req|request)\s*\.\s*(?:body|query|params|headers)\b|JSON\.parse\s*\(/;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanPrototypePollution(fp, raw) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const re of SINK_HINTS) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      // Need user input nearby (within 200 chars after the open-paren).
      const window = code.slice(m.index, m.index + 300);
      if (!USER_INPUT_RE.test(window)) continue;
      const line = lineOf(raw, m.index);
      push({
        id: `prototype-pollution:${fp}:${line}`,
        file: fp, line,
        vuln: 'Prototype Pollution: Recursive merge / set with user-controlled key',
        severity: 'high',
        cwe: 'CWE-1321',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Either (a) freeze the target with `Object.freeze(Object.prototype)`/`--disable-proto=delete` Node flag, (b) reject keys `__proto__` / `constructor` / `prototype` before recursive merge, or (c) use a merge primitive that explicitly blocks proto walks (`lodash.mergeWith` with a `customizer` that returns undefined for proto keys, or `safe-merge`). Adding `if (key === "__proto__" || key === "constructor" || key === "prototype") continue;` to a hand-rolled merge is the minimum bar.',
        parser: 'PROTO-POLLUTION',
        confidence: 0.80,
      });
    }
  }

  // Hand-rolled deep merge — only flag if user input flows in.
  let m;
  const r = new RegExp(HAND_ROLLED_MERGE.source, HAND_ROLLED_MERGE.flags);
  while ((m = r.exec(code))) {
    const window = code.slice(Math.max(0, m.index - 200), m.index + 400);
    if (!USER_INPUT_RE.test(window)) continue;
    const line = lineOf(raw, m.index);
    push({
      id: `prototype-pollution-handrolled:${fp}:${line}`,
      file: fp, line,
      vuln: 'Prototype Pollution: Hand-rolled deep merge without proto-key filter',
      severity: 'high',
      cwe: 'CWE-1321',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Add a guard clause inside the loop: `if (key === "__proto__" || key === "constructor" || key === "prototype") continue;` before writing. Better: drop the hand-rolled merge in favour of `structuredClone` + a typed schema validator (zod/yup/joi) that drops unknown keys.',
      parser: 'PROTO-POLLUTION',
      confidence: 0.75,
    });
  }

  // Explicit __proto__ writes from any source.
  for (const re of PROTO_LITERAL_WRITES) {
    const r2 = new RegExp(re.source, re.flags);
    let mm;
    while ((mm = r2.exec(code))) {
      // Only flag write context: an `=` that is a genuine assignment, not
      // part of a comparison operator (==, ===, !=, !==, <=, >=). The
      // previous /=\s*[^=]/ check wasn't anchored to the first `=`, so it
      // matched the trailing `=` of a `===` chain (e.g.
      // `obj.__proto__ === Object.prototype`) as a false "write."
      const post = code.slice(mm.index, mm.index + 60);
      if (!/(?<![=!<>])=(?!=)/.test(post)) continue;
      const line = lineOf(raw, mm.index);
      push({
        id: `prototype-pollution-direct:${fp}:${line}`,
        file: fp, line,
        vuln: 'Prototype Pollution: Direct write to __proto__ / constructor.prototype',
        severity: 'high',
        cwe: 'CWE-1321',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Direct writes to `__proto__` or `constructor.prototype` corrupt all objects of that type for the rest of the process. There is virtually no legitimate use case in application code — restructure to use `Object.create(null)`, a `Map`, or a typed class instead.',
        parser: 'PROTO-POLLUTION',
        confidence: 0.90,
      });
    }
  }

  return findings;
}
