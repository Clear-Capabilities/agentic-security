// Safe Template Haskell declarations and inert quasi-quotes (HS boundaries).
//
// The parser treats a Template Haskell splice or a quasi-quote as an opaque boundary: it cannot see the code the
// compiler will generate, so the file is `unresolved` in scan health. A small, closed set of constructs is different:
// a well-known generator applied to nothing but NAMES and LITERALS (`makeLenses ''T`, `deriveJSON defaultOptions ''T`,
// `share [mkPersist sqlSettings] [persistLowerCase| ... |]`) defines names, executes no project-controlled string and
// introduces no source, sink or sanitizer; and a raw-string quasi-quote (`[r|...|]`, or `[i|...|]` with no
// interpolation) is a string literal. Those are recognised here and reported as a DISCLOSED ASSUMPTION instead of an
// opaque boundary.
//
// Soundness rules (each one is pinned by a test in both directions):
//   - The generator must be IMPORTED from the upstream module that defines it, with the import actually exposing the name,
//     and must not be defined in the file. A local `makeLenses` stays opaque.
//   - Every token of the declaration must be accounted for. An argument that is a variable, a call, a lambda, a string
//     built from an expression, a nested splice or any other quasi-quote leaves the whole declaration opaque.
//   - Nothing here executes anything. This is a closed-form match over tokens, not an evaluation.
//   - The assumption is stated on the boundary: the generator is taken to be the upstream package's, and what it
//     generates (lenses, instances, persistent entities) is not modelled.

// generator name -> modules that export it
const GENERATORS = new Map([
  ['makeLenses', ['Control.Lens', 'Control.Lens.TH', 'Lens.Micro.TH', 'Lens.Micro.Platform']],
  ['makeLensesWith', ['Control.Lens', 'Control.Lens.TH']],
  ['makeClassy', ['Control.Lens', 'Control.Lens.TH', 'Lens.Micro.TH', 'Lens.Micro.Platform']],
  ['makeClassyPrisms', ['Control.Lens', 'Control.Lens.TH']],
  ['makePrisms', ['Control.Lens', 'Control.Lens.TH']],
  ['makeFields', ['Control.Lens', 'Control.Lens.TH']],
  ['makeWrapped', ['Control.Lens', 'Control.Lens.TH', 'Control.Lens.Wrapped']],
  ['deriveJSON', ['Data.Aeson.TH']],
  ['deriveToJSON', ['Data.Aeson.TH']],
  ['deriveFromJSON', ['Data.Aeson.TH']],
  ['deriveSafeCopy', ['Data.SafeCopy']],
  ['deriveSafeCopySimple', ['Data.SafeCopy']],
  ['mkPersist', ['Database.Persist.TH']],
  ['mkMigrate', ['Database.Persist.TH']],
  ['mkSave', ['Database.Persist.TH']],
  ['mkDeleteCascade', ['Database.Persist.TH']],
  ['share', ['Database.Persist.TH']],
  ['makeAcidic', ['Data.Acid', 'Data.Acid.TH']],
]);

// plain identifiers that may appear as an argument: option records and settings values the generators document
const SAFE_VALUES = new Map([
  ['defaultOptions', ['Data.Aeson.TH', 'Data.Aeson']],
  ['lensRules', ['Control.Lens', 'Control.Lens.TH']],
  ['camelCaseFields', ['Control.Lens', 'Control.Lens.TH']],
  ['abbreviatedFields', ['Control.Lens', 'Control.Lens.TH']],
  ['underscoreFields', ['Control.Lens', 'Control.Lens.TH']],
  ['sqlSettings', ['Database.Persist.TH']],
  ['mkPersistSettings', ['Database.Persist.TH']],
]);

// quasi-quoters accepted inside a safe declaration
const SAFE_DECL_QUOTERS = new Map([
  ['persistLowerCase', ['Database.Persist.TH']],
  ['persistUpperCase', ['Database.Persist.TH']],
]);

// Option-record update (`defaultOptions { fieldLabelModifier = drop 4 }`): field names and the pure helpers a value may use.
const OPTION_FIELDS = new Set(['fieldLabelModifier', 'constructorTagModifier', 'omitNothingFields', 'allNullaryToStringTag', 'sumEncoding', 'unwrapUnaryRecords', 'tagSingleConstructors', 'rejectUnknownFields']);
const PURE_HELPERS = new Set(['drop', 'take', 'map', 'toLower', 'toUpper', 'id', 'camelTo2', 'tail', 'init']);

// inert quasi-quoters: name -> { modules, interpolating }. `interpolating` quoters are inert only when the body has no
// interpolation marker; a raw-string quoter is inert whatever the body says.
const INERT_QUOTERS = new Map([
  ['r', { modules: ['Text.RawString.QQ'], check: false }],
  ['here', { modules: ['Data.String.Here', 'Data.String.Here.Uninterpolated', 'Data.String.Here.Interpolated'], check: true }],
  ['hereLit', { modules: ['Data.String.Here', 'Data.String.Here.Uninterpolated'], check: true }],
  ['i', { modules: ['Data.String.Interpolate', 'Data.String.Interpolate.IsString', 'Data.String.Here', 'Data.String.Here.Interpolated'], check: true }],
  ['iii', { modules: ['Data.String.Interpolate'], check: true }],
  ['__i', { modules: ['Data.String.Interpolate'], check: true }],
  ['iTrim', { modules: ['Data.String.Here', 'Data.String.Here.Interpolated'], check: true }],
]);
const INTERPOLATION_MARK = /#\{|\$\{|\$\(|\$[A-Za-z_]/;

function splitQuoter(q) {
  const i = q.lastIndexOf('.');
  return i < 0 ? { qual: null, name: q } : { qual: q.slice(0, i), name: q.slice(i + 1) };
}

/** Is `name` (optionally qualified by `qual`) exported by one of `modules` through a visible import, and not shadowed locally? */
function importedFrom(name, qual, modules, imports, defined) {
  if (defined.has(name) && !qual) return false;
  for (const imp of imports) {
    if (!imp || !imp.module || !modules.includes(imp.module)) continue;
    if (qual) { if ((imp.as || imp.module) !== qual) continue; }
    else if (imp.qualified) continue;
    if (imp.items) {
      const listed = imp.items.includes(name);
      if (imp.hiding ? listed : !listed) continue;
    }
    return true;
  }
  return false;
}

/**
 * Classify one top-level splice item as a safe generative declaration.
 * @returns {{generators:string[], modules:string[]}|null}  null leaves it opaque
 */
export function classifySafeSplice(T, a, b, match, imports, defined) {
  const generators = [];
  const modules = new Set();
  const tok = (i) => T[i];
  const sameWord = (t) => t.k === 'varid' || t.k === 'qvarid';

  // value: a single argument starting at p, returns the next index or -1
  const parseValue = (p, end) => {
    const t = tok(p);
    if (!t) return -1;
    if (t.k === 'thname' || t.k === 'string' || t.k === 'int' || t.k === 'conid' || t.k === 'qconid') {
      let q = p + 1;
      // a record update right after an atom: defaultOptions { field = value, ... }
      if (q < end && tok(q).k === '{' && match[q] > q && match[q] < end) {
        if (!parseRecordUpdate(q, match[q])) return -1;
        q = match[q] + 1;
      }
      return q;
    }
    if (sameWord(t)) {
      const sv = SAFE_VALUES.get(t.name || t.v);
      if (!sv || !importedFrom(t.name || t.v, t.qual || null, sv, imports, defined)) return -1;
      let q = p + 1;
      if (q < end && tok(q).k === '{' && match[q] > q && match[q] < end) {
        if (!parseRecordUpdate(q, match[q])) return -1;
        q = match[q] + 1;
      }
      return q;
    }
    if (t.k === 'quasiquote') {
      const { qual, name } = splitQuoter(t.quoter || '');
      const mods = SAFE_DECL_QUOTERS.get(name);
      if (!mods || !importedFrom(name, qual, mods, imports, defined)) return -1;
      return p + 1;
    }
    if (t.k === '(' && match[p] > p && match[p] < end) {
      if (!parseApp(p + 1, match[p], true)) return -1;
      return match[p] + 1;
    }
    if (t.k === '[' && match[p] > p && match[p] < end) {
      // a list of applications or atoms, separated by top-level commas
      let q = p + 1;
      const close = match[p];
      if (q === close) return close + 1;
      for (;;) {
        let e = q;
        while (e < close && tok(e).k !== ',') e = (['(', '[', '{'].includes(tok(e).k) && match[e] > e) ? match[e] + 1 : e + 1;
        if (e === q) return -1;
        if (!parseApp(q, e, true)) return -1;
        if (e >= close) break;
        q = e + 1;
      }
      return close + 1;
    }
    return -1;
  };

  const parseRecordUpdate = (open, close) => {
    let p = open + 1;
    if (p === close) return true;
    for (;;) {
      const f = tok(p);
      if (!f || f.k !== 'varid' || !OPTION_FIELDS.has(f.v)) return false;
      if (!tok(p + 1) || tok(p + 1).k !== 'rop' || tok(p + 1).v !== '=') return false;
      p += 2;
      let valueEnd = p;
      while (valueEnd < close && tok(valueEnd).k !== ',') valueEnd++;
      if (valueEnd === p) return false;
      for (let q = p; q < valueEnd; q++) {
        const t = tok(q);
        const ok = t.k === 'int' || t.k === 'string' || t.k === 'conid' || t.k === 'qconid' || t.k === '(' || t.k === ')'
          || (t.k === 'op' && t.v === '.') || (t.k === 'varid' && PURE_HELPERS.has(t.v));
        if (!ok) return false;
      }
      if (valueEnd >= close) return true;
      p = valueEnd + 1;
    }
  };

  // application: generator followed by values. `nested` allows a generator head inside parentheses or lists.
  const parseApp = (p, end, nested) => {
    const h = tok(p);
    if (!h || !sameWord(h)) {
      // a bare value inside a list (`[mkPersist sqlSettings, mkMigrate "m"]` elements are applications, but a quoter or name may stand alone)
      if (nested && p < end) { const n = parseValue(p, end); return n === end; }
      return false;
    }
    const name = h.name || h.v;
    const mods = GENERATORS.get(name);
    if (!mods && nested) return parseValue(p, end) === end;
    if (!mods || !importedFrom(name, h.qual || null, mods, imports, defined)) return false;
    generators.push(name);
    for (const m of mods) modules.add(m);
    let q = p + 1;
    while (q < end) {
      const n = parseValue(q, end);
      if (n < 0) return false;
      q = n;
    }
    return q === end;
  };

  // optional outer splice wrapper: $( ... )
  let s = a;
  let e = b;
  if (tok(a).k === 'op' && tok(a).v === '$' && tok(a + 1) && tok(a + 1).k === '(' && tok(a).e === tok(a + 1).s && match[a + 1] === b - 1) { s = a + 2; e = b - 1; }
  if (s >= e) return null;
  if (!parseApp(s, e, false)) return null;
  return { generators, modules: [...modules].sort() };
}

/** Classify one quasi-quote token as an inert string. @returns {{quoter:string, module:string}|null} */
export function classifyInertQuasiQuote(quoter, body, imports, defined) {
  if (!quoter) return null;
  const { qual, name } = splitQuoter(quoter);
  const q = INERT_QUOTERS.get(name);
  if (!q || !importedFrom(name, qual, q.modules, imports, defined)) return null;
  if (q.check && INTERPOLATION_MARK.test(body)) return null;
  return { quoter: name, modules: q.modules };
}
