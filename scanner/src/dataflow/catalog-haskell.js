// Haskell taint catalog, GENERATED from the model registry (language/haskell-models.js) so there is
// exactly one list of Haskell sources, sinks and sanitizers. Every entry matches the IMPORT-QUALIFIED
// callee the Haskell IR produces (`System.Process.callCommand`), never a bare name, so a user's own
// function with the same name resolves to its own module and cannot match.

import { HS_SOURCES, HS_SINKS, HS_SANITIZERS } from '../language/haskell-models.js';

const idOf = (kind, e, extra = '') => `hs-${kind}-${e.module}.${e.name}${extra}`.replace(/[^A-Za-z0-9.\-_]/g, '-').toLowerCase();

export const HASKELL_CATALOG = Object.freeze([
  ...HS_SOURCES.map((e) => ({
    kind: 'source', id: idOf('src', e), language: 'hs', framework: e.framework || 'haskell',
    match: { type: 'call', callee: `${e.module}.${e.name}` }, label: e.label, provenance: e.provenance,
  })),
  ...HS_SINKS.map((e) => ({
    kind: 'sink', id: idOf('sink', e, `.${e.cwe}.${e.argIndex}`), language: 'hs', framework: e.framework || 'haskell',
    match: { type: 'call', callee: `${e.module}.${e.name}` }, argIndex: e.argIndex,
    vuln: { name: e.vuln, severity: e.severity, cwe: e.cwe, remediation: e.remediation },
    hs: { family: e.family, shell: e.shell === true, argv: e.argv === true, package: e.package, htmlSkeleton: e.htmlSkeleton === true },
  })),
  // LINEAGE form of every source: a member read on the synthetic root `$hs` (see lineage/haskell-view.js, which
  // rewrites a CLONE of each Haskell function so a monadic source read becomes a seedable member read). The
  // taint engine never sees this form: the shared IR keeps the call form above.
  ...HS_SOURCES.map((e) => ({
    kind: 'source', id: idOf('lin-src', e), language: 'hs', framework: e.framework || 'haskell',
    match: { type: 'member', object: '$hs', prop: `${e.module}.${e.name}` }, label: e.label, provenance: e.provenance,
  })),
  // A text-typed parameter of an exported function (see language/haskell-ir.js `callerControlledParams`). The label says what
  // it is: the caller supplies the value and nothing in the module proves it trusted.
  // LINEAGE form of a record parameter of an exported function (see lineage/haskell-view.js)
  { kind: 'source', id: 'hs-lin-src-record-parameter', language: 'hs', framework: 'haskell', match: { type: 'member', object: '$hs', prop: 'hs:record-parameter' }, label: 'record parameter of an exported function (caller-supplied customer data)' },
  { kind: 'source', id: 'hs-src-caller-controlled-param', language: 'hs', framework: 'haskell', match: { type: 'annotation', name: 'hs:caller-controlled' }, label: 'text parameter of an exported function (caller-controlled)' },
  ...HS_SANITIZERS.map((e) => ({
    kind: 'sanitizer', id: idOf('san', e), language: 'hs',
    match: { type: 'call', callee: `${e.module}.${e.name}` }, effect: 'strip', appliesTo: e.appliesTo, note: e.note,
  })),
]);
