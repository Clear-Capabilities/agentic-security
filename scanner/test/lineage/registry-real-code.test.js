//
// Sub-project D, increment D5 — the exit-gate closure test.
//
// D2 (source-registry.js) and D3 (sink-registry.js) proved, exhaustively,
// that every CATALOG entry reclassifies correctly — but every one of those
// tests operates on CATALOG's own static entries directly, never on a call
// site extracted from actually-parsed source code. This file closes that
// specific, narrow gap: for every REACHABLE source/sink/privacy-sink
// category (DESIGN_REGISTRIES.md §9.2's corrected D5 exit criterion), and
// for AC-02's masked/raw distinction, it (1) writes a small JS/TS snippet,
// (2) parses it with the real Layer-1 IR (`parseJsFile`), (3) independently
// confirms — via a small, purpose-built structural comparison, NOT
// `dataflow/engine.js`'s real matcher, which this file never imports — that
// the chosen catalog entry's `match` field is consistent with what the
// parser actually produced, and (4) feeds the CATALOG ENTRY (not the parsed
// descriptor) into `reclassifySource`/`reclassifySink`/`reclassifyPrivacySink`
// to assert the expected category.
//
// This file does NOT re-prove the unreachable-category lists (D1/6a, D1/6b,
// already pinned and unchanged in source-registry.test.js / sink-registry.
// test.js) and does NOT re-derive coverageStatus/externality tables — that
// is D2/D3's job, already shipped. It proves exactly one thing: a real call
// site, extracted from real parsed code, structurally matches the catalog
// entry the registry then reclassifies.
//
// ─── Step 1 empirical findings (IR output shape, confirmed by running
// `parseJsFile` against real snippets before writing anything below —
// scanner/src/ir/parser-js.js's own header comment is correct on the shape
// but the following is the load-bearing detail a reader must not assume) ──
//
//   - `fn.calls[]` (a flat array, not the header's stated `Map`-of-anything
//     for this particular field — `fn.calls` IS documented as an array and
//     is one) only ever gets an entry for a call used as a bare STATEMENT
//     (`db.query(sql);`). A call used as the RHS of an assignment
//     (`const x = open(path);`) does NOT appear in `fn.calls[]` at all — it
//     only appears nested inside that assign CFG node's own `source`
//     exprDesc, as `{kind:'call', callee:{kind:'ident', name:'open'}, args}`.
//     Both source-side call entries proven below (storage-read, user-input)
//     are therefore extracted from `assign.source.callee`, never `fn.calls`.
//   - A bare member READ (`req.body`, not a call) never appears in
//     `fn.calls[]` either — it can only be observed where something
//     consumes it, which in every snippet below is an `assign` CFG node's
//     `source` field: `{kind:'member', object:{kind:'ident', name:'req'},
//     prop:'body'}`.
//   - A member WRITE (`el.innerHTML = payload;`) is an `assign` CFG node
//     whose `target` is a flat, already-dotted STRING (`'el.innerHTML'`),
//     not a nested exprDesc — this is `lhsPath`'s output, structurally
//     different from `source`'s nested shape on the same node.
//   - For a bare-statement call, `fn.calls[].callee` IS a flat string —
//     confirmed exactly as the module header states:
//     `db.query(sql)` -> `'db.query'`, `fetch(url)` -> `'fetch'`.
//     CORRECTED (Sub-project H, AC-07 closure — measured from a real test
//     failure): that flattening keeps only ONE level of receiver.
//     `anthropic.messages.create(x)` -> `'create'`, NOT
//     `'anthropic.messages.create'`. The real matcher never reads this
//     field (it walks the CFG call node's structured `callee` exprDesc via
//     `_receiverSegments`), so nothing in the engine is affected — but this
//     file's own structural stand-in was, and now flattens the structured
//     CFG callee itself. See `flatCalleeOfStatementCall` below.
//   - `fn.cfg.nodes` is a plain Object keyed by node id (`{n5: {...}, ...}`)
//     at runtime, NOT a `Map` as the header comment states — irrelevant to
//     what this file needs (it only ever needs the VALUES, found via
//     `Object.values`), but noted here because a future reader relying on
//     the header's `Map<nodeId, Node>` claim for iteration would be wrong.
//
// ─── A judgment call worth a reviewer's attention: `receiverTypeIn` ──────
//
// `dataflow/catalog.js`'s own `_receiverTypeAllowed` (read, not imported)
// clarified something this task's structural check would otherwise get
// wrong: `match.receiverTypeIn` is NOT a textual check on the receiver's
// SOURCE NAME (`db`, `pool`, `console`, ...) — it gates on a CHA-RESOLVED
// CLASS TYPE, a completely different signal computed by `engine.js`, which
// this file never imports. The real matcher treats an unresolved type as
// permissive (never suppresses a match). The textual receiver-name checks
// that DO exist (`match.receiver` / `match.receiverBase`, read via
// `_receiverAllowed`) are what this file's own `callMatches` reproduces
// narrowly, keyed on the exact same fields; `receiverTypeIn` is
// deliberately left unvalidated by this file's structural check — checking
// it here would fabricate a signal this isolated comparison cannot honestly
// compute. This was originally written when NONE of the 24 entries chosen
// below declared `match.receiver` / `match.receiverBase`, so `callMatches`
// reduced to a callee-name check for every one of them — the fields were
// wired up anyway so a future entry that DOES set them fails loudly here
// instead of passing by accident. That future entry has now arrived:
// `js-anthropic-messages-create` (the 25th proof, Sub-project H's AC-07
// closure) declares `receiver: '^messages$'`, and its proof genuinely
// exercises the `receiver` branch of `callSinkMatches` rather than reducing
// to a callee-name check.
//

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseJsFile } from '../../src/ir/parser-js.js';
import { CATALOG } from '../../src/dataflow/catalog.js';
import { PRIVACY_SINK_CATALOG } from '../../src/dataflow/privacy-catalog.js';
import { reclassifySource } from '../../src/lineage/source-registry.js';
import { reclassifySink, reclassifyPrivacySink } from '../../src/lineage/sink-registry.js';
import { recognizeTransformation } from '../../src/lineage/transform-catalog.js';
import { SOURCE_CATEGORIES, SINK_CATEGORIES } from '../../src/lineage/schema.js';

// ─────────────────────────────────────────────────────────────────────────
// Parsing helper. Every snippet is wrapped in one named function so the
// real IR always gives us exactly one `functions[]` entry to inspect.
// ─────────────────────────────────────────────────────────────────────────

function parseSnippet(body) {
  const ir = parseJsFile('scratch.js', `function subject() {\n${body}\n}`);
  const fn = ir.functions.find((f) => f.name === 'subject');
  assert.ok(fn, `parseJsFile produced no 'subject' function for snippet: ${body}`);
  return fn;
}

function firstAssignNode(fn) {
  const node = Object.values(fn.cfg.nodes).find((n) => n.kind === 'assign');
  assert.ok(node, 'snippet produced no assign CFG node');
  return node;
}

// ─────────────────────────────────────────────────────────────────────────
// MEASURED CORRECTION (Sub-project H, AC-07 closure — found by a real test
// failure, not predicted): `fn.calls[].callee` flattens only ONE level of a
// member chain. `db.query(sql)` -> `'db.query'` (as this file's header
// says), but `anthropic.messages.create(x)` -> `'create'` and
// `openai.chat.completions.create(x)` -> `'create'` — the receiver segments
// are GONE. The real matcher is unaffected: `matchSinkOrSanitizer` reads the
// CFG call node's STRUCTURED `callee` exprDesc and `_receiverSegments` walks
// the whole chain outward, which is why the real engine matches these entries
// correctly (independently verified against `matchSinkOrSanitizer` itself).
// Only THIS file's structural stand-in was reading the lossy field. Fixed by
// flattening the structured CFG callee here instead, which reproduces exactly
// what `_receiverSegments` sees. Every pre-existing proof in this file uses a
// bare or one-level callee, so this returns a byte-identical string for all
// of them.
// ─────────────────────────────────────────────────────────────────────────
function flatCalleeOfStatementCall(fn) {
  const node = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call' && n.callee);
  assert.ok(node, 'snippet produced no bare-statement call CFG node');
  const segs = [];
  let cur = node.callee;
  let depth = 0;
  while (cur && depth++ < 8) {
    if (cur.kind === 'ident') { segs.unshift(cur.name); break; }
    if (cur.kind === 'member') { if (typeof cur.prop === 'string') segs.unshift(cur.prop); cur = cur.object; continue; }
    break;
  }
  // A non-JS-parser flat string callee would arrive already dotted.
  if (typeof node.callee === 'string') return node.callee;
  assert.ok(segs.length, `could not flatten CFG callee ${JSON.stringify(node.callee)}`);
  return segs.join('.');
}

// ─────────────────────────────────────────────────────────────────────────
// Structural comparisons — small, self-contained, purpose-built. NOT
// `dataflow/catalog.js`'s real matchSource/matchSinkOrSanitizer/
// matchMemberWriteSink (never imported here, per the Global Constraints).
// Each function below mirrors ONLY the specific keying rule the real
// matcher uses for the match `type` it handles (confirmed by reading, not
// guessing, matchSource/matchSinkOrSanitizer/matchMemberWriteSink's own
// source — see the header note on `receiverTypeIn` above for the one place
// that reading corrected an assumption this file would otherwise have made).
// ─────────────────────────────────────────────────────────────────────────

// A member READ (`req.body`), e.g. matchSource's MEMBER_INDEX key
// `${object.name}.${prop}`.
function memberReadMatches(exprDesc, m) {
  return (
    exprDesc?.kind === 'member' &&
    exprDesc.object?.kind === 'ident' &&
    exprDesc.object.name === m.object &&
    exprDesc.prop === m.prop
  );
}

// A member WRITE (`el.innerHTML = x`), e.g. matchMemberWriteSink's
// `_any_.<prop>` keying — the object is IGNORED entirely when
// `m.object === '_any_'`, exactly mirroring the real function.
function memberWriteMatches(targetFlat, m) {
  if (typeof targetFlat !== 'string' || !targetFlat.includes('.')) return false;
  const prop = targetFlat.slice(targetFlat.lastIndexOf('.') + 1);
  if (prop !== m.prop) return false;
  if (m.object === '_any_') return true;
  const objectPath = targetFlat.slice(0, targetFlat.length - prop.length - 1);
  return objectPath === m.object;
}

// A CALL used as a bare statement (`db.query(sql);`) — extracted from
// `fn.calls[].callee`, already a flat string.
function callSinkMatches(flatCallee, m) {
  if (typeof flatCallee !== 'string') return false;
  const segs = flatCallee.split('.');
  const name = segs[segs.length - 1];
  if (name !== m.callee) return false;
  const receiverSegs = segs.slice(0, -1);
  // Mirrors `_receiverAllowed`'s textual `receiver`/`receiverBase` regex
  // fields — deliberately NOT `receiverTypeIn` (see the file header note).
  if (m.receiver && !receiverSegs.some((s) => new RegExp(m.receiver).test(s))) return false;
  if (m.receiverBase && !receiverSegs.some((s) => new RegExp(m.receiverBase).test(s))) return false;
  return true;
}

// A CALL used as an assignment RHS (`const x = open(path);`) — extracted
// from the assign node's own nested `source.callee` exprDesc, per Step 1's
// finding that this shape never reaches `fn.calls[]` at all. Both entries
// this file uses this for are bare-identifier callees, so only the `ident`
// case is handled (matching what real code needs here, not a general form).
function callSourceMatches(sourceExprDesc, m) {
  return (
    sourceExprDesc?.kind === 'call' &&
    sourceExprDesc.callee?.kind === 'ident' &&
    sourceExprDesc.callee.name === m.callee
  );
}

function findEntry(catalog, id) {
  const entry = catalog.find((e) => e.id === id);
  assert.ok(entry, `catalog entry '${id}' not found — has the catalog changed?`);
  return entry;
}

// ─────────────────────────────────────────────────────────────────────────
// Step 2 (re-derived, not trusted from the plan): source-registry.test.js's
// own 'unreachable source categories' test and sink-registry.test.js's own
// 'unreachable sink categories' test were read directly (not re-run here —
// re-proving the unreachable list is explicitly D2/D3's job, inherited
// unchanged) and confirm the reachable lists below are CURRENT, matching
// this task's own plan with NO drift:
//   14 reachable SOURCE_CATEGORIES: http-body, http-query, http-route,
//     http-header, http-cookie, http-upload, cli-argument, env-value,
//     storage-read, user-input, external-api-response, ai-model-output,
//     ai-tool-result, ai-retrieved-document.
//   10 reachable SINK_CATEGORIES: log, http-response, client-storage,
//     database, file, object-storage, queue, analytics, email,
//     external-api.
// ─────────────────────────────────────────────────────────────────────────

// One representative CATALOG entry per reachable source category, plus the
// snippet whose parsed shape structurally matches that entry's own `match`
// field. `extraction` records HOW the callee/member shape is read out of
// the real parsed IR (per Step 1's findings above): 'member-read' (an
// assign node's nested `source`), or 'call-source' (an assign node's
// nested `source.callee`, for the two entries whose only catalog
// representative is call-shaped and naturally flows into a variable).
//
// Four of the fourteen (http-upload, cli-argument, storage-read,
// user-input) have NO `language: 'js'`-tagged catalog entry at all — the
// catalog's only representatives for these categories are Python-tagged
// (`py-django-request-FILES`, `py-sys-argv`, `py-open-read`, `py-input`).
// This is a disclosed, deliberate judgment call (flagged again in this
// task's own report): `parseJsFile` is JS/TS-only, so proving these four
// categories via "real parsed code" necessarily means writing JS/TS SYNTAX
// that mirrors the chosen entry's `match` field's object/prop/callee
// strings verbatim, even though those identifiers are not real JS APIs —
// this is legitimate for what this task proves (that the IR's structural
// EXTRACTION genuinely corresponds to the entry's declared `match` shape),
// since `source-registry.js`'s reclassification is itself entirely
// language-agnostic (it reads `entry.provenance`/`entry.id`, never
// `entry.language`) and Sub-project D4's own precedent
// (`transform-catalog.js`, gap 8) already discloses catalog entries ahead
// of this engine's JS/TS-only parsing scope.
//
// task review MF-1: name the sharper limit precisely, don't understate it.
// The REAL matcher (`dataflow/catalog.js`'s `matchSource`) applies
// `_languageAllowed` before ever consulting `match` — for a file the real
// engine treats as JS (e.g. `scratch.js`), a `py-*`-tagged entry is
// discarded by that language gate regardless of how well its `match`
// shape corresponds to the parsed code. These four proofs therefore cover
// EXTRACTION-SHAPE CORRESPONDENCE ONLY ("the IR extracts exactly what this
// entry's `match` field declares") — not "real parsed JS/TS code would
// reach this catalog entry through the real engine's matcher", which it
// would not, for these four specifically. The other 20 proofs, all
// `language: 'js'`-tagged, carry no such gap.
const SOURCE_PROOFS = [
  { category: 'http-body', entryId: 'js-req-body', extraction: 'member-read', src: 'const x = req.body;' },
  { category: 'http-query', entryId: 'js-req-query', extraction: 'member-read', src: 'const x = req.query;' },
  { category: 'http-route', entryId: 'js-req-params', extraction: 'member-read', src: 'const x = req.params;' },
  { category: 'http-header', entryId: 'js-req-headers', extraction: 'member-read', src: 'const x = req.headers;' },
  { category: 'http-cookie', entryId: 'js-req-cookies', extraction: 'member-read', src: 'const x = req.cookies;' },
  { category: 'http-upload', entryId: 'py-django-request-FILES', extraction: 'member-read', src: 'const x = request.FILES;' },
  { category: 'cli-argument', entryId: 'py-sys-argv', extraction: 'member-read', src: 'const x = sys.argv;' },
  { category: 'env-value', entryId: 'js-process-env', extraction: 'member-read', src: 'const x = process.env;' },
  { category: 'storage-read', entryId: 'py-open-read', extraction: 'call-source', src: 'const x = open(path);' },
  { category: 'user-input', entryId: 'py-input', extraction: 'call-source', src: 'const x = input();' },
  { category: 'external-api-response', entryId: 'js-axios-data', extraction: 'member-read', src: 'const x = response.data;' },
  { category: 'ai-model-output', entryId: 'js-mcp-call-args', extraction: 'member-read', src: 'const x = params.arguments;' },
  { category: 'ai-tool-result', entryId: 'js-mcp-tool-result', extraction: 'member-read', src: 'const x = result.content;' },
  { category: 'ai-retrieved-document', entryId: 'js-mcp-resource-contents', extraction: 'member-read', src: 'const x = resource.contents;' },
];

test('D5/1: SOURCE_PROOFS covers exactly the 14 reachable source categories, no duplicates, no typos', () => {
  assert.equal(SOURCE_PROOFS.length, 14);
  const cats = new Set(SOURCE_PROOFS.map((p) => p.category));
  assert.equal(cats.size, 14, 'a category is duplicated');
  for (const c of cats) assert.ok(SOURCE_CATEGORIES.includes(c), `${c} is not a real SOURCE_CATEGORIES value`);
});

for (const proof of SOURCE_PROOFS) {
  test(`D5/2 source real-code proof: ${proof.category} (${proof.entryId})`, () => {
    const entry = findEntry(CATALOG, proof.entryId);
    assert.equal(entry.kind, 'source', `${proof.entryId} must be a source entry`);

    const fn = parseSnippet(proof.src);
    const assignNode = firstAssignNode(fn);

    if (proof.extraction === 'member-read') {
      assert.ok(
        memberReadMatches(assignNode.source, entry.match),
        `${proof.entryId}: parsed member read ${JSON.stringify(assignNode.source)} does not structurally match entry.match ${JSON.stringify(entry.match)}`,
      );
    } else if (proof.extraction === 'call-source') {
      assert.ok(
        callSourceMatches(assignNode.source, entry.match),
        `${proof.entryId}: parsed call ${JSON.stringify(assignNode.source)} does not structurally match entry.match ${JSON.stringify(entry.match)}`,
      );
    } else {
      assert.fail(`unknown extraction kind ${proof.extraction}`);
    }

    // The proof itself: feed the CATALOG ENTRY (not the parsed descriptor)
    // into the registry and confirm the expected reachable category.
    const decision = reclassifySource(entry);
    assert.equal(decision.category, proof.category);
    assert.equal(decision.kind, 'source');
  });
}

// One representative entry per reachable sink category. `catalogSide`
// distinguishes `CATALOG` (via `reclassifySink`) from
// `PRIVACY_SINK_CATALOG` (via `reclassifyPrivacySink`) — mirrors
// sink-registry.js's own two-function split (§2.1: the two catalogs key on
// different fields and are deliberately not merged). `extraction` is
// 'call-sink' (a bare-statement call, read from `fn.calls[].callee`) for
// every entry except `client-storage`, whose only reachable representative
// is a member WRITE (`el.innerHTML = payload;`), read from the assign
// node's flat `target` string.
const SINK_PROOFS = [
  { category: 'log', entryId: 'privacy-js-console-log', catalogSide: 'privacy', extraction: 'call-sink', src: 'console.log(x);' },
  { category: 'http-response', entryId: 'js-res-redirect', catalogSide: 'catalog', extraction: 'call-sink', src: 'res.redirect(url);' },
  { category: 'client-storage', entryId: 'js-innerHTML-assign', catalogSide: 'catalog', extraction: 'member-write', src: 'el.innerHTML = payload;' },
  { category: 'database', entryId: 'js-sql-query', catalogSide: 'catalog', extraction: 'call-sink', src: 'db.query(sql);' },
  { category: 'file', entryId: 'js-fs-readFile', catalogSide: 'catalog', extraction: 'call-sink', src: 'fs.readFile(path);' },
  { category: 'object-storage', entryId: 'privacy-js-s3-putObject', catalogSide: 'privacy', extraction: 'call-sink', src: 's3.putObject(params);' },
  { category: 'queue', entryId: 'privacy-js-queue-sendMessage', catalogSide: 'privacy', extraction: 'call-sink', src: 'queue.sendMessage(params);' },
  { category: 'analytics', entryId: 'privacy-js-analytics-track', catalogSide: 'privacy', extraction: 'call-sink', src: 'analytics.track(props);' },
  { category: 'email', entryId: 'privacy-js-sendMail', catalogSide: 'privacy', extraction: 'call-sink', src: 'sendMail(msg);' },
  { category: 'external-api', entryId: 'js-fetch', catalogSide: 'catalog', extraction: 'call-sink', src: 'fetch(url);' },
  // AC-07 closure (Sub-project H): the 11th reachable sink category, and the
  // first ai-* one. The call is written as a BARE STATEMENT deliberately —
  // an assign-form call (`const r = anthropic.messages.create(...)`) never
  // reaches `fn.calls[]` at all, per this file's own Step-1 finding.
  { category: 'ai-model-provider', entryId: 'js-anthropic-messages-create', catalogSide: 'catalog', extraction: 'call-sink', src: 'anthropic.messages.create(params);' },
];

test('D5/3: SINK_PROOFS covers exactly the 11 reachable sink categories, no duplicates, no typos', () => {
  assert.equal(SINK_PROOFS.length, 11);
  const cats = new Set(SINK_PROOFS.map((p) => p.category));
  assert.equal(cats.size, 11, 'a category is duplicated');
  for (const c of cats) assert.ok(SINK_CATEGORIES.includes(c), `${c} is not a real SINK_CATEGORIES value`);
});

for (const proof of SINK_PROOFS) {
  test(`D5/4 sink real-code proof: ${proof.category} (${proof.entryId})`, () => {
    const catalog = proof.catalogSide === 'privacy' ? PRIVACY_SINK_CATALOG : CATALOG;
    const entry = findEntry(catalog, proof.entryId);
    assert.equal(entry.kind, 'sink', `${proof.entryId} must be a sink entry`);

    const fn = parseSnippet(proof.src);

    if (proof.extraction === 'call-sink') {
      assert.equal(fn.calls.length, 1, `expected exactly one bare-statement call in: ${proof.src}`);
      // NOT `fn.calls[0].callee` — see flatCalleeOfStatementCall's own header
      // for the measured reason (that field truncates a >1-level chain).
      const flatCallee = flatCalleeOfStatementCall(fn);
      assert.ok(
        callSinkMatches(flatCallee, entry.match),
        `${proof.entryId}: parsed callee '${flatCallee}' does not structurally match entry.match ${JSON.stringify(entry.match)}`,
      );
    } else if (proof.extraction === 'member-write') {
      const assignNode = firstAssignNode(fn);
      assert.ok(
        memberWriteMatches(assignNode.target, entry.match),
        `${proof.entryId}: parsed write target '${assignNode.target}' does not structurally match entry.match ${JSON.stringify(entry.match)}`,
      );
    } else {
      assert.fail(`unknown extraction kind ${proof.extraction}`);
    }

    const decision = proof.catalogSide === 'privacy' ? reclassifyPrivacySink(entry) : reclassifySink(entry);
    assert.equal(decision.category, proof.category);
  });
}

// ─────────────────────────────────────────────────────────────────────────
// Step 5 — AC-02's masked/raw distinction, against REAL PARSED CODE (not
// the descriptor-literal form D4's own D4/1a-1d already used). Reuses the
// exact raw-log shape D4/1b established (`logger.info(...)`) for
// consistency with the existing, already-shipped proof.
// ─────────────────────────────────────────────────────────────────────────

test('D5/5a: AC-02 masked flow — maskCard(cardNumber), parsed for real, recognizes as a mask transform', () => {
  const fn = parseSnippet('maskCard(cardNumber);');
  assert.equal(fn.calls.length, 1);
  const flatCallee = fn.calls[0].callee;
  assert.equal(flatCallee, 'maskCard');
  // `fn.calls[].callee` is already the exact dotted-or-bare string shape
  // `recognizeTransformation`'s own `{type:'call', callee}` form accepts
  // directly (transform-catalog.js's own docs: "A dotted callee string ...
  // is accepted too and resolves identically") — no local re-splitting
  // needed for this descriptor form.
  const decision = recognizeTransformation({ type: 'call', callee: flatCallee });
  assert.ok(decision, 'maskCard must be recognized from real parsed code');
  assert.equal(decision.kind, 'mask');
});

test('D5/5b: AC-02 raw-log flow — logger.info(cardNumber), parsed for real, recognizes as NO transformation', () => {
  const fn = parseSnippet('logger.info(cardNumber);');
  assert.equal(fn.calls.length, 1);
  const flatCallee = fn.calls[0].callee;
  assert.equal(flatCallee, 'logger.info');
  assert.equal(recognizeTransformation({ type: 'call', callee: flatCallee }), null);
});

test('D5/5c: AC-02 raw-log flow, member-call descriptor form agrees (built from the same real parsed callee)', () => {
  const fn = parseSnippet('logger.info(cardNumber);');
  const flatCallee = fn.calls[0].callee;
  const dot = flatCallee.lastIndexOf('.');
  const object = flatCallee.slice(0, dot);
  const method = flatCallee.slice(dot + 1);
  assert.deepEqual(
    recognizeTransformation({ type: 'call', callee: flatCallee }),
    recognizeTransformation({ type: 'member-call', object, method }),
  );
});

test('D5/5d: AC-02 — the masked and raw call sites, both from real parsed code, are distinguishable', () => {
  const maskedFn = parseSnippet('maskCard(cardNumber);');
  const rawFn = parseSnippet('logger.info(cardNumber);');
  const masked = recognizeTransformation({ type: 'call', callee: maskedFn.calls[0].callee });
  const raw = recognizeTransformation({ type: 'call', callee: rawFn.calls[0].callee });
  assert.ok(masked !== null && raw === null);
});

// ─────────────────────────────────────────────────────────────────────────
// Step 6 — closing summary assertion. Derived from the same tables the
// per-category tests above iterate (not a separately hand-copied number),
// so a future refactor that silently drops a row from either table fails
// this count too, not just the missing individual test.
// ─────────────────────────────────────────────────────────────────────────

test('D5/6: exactly 25 distinct reachable categories (14 source + 11 sink) got a real-code proof in this file', () => {
  // 24 -> 25 (sink 10 -> 11): Sub-project H's AC-07 closure made
  // `ai-model-provider` the 11th reachable sink category.
  const sourceCats = new Set(SOURCE_PROOFS.map((p) => p.category));
  const sinkCats = new Set(SINK_PROOFS.map((p) => p.category));
  for (const c of sourceCats) assert.ok(!sinkCats.has(c), `${c} appears in both source and sink proofs`);
  assert.equal(sourceCats.size, 14);
  assert.equal(sinkCats.size, 11);
  assert.equal(sourceCats.size + sinkCats.size, 25);
});
