# Agentic Discovery Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an LLM-driven vulnerability *discovery* layer that proposes candidate findings the rule engine cannot encode (business logic, authorization, feature abuse, multi-step chains), then confirms every candidate against the existing deterministic taint engine before it is allowed to become a finding.

**Architecture:** A new `scanner/src/discovery/` subsystem of small, pure, dependency-injected modules composed by one orchestrator. The call graph partitions the codebase into disjoint focus areas; N (focus area × lens) hunter runs propose candidates; each candidate is routed back through `runDeepAnalysis` for structural confirmation; a majority-vote refutation panel drops the unsupported; a judge dedupes survivors against `last-scan.json` and triage feedback. Every LLM call arrives as an injected `llmInvoke` callback — exactly the convention `posture/adversary-agent.js` already uses — so the entire pipeline runs and is tested offline, degrading to a deterministic static path rather than failing.

**Tech Stack:** Node ≥ 24, ESM, `node:test` + `node:assert/strict`, existing `scanner/src/ir/callgraph.js`, `scanner/src/dataflow/index.js`, `scanner/src/posture/stable-id.js`.

## Global Constraints

- **ESM only.** Every file under `scanner/src/` uses `import`/`export`. No CommonJS in the scanner tree.
- **Node ≥ 24.** Tests use `node:test` and `node:assert/strict`, matching `scanner/test/coverage-report.test.js`.
- **No new runtime network dependencies.** No new npm packages at all in this plan. LLM access is only ever an injected callback or the pre-existing `AGENTIC_SECURITY_LLM_ENDPOINT` env var, and its absence must degrade gracefully, never throw.
- **No non-determinism in identity.** `Date.now()`, `Math.random()`, and wall-clock values must never feed an id, a digest, or a sort key. Timestamps may appear only in transcript/report metadata fields, never in identity.
- **Findings schema.** Anything this subsystem promotes to a real finding must carry `{ id, severity, file, line, vuln, cwe, description, remediation, parser, family }`. Use `parser: 'DISCOVERY'` and set `family` from the lens.
- **Never name any external tool** — competitor or otherwise — in source, comments, docs, commit messages, or command help text.
- **Rebuild after src changes.** `cd scanner && npm run build` before relying on `dist/agentic-security.mjs`. Unit tests run against `src/` and need no rebuild.
- **The pre-push gate is the price of pushing.** `npm test`, `npm run bench:cve-replay:check`, `npm run bench:self-scan:check` must all pass. Read the output; do not assume.
- **Discovery output is never gated on by CI by default.** Candidates are advisory until a human or the confirmation gate promotes them. Wire nothing in this plan into an exit-code gate.

---

### Task 1: Focus-area partitioner

Partition the codebase into disjoint focus areas so parallel hunters do not converge on the same code. The partition is computed from the real call graph — weakly-connected components over call edges — not from directory names.

**Files:**
- Create: `scanner/src/discovery/partition.js`
- Test: `scanner/test/discovery-partition.test.js`

**Interfaces:**
- Consumes: `buildCallGraph(perFileIR, fileContents)` from `scanner/src/ir/callgraph.js`, which returns an object with `functions` (a `Map<qid, fnRecord>`) and `edges` (an array of `{ caller, callee }` where both are qid strings). Each `fnRecord` has at least `{ qid, name, file }`.
- Produces:
  - `focusAreaId(files: string[]): string` — 12-hex-char deterministic id.
  - `partitionCallGraph(callGraph, opts?): FocusArea[]` where
    `FocusArea = { id: string, label: string, files: string[], functions: string[], size: number }`.
    `opts.maxAreas` (default 8) caps the count by merging the smallest areas into one `"misc"` area.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-partition.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { focusAreaId, partitionCallGraph } from '../src/discovery/partition.js';

function graph(fns, edges) {
  return { functions: new Map(fns.map(f => [f.qid, f])), edges };
}

test('focusAreaId is deterministic and order-independent', () => {
  assert.equal(focusAreaId(['b.js', 'a.js']), focusAreaId(['a.js', 'b.js']));
  assert.notEqual(focusAreaId(['a.js']), focusAreaId(['b.js']));
  assert.match(focusAreaId(['a.js']), /^[0-9a-f]{12}$/);
});

test('partitionCallGraph splits disconnected components into separate areas', () => {
  const cg = graph(
    [
      { qid: 'auth.js::login@1', name: 'login', file: 'auth.js' },
      { qid: 'auth.js::check@9', name: 'check', file: 'auth.js' },
      { qid: 'bill.js::charge@1', name: 'charge', file: 'bill.js' },
    ],
    [{ caller: 'auth.js::login@1', callee: 'auth.js::check@9' }],
  );
  const areas = partitionCallGraph(cg);
  assert.equal(areas.length, 2);
  const byFile = Object.fromEntries(areas.map(a => [a.files.join(','), a]));
  assert.ok(byFile['auth.js']);
  assert.equal(byFile['auth.js'].functions.length, 2);
  assert.equal(byFile['bill.js'].size, 1);
});

test('partitionCallGraph merges components that share a file', () => {
  // Two unconnected functions in one file still belong to one area:
  // a hunter reads whole files, so splitting a file across areas would
  // hand the same source to two hunters and reintroduce convergence.
  const cg = graph(
    [
      { qid: 'a.js::x@1', name: 'x', file: 'a.js' },
      { qid: 'a.js::y@5', name: 'y', file: 'a.js' },
    ],
    [],
  );
  const areas = partitionCallGraph(cg);
  assert.equal(areas.length, 1);
  assert.deepEqual(areas[0].files, ['a.js']);
});

test('partitionCallGraph caps area count and folds the remainder into misc', () => {
  const fns = [];
  for (let i = 0; i < 10; i++) fns.push({ qid: `f${i}.js::m@1`, name: 'm', file: `f${i}.js` });
  const areas = partitionCallGraph(graph(fns, []), { maxAreas: 3 });
  assert.equal(areas.length, 3);
  const misc = areas.find(a => a.label === 'misc');
  assert.ok(misc, 'expected a misc area');
  assert.ok(misc.files.length > 1);
  // Every input file appears in exactly one area.
  const all = areas.flatMap(a => a.files).sort();
  assert.equal(new Set(all).size, 10);
  assert.equal(all.length, 10);
});

test('partitionCallGraph returns [] for an empty or missing graph', () => {
  assert.deepEqual(partitionCallGraph(null), []);
  assert.deepEqual(partitionCallGraph({ functions: new Map(), edges: [] }), []);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-partition.test.js`
Expected: FAIL — `Cannot find module '../src/discovery/partition.js'`.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/partition.js
//
// Split the codebase into disjoint focus areas so parallel hunters cannot
// converge on the same code.
//
// WHY THE CALL GRAPH AND NOT DIRECTORIES: a directory split hands one
// subsystem to several hunters whenever a feature spans folders, and hands
// unrelated code to one hunter whenever a folder is a grab bag. Weakly-
// connected components over call edges group code that actually talks to
// itself, which is the unit a hunter can reason about end to end.
//
// FILES, NOT FUNCTIONS, ARE THE ATOM. A hunter reads whole files. If two
// components share a file they are merged, otherwise the same source lands in
// two hunters' context and the convergence this module exists to prevent
// comes straight back.
import * as crypto from 'node:crypto';

export function focusAreaId(files) {
  const canon = [...new Set(files || [])].sort().join('\n');
  return crypto.createHash('sha256').update(canon).digest('hex').slice(0, 12);
}

// Union-find over file paths.
function makeDSU() {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r);
    while (parent.get(x) !== r) { const n = parent.get(x); parent.set(x, r); x = n; }
    return r;
  };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb); };
  return { find, union };
}

function labelFor(files) {
  if (files.length === 1) return files[0];
  const parts = files[0].split('/');
  for (let i = parts.length - 1; i > 0; i--) {
    const prefix = parts.slice(0, i).join('/') + '/';
    if (files.every(f => f.startsWith(prefix))) return prefix;
  }
  return files[0] + ` (+${files.length - 1})`;
}

export function partitionCallGraph(callGraph, opts = {}) {
  const fns = callGraph?.functions;
  if (!fns || typeof fns.get !== 'function' || fns.size === 0) return [];
  const maxAreas = Number.isInteger(opts.maxAreas) && opts.maxAreas > 0 ? opts.maxAreas : 8;

  const dsu = makeDSU();
  for (const fn of fns.values()) if (fn?.file) dsu.find(fn.file);
  for (const e of callGraph.edges || []) {
    const a = fns.get(e?.caller)?.file;
    const b = fns.get(e?.callee)?.file;
    if (a && b) dsu.union(a, b);
  }

  const filesByRoot = new Map();
  for (const fn of fns.values()) {
    if (!fn?.file) continue;
    const root = dsu.find(fn.file);
    if (!filesByRoot.has(root)) filesByRoot.set(root, new Set());
    filesByRoot.get(root).add(fn.file);
  }

  const fnsByFile = new Map();
  for (const fn of fns.values()) {
    if (!fn?.file) continue;
    if (!fnsByFile.has(fn.file)) fnsByFile.set(fn.file, []);
    fnsByFile.get(fn.file).push(fn.qid);
  }

  const build = (files, label) => {
    const sorted = [...files].sort();
    const functions = sorted.flatMap(f => (fnsByFile.get(f) || [])).sort();
    return { id: focusAreaId(sorted), label: label ?? labelFor(sorted), files: sorted, functions, size: functions.length };
  };

  let areas = [...filesByRoot.values()].map(s => build(s));
  // Deterministic ranking: biggest first, ties broken by id so two runs on the
  // same graph produce the same order.
  areas.sort((a, b) => b.size - a.size || (a.id < b.id ? -1 : 1));

  if (areas.length > maxAreas) {
    const kept = areas.slice(0, maxAreas - 1);
    const tail = areas.slice(maxAreas - 1);
    kept.push(build(tail.flatMap(a => a.files), 'misc'));
    areas = kept;
  }
  return areas;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-partition.test.js`
Expected: PASS, 5/5.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/partition.js scanner/test/discovery-partition.test.js
git commit -m "feat(discovery): partition the call graph into disjoint hunter focus areas"
```

---

### Task 2: Lens catalog and hunter prompt builder

Seven fixed lenses give each hunter a distinct angle. Redundant hunters find redundant bugs; diverse lenses cover failure modes that a single prompt misses.

**Files:**
- Create: `scanner/src/discovery/lenses.js`
- Test: `scanner/test/discovery-lenses.test.js`

**Interfaces:**
- Consumes: `FocusArea` from Task 1.
- Produces:
  - `LENSES: ReadonlyArray<{ key, title, family, cwe, brief }>` — exactly seven entries with keys `injection`, `authz`, `crypto`, `business-logic`, `feature-abuse`, `chained`, `wildcard`.
  - `lensByKey(key): Lens | null`
  - `buildHunterPrompt(focusArea, lens, ctx): string` where `ctx = { fileContents: Record<string,string>, maxChars?: number }`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-lenses.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LENSES, lensByKey, buildHunterPrompt } from '../src/discovery/lenses.js';

test('there are seven distinct lenses, each with a family and a cwe', () => {
  assert.equal(LENSES.length, 7);
  assert.equal(new Set(LENSES.map(l => l.key)).size, 7);
  for (const l of LENSES) {
    assert.ok(l.family, `${l.key} needs a family`);
    assert.match(String(l.cwe), /^CWE-\d+$/);
    assert.ok(l.brief.length > 20);
  }
});

test('lensByKey resolves and rejects', () => {
  assert.equal(lensByKey('authz').key, 'authz');
  assert.equal(lensByKey('nope'), null);
  assert.equal(lensByKey(undefined), null);
});

test('buildHunterPrompt embeds the lens brief, the file list, and the source', () => {
  const area = { id: 'abc123abc123', label: 'auth/', files: ['auth.js'], functions: ['auth.js::login@1'], size: 1 };
  const p = buildHunterPrompt(area, lensByKey('authz'), { fileContents: { 'auth.js': 'function login(){}' } });
  assert.ok(p.includes('auth.js'));
  assert.ok(p.includes('function login(){}'));
  assert.ok(p.includes(lensByKey('authz').brief));
  // The output contract must be stated, or the hunter returns prose.
  assert.ok(p.includes('candidates'));
});

test('buildHunterPrompt truncates oversized source and says so', () => {
  const big = 'x'.repeat(5000);
  const area = { id: 'a', label: 'a', files: ['big.js'], functions: [], size: 0 };
  const p = buildHunterPrompt(area, lensByKey('injection'), { fileContents: { 'big.js': big }, maxChars: 100 });
  assert.ok(p.length < 2000);
  assert.ok(p.includes('truncated'), 'truncation must be disclosed in the prompt');
});

test('buildHunterPrompt omits files with no content rather than emitting undefined', () => {
  const area = { id: 'a', label: 'a', files: ['gone.js'], functions: [], size: 0 };
  const p = buildHunterPrompt(area, lensByKey('crypto'), { fileContents: {} });
  assert.ok(!p.includes('undefined'));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-lenses.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/lenses.js
//
// The seven hunting lenses. Each hunter run is one (focus area × lens) pair.
//
// WHY DIVERSE LENSES RATHER THAN N IDENTICAL HUNTERS: redundancy raises
// confidence in what was already found and adds nothing to coverage. A lens
// that is told to look only at authorization asks different questions of the
// same code than one told to look at crypto, so the union covers failure modes
// no single prompt reaches. `wildcard` exists because a fixed taxonomy is a
// ceiling, and the classes worth finding are the ones not on the list.
export const LENSES = Object.freeze([
  { key: 'injection', title: 'Injection', family: 'injection', cwe: 'CWE-74',
    brief: 'Untrusted input reaching an interpreter: SQL, shell, template, XPath, LDAP, or deserialization. Follow the value, not the function name.' },
  { key: 'authz', title: 'Authorization', family: 'access-control', cwe: 'CWE-285',
    brief: 'Missing, partial, or bypassable authorization: object references not scoped to the caller, tier checks applied on one path but not another, checks performed after the effect.' },
  { key: 'crypto', title: 'Cryptography', family: 'crypto', cwe: 'CWE-327',
    brief: 'Misuse rather than choice of primitive: reused nonces, unauthenticated ciphertext, comparisons that are not constant time, keys derived from guessable material.' },
  { key: 'business-logic', title: 'Business logic', family: 'business-logic', cwe: 'CWE-840',
    brief: 'The code does what it says and what it says is wrong: state machines that accept out-of-order transitions, quantities that may be negative, refunds that exceed charges, limits enforced client side.' },
  { key: 'feature-abuse', title: 'Feature abuse', family: 'abuse', cwe: 'CWE-799',
    brief: 'A working feature used as a weapon: unbounded fan-out, expensive endpoints with no cost to the caller, invitations or exports that leak across tenants.' },
  { key: 'chained', title: 'Chained', family: 'attack-chain', cwe: 'CWE-1173',
    brief: 'Two behaviours that are each acceptable alone and unacceptable together. State the chain as an ordered sequence of steps with the attacker capability required at each.' },
  { key: 'wildcard', title: 'Wildcard', family: 'other', cwe: 'CWE-noinfo',
    brief: 'Anything the other lenses do not cover. Prefer the surprising and specific over the generic; report nothing rather than something already obvious.' },
]);

export function lensByKey(key) {
  if (typeof key !== 'string') return null;
  return LENSES.find(l => l.key === key) || null;
}

const DEFAULT_MAX_CHARS = 60_000;

export function buildHunterPrompt(focusArea, lens, ctx = {}) {
  const maxChars = Number.isInteger(ctx.maxChars) && ctx.maxChars > 0 ? ctx.maxChars : DEFAULT_MAX_CHARS;
  const contents = ctx.fileContents || {};
  const files = (focusArea?.files || []).filter(f => typeof contents[f] === 'string');

  let budget = maxChars;
  const blocks = [];
  for (const f of files) {
    const src = contents[f];
    const slice = src.length > budget ? src.slice(0, Math.max(0, budget)) : src;
    const truncated = slice.length < src.length;
    blocks.push(`--- ${f}${truncated ? ' (truncated)' : ''} ---\n${slice}`);
    budget -= slice.length;
    if (budget <= 0) break;
  }
  const omitted = files.length - blocks.length;

  return [
    `You are hunting for security vulnerabilities in one area of a codebase.`,
    `Area: ${focusArea?.label ?? 'unknown'} (${files.length} files)`,
    ``,
    `Your lens is ${lens.title}. ${lens.brief}`,
    `Report ONLY through this lens. Another hunter covers the others.`,
    ``,
    `Rules:`,
    `- Report a candidate only if you can name the entry point an attacker controls and the effect they achieve.`,
    `- Do not report defence-in-depth gaps, style, or "could be hardened". Those are not candidates.`,
    `- Cite a real file and line from the source below. A candidate with no location is discarded.`,
    ``,
    `Return JSON: {"candidates":[{"title","file","line","rationale","entryPoint","sink"}]}`,
    `Return {"candidates":[]} if you find nothing. An empty result is a valid and useful answer.`,
    ``,
    omitted > 0 ? `NOTE: ${omitted} file(s) omitted, prompt budget exhausted (truncated context).\n` : ``,
    ...blocks,
  ].join('\n');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-lenses.test.js`
Expected: PASS, 5/5.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/lenses.js scanner/test/discovery-lenses.test.js
git commit -m "feat(discovery): seven-lens catalog and hunter prompt builder"
```

---

### Task 3: Hunter agent

One bounded LLM run per (focus area × lens), with a hash-chained transcript and a hard call/wall budget. Mirrors the injection and short-circuit convention in `scanner/src/posture/adversary-agent.js`.

**Files:**
- Create: `scanner/src/discovery/hunter.js`
- Test: `scanner/test/discovery-hunter.test.js`

**Interfaces:**
- Consumes: `buildHunterPrompt`, `lensByKey` (Task 2); `FocusArea` (Task 1).
- Produces:
  - `parseCandidates(raw, focusArea, lens): Candidate[]` where
    `Candidate = { id, focusAreaId, lens, title, file, line, family, cwe, rationale, entryPoint, sink }`.
    `id` is a 12-hex digest of `focusAreaId|lens|file|line|title` — deterministic, no clock.
  - `runHunter(focusArea, lens, ctx, opts?): Promise<HunterRun>` where
    `HunterRun = { focusAreaId, lens, candidates, transcript, degraded: boolean, reason: string|null }`.
    `opts.llmInvoke(prompt): Promise<string>`. With no `llmInvoke` and no `AGENTIC_SECURITY_LLM_ENDPOINT`, returns `degraded: true`, `candidates: []`, and a `reason` — it must never throw.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-hunter.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCandidates, runHunter } from '../src/discovery/hunter.js';
import { lensByKey } from '../src/discovery/lenses.js';

const AREA = { id: 'aaaaaaaaaaaa', label: 'auth/', files: ['auth.js'], functions: [], size: 1 };
const CTX = { fileContents: { 'auth.js': 'function login(u){ return db.query("select * from u where n=" + u); }' } };
const LENS = lensByKey('injection');

test('parseCandidates extracts a JSON block and stamps deterministic ids', () => {
  const raw = 'Here you go:\n{"candidates":[{"title":"SQLi in login","file":"auth.js","line":1,"rationale":"concat","entryPoint":"u","sink":"db.query"}]}';
  const a = parseCandidates(raw, AREA, LENS);
  const b = parseCandidates(raw, AREA, LENS);
  assert.equal(a.length, 1);
  assert.equal(a[0].family, 'injection');
  assert.equal(a[0].cwe, 'CWE-74');
  assert.equal(a[0].focusAreaId, AREA.id);
  assert.match(a[0].id, /^[0-9a-f]{12}$/);
  assert.equal(a[0].id, b[0].id, 'ids must be stable across parses');
});

test('parseCandidates drops entries with no file or no line', () => {
  const raw = '{"candidates":[{"title":"vague","rationale":"x"},{"title":"ok","file":"auth.js","line":1}]}';
  const out = parseCandidates(raw, AREA, LENS);
  assert.equal(out.length, 1);
  assert.equal(out[0].title, 'ok');
});

test('parseCandidates returns [] on unparseable output instead of throwing', () => {
  assert.deepEqual(parseCandidates('I could not find anything.', AREA, LENS), []);
  assert.deepEqual(parseCandidates('{"candidates": not-json', AREA, LENS), []);
  assert.deepEqual(parseCandidates(null, AREA, LENS), []);
});

test('runHunter degrades with no llmInvoke and no endpoint, and does not throw', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const r = await runHunter(AREA, LENS, CTX, {});
    assert.equal(r.degraded, true);
    assert.deepEqual(r.candidates, []);
    assert.match(r.reason, /no llmInvoke/);
  } finally {
    if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  }
});

test('runHunter returns candidates and a hash-chained transcript', async () => {
  const llmInvoke = async () => '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat"}]}';
  const r = await runHunter(AREA, LENS, CTX, { llmInvoke });
  assert.equal(r.degraded, false);
  assert.equal(r.candidates.length, 1);
  assert.ok(r.transcript.length >= 2);
  for (let i = 1; i < r.transcript.length; i++) {
    assert.equal(r.transcript[i].prev, r.transcript[i - 1].hash);
  }
});

test('runHunter survives an llmInvoke that throws', async () => {
  const llmInvoke = async () => { throw new Error('429 rate limited'); };
  const r = await runHunter(AREA, LENS, CTX, { llmInvoke });
  assert.equal(r.degraded, true);
  assert.deepEqual(r.candidates, []);
  assert.match(r.reason, /429/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-hunter.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/hunter.js
//
// One bounded hunter run = one focus area seen through one lens.
//
// A hunter PROPOSES. Nothing here is a finding: every candidate must survive
// `confirm.js` and `disprove.js` first. That separation is the whole design —
// the model is allowed to be imaginative precisely because something
// deterministic checks it afterwards.
//
// FAILURE IS ALWAYS DEGRADATION, NEVER AN EXCEPTION. A missing endpoint, a
// rate limit, or unparseable output yields `degraded:true` with a reason. A
// discovery pass that cannot run must leave the rest of the scan intact.
import * as crypto from 'node:crypto';
import { buildHunterPrompt } from './lenses.js';

function appendEntry(transcript, entry) {
  const prev = transcript.length ? transcript[transcript.length - 1].hash : null;
  const body = JSON.stringify({ ...entry, prev });
  const hash = crypto.createHash('sha256').update(body).digest('hex');
  transcript.push({ ...entry, prev, hash });
  return transcript;
}

function extractJson(raw) {
  if (typeof raw !== 'string') return null;
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  try { return JSON.parse(raw.slice(start, end + 1)); } catch { return null; }
}

function candidateId(focusAreaId, lensKey, file, line, title) {
  return crypto.createHash('sha256')
    .update(`${focusAreaId}|${lensKey}|${file}|${line}|${title}`)
    .digest('hex').slice(0, 12);
}

export function parseCandidates(raw, focusArea, lens) {
  const parsed = extractJson(raw);
  const list = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  const out = [];
  for (const c of list) {
    const file = typeof c?.file === 'string' ? c.file : null;
    const line = Number.isInteger(c?.line) ? c.line : Number.parseInt(c?.line, 10);
    if (!file || !Number.isInteger(line)) continue;      // no location, no candidate
    const title = typeof c?.title === 'string' && c.title ? c.title : `${lens.title} candidate`;
    out.push({
      id: candidateId(focusArea.id, lens.key, file, line, title),
      focusAreaId: focusArea.id,
      lens: lens.key,
      title,
      file,
      line,
      family: lens.family,
      cwe: lens.cwe,
      rationale: typeof c?.rationale === 'string' ? c.rationale : '',
      entryPoint: typeof c?.entryPoint === 'string' ? c.entryPoint : '',
      sink: typeof c?.sink === 'string' ? c.sink : '',
    });
  }
  return out;
}

async function defaultLlmInvoke(prompt) {
  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

export async function runHunter(focusArea, lens, ctx = {}, opts = {}) {
  const transcript = [];
  const base = { focusAreaId: focusArea.id, lens: lens.key, transcript };
  const llmInvoke = opts.llmInvoke
    || (process.env.AGENTIC_SECURITY_LLM_ENDPOINT ? defaultLlmInvoke : null);

  if (typeof llmInvoke !== 'function') {
    const reason = 'no llmInvoke supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set';
    appendEntry(transcript, { phase: 'init', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  const prompt = buildHunterPrompt(focusArea, lens, ctx);
  appendEntry(transcript, { phase: 'prompt', promptChars: prompt.length, files: focusArea.files.length });

  let raw;
  try {
    raw = await llmInvoke(prompt);
  } catch (err) {
    const reason = `hunter llm call failed: ${err?.message || String(err)}`;
    appendEntry(transcript, { phase: 'error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  const candidates = parseCandidates(raw, focusArea, lens);
  appendEntry(transcript, { phase: 'result', candidateCount: candidates.length });
  return { ...base, candidates, degraded: false, reason: null };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-hunter.test.js`
Expected: PASS, 6/6.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/hunter.js scanner/test/discovery-hunter.test.js
git commit -m "feat(discovery): bounded hunter agent with hash-chained transcript"
```

---

### Task 4: Deterministic confirmation gate

**This task is the differentiator.** Every candidate is routed back through the existing taint engine and sink catalog. A candidate the deterministic layer can corroborate is worth far more than one only a model believes.

**Files:**
- Create: `scanner/src/discovery/confirm.js`
- Test: `scanner/test/discovery-confirm.test.js`

**Interfaces:**
- Consumes: `Candidate` (Task 3). Real analysis arrives injected as `opts.taintProbe` so the module is testable without building an IR; the orchestrator (Task 7) supplies the real one built on `runDeepAnalysis(perFileIR, callGraph, opts)` from `scanner/src/dataflow/index.js`.
- Produces:
  - `CONFIRMATION_TIERS: readonly ['taint-confirmed','sink-adjacent','unconfirmed']`
  - `confirmCandidate(candidate, opts?): Promise<Candidate & { confirmation: { tier, evidence, probedBy } }>`
  - `confirmAll(candidates, opts?): Promise<Array<...>>`
  - A `taintProbe` has signature `(candidate) => Promise<{ tier, evidence } | null>`; a `null` or a throw means "probe said nothing", which lowers to `unconfirmed` and must never be reported as a refutation.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-confirm.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONFIRMATION_TIERS, confirmCandidate, confirmAll } from '../src/discovery/confirm.js';

const C = { id: 'c1', file: 'auth.js', line: 1, family: 'injection', title: 't' };

test('tiers are ordered strongest-first and frozen', () => {
  assert.deepEqual([...CONFIRMATION_TIERS], ['taint-confirmed', 'sink-adjacent', 'unconfirmed']);
  assert.ok(Object.isFrozen(CONFIRMATION_TIERS));
});

test('a probe that finds a taint path yields taint-confirmed with its evidence', async () => {
  const taintProbe = async () => ({ tier: 'taint-confirmed', evidence: { source: 'req.body.n', sink: 'db.query' } });
  const out = await confirmCandidate(C, { taintProbe });
  assert.equal(out.confirmation.tier, 'taint-confirmed');
  assert.equal(out.confirmation.evidence.sink, 'db.query');
  assert.equal(out.confirmation.probedBy, 'taintProbe');
  assert.equal(out.id, 'c1', 'the candidate must pass through unmodified');
});

test('a probe returning null lowers to unconfirmed, not refuted', async () => {
  const out = await confirmCandidate(C, { taintProbe: async () => null });
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.equal(out.confirmation.evidence, null);
});

test('a probe that throws lowers to unconfirmed and records why', async () => {
  const out = await confirmCandidate(C, { taintProbe: async () => { throw new Error('IR build failed'); } });
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.match(out.confirmation.reason, /IR build failed/);
});

test('no probe at all is unconfirmed, never confirmed by default', async () => {
  const out = await confirmCandidate(C, {});
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.equal(out.confirmation.probedBy, null);
});

test('an unknown tier from a probe is rejected rather than trusted', async () => {
  const out = await confirmCandidate(C, { taintProbe: async () => ({ tier: 'definitely-real', evidence: {} }) });
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.match(out.confirmation.reason, /unknown tier/);
});

test('confirmAll preserves input order and confirms each independently', async () => {
  const probe = async (c) => (c.line === 2 ? { tier: 'sink-adjacent', evidence: { token: 'eval' } } : null);
  const out = await confirmAll([{ ...C, line: 1 }, { ...C, id: 'c2', line: 2 }], { taintProbe: probe });
  assert.deepEqual(out.map(o => o.confirmation.tier), ['unconfirmed', 'sink-adjacent']);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-confirm.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/confirm.js
//
// Route every model-proposed candidate back through the deterministic layer.
//
// WHY THIS EXISTS. A hunter's output is a hypothesis. The engine underneath it
// can already decide, for a given file and line, whether tainted data reaches a
// modelled sink there. Asking it turns "the model thinks so" into "the model
// thinks so AND the taint engine agrees", which is a materially stronger claim
// than either layer makes alone.
//
// THE ASYMMETRY IS DELIBERATE. Confirmation raises standing; the absence of
// confirmation NEVER lowers it below `unconfirmed` and is never recorded as a
// refutation. The taint engine models a subset of the program — an
// unconfirmed candidate may be a real bug in a construct the engine does not
// model, and calling that a false positive would launder a coverage gap into a
// verdict. Refutation is `disprove.js`'s job, and it must be argued, not
// inferred from silence.
export const CONFIRMATION_TIERS = Object.freeze(['taint-confirmed', 'sink-adjacent', 'unconfirmed']);

function unconfirmed(probedBy, reason) {
  return { tier: 'unconfirmed', evidence: null, probedBy, reason: reason || null };
}

export async function confirmCandidate(candidate, opts = {}) {
  const probe = typeof opts.taintProbe === 'function' ? opts.taintProbe : null;
  if (!probe) return { ...candidate, confirmation: unconfirmed(null, 'no taintProbe supplied') };

  let res;
  try {
    res = await probe(candidate);
  } catch (err) {
    return { ...candidate, confirmation: unconfirmed('taintProbe', `probe failed: ${err?.message || String(err)}`) };
  }
  if (!res) return { ...candidate, confirmation: unconfirmed('taintProbe', null) };
  if (!CONFIRMATION_TIERS.includes(res.tier)) {
    return { ...candidate, confirmation: unconfirmed('taintProbe', `unknown tier: ${res.tier}`) };
  }
  return {
    ...candidate,
    confirmation: { tier: res.tier, evidence: res.evidence ?? null, probedBy: 'taintProbe', reason: null },
  };
}

export async function confirmAll(candidates, opts = {}) {
  const out = [];
  for (const c of candidates || []) out.push(await confirmCandidate(c, opts));
  return out;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-confirm.test.js`
Expected: PASS, 7/7.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/confirm.js scanner/test/discovery-confirm.test.js
git commit -m "feat(discovery): deterministic confirmation gate over hunter candidates"
```

---

### Task 5: Adversarial refutation panel

Each surviving candidate faces N independent voters prompted to *refute* it. A candidate refuted by a majority is dropped.

**Files:**
- Create: `scanner/src/discovery/disprove.js`
- Test: `scanner/test/discovery-disprove.test.js`

**Interfaces:**
- Consumes: confirmed candidates from Task 4.
- Produces:
  - `REFUTE_ANGLES: readonly ['reachability','preconditions','sanitization']`
  - `buildRefutePrompt(candidate, angle): string`
  - `disproveCandidate(candidate, opts?): Promise<Candidate & { refutation: { votes, refuteCount, voterCount, refuted, undecided } }>`
    `opts.llmInvoke(prompt): Promise<string>`; a voter returns `{"refuted":bool,"reason":string}`.
  - `disprovePanel(candidates, opts?): Promise<{ survivors, refuted }>`
  - Voting rule: `refuted` is true only when `refuteCount * 2 > voterCount`. A voter that errors or returns unparseable output is **not** counted in `voterCount` (it did not vote); if no voter votes, `undecided: true` and the candidate **survives**.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-disprove.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { REFUTE_ANGLES, buildRefutePrompt, disproveCandidate, disprovePanel } from '../src/discovery/disprove.js';

const C = { id: 'c1', file: 'a.js', line: 3, title: 'SQLi in login', rationale: 'concat', confirmation: { tier: 'unconfirmed' } };

test('there are three refutation angles and each prompt names its own', () => {
  assert.equal(REFUTE_ANGLES.length, 3);
  for (const a of REFUTE_ANGLES) {
    const p = buildRefutePrompt(C, a);
    assert.ok(p.includes(a));
    assert.ok(p.includes('SQLi in login'));
    assert.ok(/refute/i.test(p), 'the voter must be told to refute, not to assess');
  }
});

test('a majority of refute votes drops the candidate', async () => {
  const llmInvoke = async () => '{"refuted":true,"reason":"unreachable"}';
  const out = await disproveCandidate(C, { llmInvoke });
  assert.equal(out.refutation.voterCount, 3);
  assert.equal(out.refutation.refuteCount, 3);
  assert.equal(out.refutation.refuted, true);
});

test('a tie is not a majority and the candidate survives', async () => {
  let n = 0;
  const llmInvoke = async () => (++n <= 2 ? '{"refuted":true,"reason":"x"}' : '{"refuted":false,"reason":"y"}');
  const out = await disproveCandidate(C, { llmInvoke, angles: ['reachability', 'preconditions', 'sanitization', 'reachability'] });
  assert.equal(out.refutation.refuteCount, 2);
  assert.equal(out.refutation.voterCount, 4);
  assert.equal(out.refutation.refuted, false, '2 of 4 is not a majority');
});

test('voters that error are excluded from the denominator, not counted as agreement', async () => {
  let n = 0;
  const llmInvoke = async () => {
    if (++n === 1) return '{"refuted":true,"reason":"x"}';
    throw new Error('timeout');
  };
  const out = await disproveCandidate(C, { llmInvoke });
  assert.equal(out.refutation.voterCount, 1);
  assert.equal(out.refutation.refuteCount, 1);
  assert.equal(out.refutation.refuted, true);
});

test('when no voter votes the panel is undecided and the candidate survives', async () => {
  const llmInvoke = async () => { throw new Error('down'); };
  const out = await disproveCandidate(C, { llmInvoke });
  assert.equal(out.refutation.voterCount, 0);
  assert.equal(out.refutation.undecided, true);
  assert.equal(out.refutation.refuted, false, 'silence must never refute');
});

test('with no llmInvoke the panel is undecided and does not throw', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const out = await disproveCandidate(C, {});
    assert.equal(out.refutation.undecided, true);
    assert.equal(out.refutation.refuted, false);
  } finally {
    if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  }
});

test('disprovePanel splits survivors from refuted', async () => {
  const llmInvoke = async (p) => (p.includes('doomed') ? '{"refuted":true}' : '{"refuted":false}');
  const r = await disprovePanel([C, { ...C, id: 'c2', title: 'doomed' }], { llmInvoke });
  assert.deepEqual(r.survivors.map(s => s.id), ['c1']);
  assert.deepEqual(r.refuted.map(s => s.id), ['c2']);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-disprove.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/disprove.js
//
// Adversarial refutation. Each voter is told to REFUTE the candidate, not to
// assess it: a model asked "is this real?" agrees with the premise far more
// often than one asked "show me why this cannot happen", and the second
// question is the one that kills plausible-but-wrong findings.
//
// THREE ANGLES, NOT THREE COPIES. A candidate can fail in more than one way,
// and three identical voters mostly measure sampling noise. Reachability,
// attacker preconditions, and sanitization are the three ways these candidates
// actually die.
//
// SILENCE NEVER REFUTES. A voter that errors or returns unparseable output did
// not vote, and is excluded from the denominator rather than counted as
// agreement. If nobody votes the panel is `undecided` and the candidate
// SURVIVES — an outage must not quietly delete findings.
const DEFAULT_ANGLES = ['reachability', 'preconditions', 'sanitization'];
export const REFUTE_ANGLES = Object.freeze([...DEFAULT_ANGLES]);

const ANGLE_BRIEF = {
  reachability: 'Can attacker-controlled data actually reach this line at runtime? Name the caller chain or show there is none.',
  preconditions: 'What must the attacker already have — a session, a role, a tenant, a race window? If the prerequisites exceed the impact, it is refuted.',
  sanitization: 'Is the value validated, escaped, parameterised, or type-constrained anywhere on the path? A framework default counts.',
};

export function buildRefutePrompt(candidate, angle) {
  return [
    `Your job is to REFUTE the security finding below. Assume it is wrong and look for the reason.`,
    `Refute it on this angle only: ${angle}. ${ANGLE_BRIEF[angle] || ''}`,
    ``,
    `Finding: ${candidate.title}`,
    `Location: ${candidate.file}:${candidate.line}`,
    `Claimed reason: ${candidate.rationale || '(none given)'}`,
    `Deterministic confirmation: ${candidate.confirmation?.tier || 'unknown'}`,
    ``,
    `If you cannot refute it on this angle, say so honestly.`,
    `Return JSON: {"refuted":true|false,"reason":"..."}`,
  ].join('\n');
}

function parseVote(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.indexOf('{'), e = raw.lastIndexOf('}');
  if (s < 0 || e <= s) return null;
  let p;
  try { p = JSON.parse(raw.slice(s, e + 1)); } catch { return null; }
  if (typeof p?.refuted !== 'boolean') return null;
  return { refuted: p.refuted, reason: typeof p.reason === 'string' ? p.reason : '' };
}

async function defaultLlmInvoke(prompt) {
  const res = await fetch(process.env.AGENTIC_SECURITY_LLM_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

export async function disproveCandidate(candidate, opts = {}) {
  const angles = Array.isArray(opts.angles) && opts.angles.length ? opts.angles : DEFAULT_ANGLES;
  const llmInvoke = opts.llmInvoke
    || (process.env.AGENTIC_SECURITY_LLM_ENDPOINT ? defaultLlmInvoke : null);

  const votes = [];
  if (typeof llmInvoke === 'function') {
    for (const angle of angles) {
      let vote = null;
      try { vote = parseVote(await llmInvoke(buildRefutePrompt(candidate, angle))); } catch { vote = null; }
      if (vote) votes.push({ angle, ...vote });
    }
  }

  const voterCount = votes.length;
  const refuteCount = votes.filter(v => v.refuted).length;
  const undecided = voterCount === 0;
  const refuted = !undecided && refuteCount * 2 > voterCount;
  return { ...candidate, refutation: { votes, voterCount, refuteCount, refuted, undecided } };
}

export async function disprovePanel(candidates, opts = {}) {
  const survivors = [], refuted = [];
  for (const c of candidates || []) {
    const judged = await disproveCandidate(c, opts);
    (judged.refutation.refuted ? refuted : survivors).push(judged);
  }
  return { survivors, refuted };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-disprove.test.js`
Expected: PASS, 7/7.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/disprove.js scanner/test/discovery-disprove.test.js
git commit -m "feat(discovery): three-angle adversarial refutation panel with majority vote"
```

---

### Task 6: Judge — dedupe against prior scan and triage feedback

Survivors are compared against `last-scan.json` and `triage-feedback.json`. Anything the rule engine already reports is a duplicate; anything a human already marked `fp` is suppressed.

**Files:**
- Create: `scanner/src/discovery/judge.js`
- Test: `scanner/test/discovery-judge.test.js`

**Interfaces:**
- Consumes: `computeStableId(finding)` from `scanner/src/posture/stable-id.js`; survivors from Task 5.
- Produces:
  - `toFindingShape(candidate): Finding` — full schema: `{ id, severity, file, line, vuln, cwe, description, remediation, parser: 'DISCOVERY', family }`, plus `stableId`, `discovery: { lens, focusAreaId, confirmation, refutation }`.
  - `judgeCandidates(candidates, priorScan, triageFeedback): { fresh, duplicates, suppressed }` — every input lands in exactly one bucket.
  - Duplicate rule: same `file` **and** `line` as an existing finding of the same `family`, or an identical `stableId`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-judge.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toFindingShape, judgeCandidates } from '../src/discovery/judge.js';

const cand = (over = {}) => ({
  id: 'c1', focusAreaId: 'fa1', lens: 'injection', title: 'SQLi in login',
  file: 'auth.js', line: 12, family: 'injection', cwe: 'CWE-74',
  rationale: 'string concat into a query', entryPoint: 'req.body.n', sink: 'db.query',
  confirmation: { tier: 'taint-confirmed', evidence: {} },
  refutation: { refuted: false, voterCount: 3, refuteCount: 0, undecided: false, votes: [] },
  ...over,
});

test('toFindingShape emits every required schema field', () => {
  const f = toFindingShape(cand());
  for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) {
    assert.ok(f[k] !== undefined && f[k] !== null && f[k] !== '', `missing ${k}`);
  }
  assert.equal(f.parser, 'DISCOVERY');
  assert.equal(f.family, 'injection');
  assert.ok(f.stableId);
  assert.equal(f.discovery.lens, 'injection');
});

test('a taint-confirmed candidate outranks an unconfirmed one in severity', () => {
  const hi = toFindingShape(cand());
  const lo = toFindingShape(cand({ confirmation: { tier: 'unconfirmed', evidence: null } }));
  assert.equal(hi.severity, 'high');
  assert.equal(lo.severity, 'low');
});

test('judgeCandidates marks same-file/line/family as a duplicate of the prior scan', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'injection', stableId: 'x' }] };
  const r = judgeCandidates([cand()], prior, null);
  assert.equal(r.fresh.length, 0);
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.duplicates[0].duplicateOf, 'x');
});

test('a different family at the same line is fresh, not a duplicate', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'crypto', stableId: 'x' }] };
  const r = judgeCandidates([cand()], prior, null);
  assert.equal(r.fresh.length, 1);
});

test('a stableId a human marked fp is suppressed', () => {
  const f = toFindingShape(cand());
  const r = judgeCandidates([cand()], null, { [f.stableId]: 'fp' });
  assert.equal(r.suppressed.length, 1);
  assert.equal(r.fresh.length, 0);
});

test('a stableId marked tp is still fresh — a prior true positive is not a duplicate', () => {
  const f = toFindingShape(cand());
  const r = judgeCandidates([cand()], null, { [f.stableId]: 'tp' });
  assert.equal(r.fresh.length, 1);
});

test('stableId collides across lines of the same lens and file — pinned deliberately', () => {
  // computeStableId hashes ruleId + snippet + path shape + basename, NOT the
  // line, so it survives code moving. Two candidates of one lens in one file
  // therefore share an id. This is pinned so a future change to stable-id.js
  // that alters the behaviour shows up here as a decision, not a surprise.
  const a = toFindingShape(cand({ line: 12 }));
  const b = toFindingShape(cand({ id: 'c2', line: 99 }));
  assert.equal(a.stableId, b.stableId);
  assert.equal(a.ruleId, 'discovery:injection');
});

test('file+line+family is the primary duplicate key, so a colliding id at a new line is fresh', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'injection', stableId: null }] };
  const r = judgeCandidates([cand({ id: 'c2', line: 99 })], prior, null);
  assert.equal(r.fresh.length, 1);
});

test('every candidate lands in exactly one bucket', () => {
  const prior = { findings: [{ file: 'auth.js', line: 12, family: 'injection', stableId: 'x' }] };
  const cands = [cand(), cand({ id: 'c2', line: 99 }), cand({ id: 'c3', line: 50 })];
  const r = judgeCandidates(cands, prior, null);
  assert.equal(r.fresh.length + r.duplicates.length + r.suppressed.length, 3);
});

test('missing prior scan and feedback are tolerated', () => {
  const r = judgeCandidates([cand()], undefined, undefined);
  assert.equal(r.fresh.length, 1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-judge.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/judge.js
//
// Turn surviving candidates into findings, then decide which are actually new.
//
// SEVERITY IS DRIVEN BY EVIDENCE, NOT BY THE MODEL'S ADJECTIVES. A hunter has
// no calibrated view of impact and will call everything critical. What we can
// defend is how well-evidenced the candidate is, so the confirmation tier sets
// the ceiling: taint-confirmed → high, sink-adjacent → medium, unconfirmed →
// low. A human or the existing triage path can raise it; the discovery layer
// never claims critical on its own.
//
// A PRIOR TRUE POSITIVE IS NOT A DUPLICATE. Triage feedback suppresses only
// `fp` verdicts. A `tp` verdict means the finding was real, and re-reporting it
// while it is still in the code is correct behaviour.
//
// STABLE IDS ARE LOCATION-FUZZY BY DESIGN, AND THAT MATTERS HERE. `stable-id.js`
// hashes ruleId, snippet, path shape, and BASENAME — deliberately not the line,
// so an id survives code moving down a file. The consequence for this layer:
// two different candidates of the same lens in the same file collide on one
// stableId. That is why file+line+family is the PRIMARY duplicate key and the
// stableId check is only a secondary net. It also means an `fp` verdict
// suppresses the whole (lens, file) pair rather than one line — the same
// breadth the rest of the engine already has, kept rather than silently
// diverged from. `ruleId` is set explicitly so ids partition by lens rather
// than falling back to the CWE.
import { computeStableId } from '../posture/stable-id.js';

const SEVERITY_BY_TIER = { 'taint-confirmed': 'high', 'sink-adjacent': 'medium', 'unconfirmed': 'low' };

export function toFindingShape(candidate) {
  const tier = candidate?.confirmation?.tier || 'unconfirmed';
  const base = {
    id: `discovery-${candidate.lens}-${candidate.id}`,
    severity: SEVERITY_BY_TIER[tier] || 'low',
    file: candidate.file,
    line: candidate.line,
    vuln: candidate.title,
    cwe: candidate.cwe || 'CWE-noinfo',
    description: candidate.rationale
      ? `${candidate.rationale} (entry point: ${candidate.entryPoint || 'unstated'}; sink: ${candidate.sink || 'unstated'})`
      : `Proposed by the ${candidate.lens} lens; no rationale supplied.`,
    remediation: `Review ${candidate.file}:${candidate.line}. Confirm whether ${candidate.entryPoint || 'attacker-controlled input'} can reach ${candidate.sink || 'this operation'}, and constrain it at the boundary if so.`,
    parser: 'DISCOVERY',
    family: candidate.family || 'other',
    ruleId: `discovery:${candidate.lens}`,
  };
  return {
    ...base,
    stableId: computeStableId(base),
    discovery: {
      lens: candidate.lens,
      focusAreaId: candidate.focusAreaId,
      confirmation: candidate.confirmation || null,
      refutation: candidate.refutation || null,
    },
  };
}

export function judgeCandidates(candidates, priorScan, triageFeedback) {
  const prior = Array.isArray(priorScan?.findings) ? priorScan.findings : [];
  const priorByLoc = new Map();
  const priorIds = new Set();
  for (const p of prior) {
    if (p?.stableId) priorIds.add(p.stableId);
    priorByLoc.set(`${p?.file}|${p?.line}|${p?.family}`, p?.stableId || null);
  }
  const feedback = triageFeedback && typeof triageFeedback === 'object' ? triageFeedback : {};

  const fresh = [], duplicates = [], suppressed = [];
  for (const c of candidates || []) {
    const f = toFindingShape(c);
    if (feedback[f.stableId] === 'fp') { suppressed.push({ ...f, suppressedBy: 'triage-fp' }); continue; }
    const locKey = `${f.file}|${f.line}|${f.family}`;
    if (priorIds.has(f.stableId)) { duplicates.push({ ...f, duplicateOf: f.stableId }); continue; }
    if (priorByLoc.has(locKey)) { duplicates.push({ ...f, duplicateOf: priorByLoc.get(locKey) }); continue; }
    fresh.push(f);
  }
  return { fresh, duplicates, suppressed };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-judge.test.js`
Expected: PASS, 10/10.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/judge.js scanner/test/discovery-judge.test.js
git commit -m "feat(discovery): judge — finding shape, evidence-driven severity, dedupe"
```

---

### Task 7: Orchestrator

Compose Tasks 1–6 into one run, with a real taint probe built on `runDeepAnalysis`, and a report that discloses what did *not* run.

**Files:**
- Create: `scanner/src/discovery/index.js`
- Test: `scanner/test/discovery-run.test.js`

**Interfaces:**
- Consumes: everything above; `runDeepAnalysis(perFileIR, callGraph, opts)` from `scanner/src/dataflow/index.js`.
- Produces:
  - `makeTaintProbe(perFileIR, callGraph): (candidate) => Promise<{tier,evidence}|null>`
  - `runDiscovery(ctx, opts?): Promise<DiscoveryReport>` where
    `ctx = { perFileIR, callGraph, fileContents, priorScan, triageFeedback }` and
    `DiscoveryReport = { schema: 'agentic-security/discovery@1', focusAreas, runs, fresh, duplicates, suppressed, refuted, coverage: { areasPlanned, areasHunted, lensesPerArea, degradedRuns, reasons } }`.
  - `opts.lenses` (default all seven), `opts.maxAreas` (default 8), `opts.llmInvoke`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-run.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDiscovery, makeTaintProbe } from '../src/discovery/index.js';

const CTX = {
  perFileIR: {},
  callGraph: {
    functions: new Map([['auth.js::login@1', { qid: 'auth.js::login@1', name: 'login', file: 'auth.js' }]]),
    edges: [],
  },
  fileContents: { 'auth.js': 'function login(u){ return db.query("select "+u); }' },
  priorScan: null,
  triageFeedback: null,
};

test('runDiscovery with no llm produces an empty but well-formed report', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  try {
    const r = await runDiscovery(CTX, {});
    assert.equal(r.schema, 'agentic-security/discovery@1');
    assert.deepEqual(r.fresh, []);
    assert.equal(r.coverage.areasPlanned, 1);
    assert.equal(r.coverage.degradedRuns, r.runs.length);
    assert.ok(r.coverage.reasons.length > 0, 'degradation must be disclosed, not silent');
  } finally {
    if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  }
});

test('runDiscovery runs one hunter per area per lens', async () => {
  const seen = [];
  const llmInvoke = async (p) => { seen.push(p); return '{"candidates":[]}'; };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection', 'authz'] });
  assert.equal(r.runs.length, 2);
  assert.equal(r.coverage.lensesPerArea, 2);
  assert.equal(r.coverage.areasHunted, 1);
});

test('a candidate flows hunt -> confirm -> disprove -> judge and lands in fresh', async () => {
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return '{"refuted":false,"reason":"looks real"}';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat","entryPoint":"u","sink":"db.query"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.fresh.length, 1);
  assert.equal(r.fresh[0].parser, 'DISCOVERY');
  assert.ok(r.fresh[0].stableId);
});

test('a refuted candidate never reaches fresh', async () => {
  const llmInvoke = async (p) => {
    if (/REFUTE/.test(p)) return '{"refuted":true,"reason":"unreachable"}';
    return '{"candidates":[{"title":"SQLi","file":"auth.js","line":1,"rationale":"concat"}]}';
  };
  const r = await runDiscovery(CTX, { llmInvoke, lenses: ['injection'] });
  assert.equal(r.fresh.length, 0);
  assert.equal(r.refuted.length, 1);
});

test('makeTaintProbe returns null rather than throwing on an unanalysable input', async () => {
  const probe = makeTaintProbe({}, null);
  assert.equal(await probe({ file: 'a.js', line: 1 }), null);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-run.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```js
// scanner/src/discovery/index.js
//
// Compose the discovery pipeline:
//
//   partition → (area × lens) hunters → confirm → disprove → judge
//
// COVERAGE IS PART OF THE OUTPUT. Every report states how many areas were
// planned versus hunted and how many runs degraded, with reasons. A discovery
// pass that half failed and reports "no findings" is indistinguishable from a
// clean codebase unless it says so.
import { partitionCallGraph } from './partition.js';
import { LENSES, lensByKey } from './lenses.js';
import { runHunter } from './hunter.js';
import { confirmAll } from './confirm.js';
import { disprovePanel } from './disprove.js';
import { judgeCandidates } from './judge.js';

// Bridge a candidate to the deterministic layer. A taint finding at or within
// two lines of the candidate corroborates it; a modelled sink on the line
// without a full path is weaker corroboration ("sink-adjacent").
export function makeTaintProbe(perFileIR, callGraph) {
  let cache = null;
  return async (candidate) => {
    if (!callGraph || !perFileIR) return null;
    try {
      if (!cache) cache = runDeepAnalysisSafe(perFileIR, callGraph);
      const deep = await cache;
      if (!deep) return null;
      const hits = (deep.findings || []).filter(f => f.file === candidate.file);
      const exact = hits.find(f => Math.abs((f.line ?? -1) - candidate.line) <= 2);
      if (exact) {
        return { tier: 'taint-confirmed', evidence: { matchedFinding: exact.id ?? null, line: exact.line, vuln: exact.vuln ?? null } };
      }
      return hits.length ? { tier: 'sink-adjacent', evidence: { sameFileFindings: hits.length } } : null;
    } catch {
      return null;
    }
  };
}

async function runDeepAnalysisSafe(perFileIR, callGraph) {
  try {
    const { runDeepAnalysis } = await import('../dataflow/index.js');
    return runDeepAnalysis(perFileIR, callGraph, {});
  } catch {
    return null;
  }
}

export async function runDiscovery(ctx = {}, opts = {}) {
  const areas = partitionCallGraph(ctx.callGraph, { maxAreas: opts.maxAreas ?? 8 });
  const lensKeys = Array.isArray(opts.lenses) && opts.lenses.length ? opts.lenses : LENSES.map(l => l.key);
  const lenses = lensKeys.map(lensByKey).filter(Boolean);

  const runs = [];
  const reasons = [];
  let candidates = [];
  const hunted = new Set();

  for (const area of areas) {
    for (const lens of lenses) {
      const run = await runHunter(area, lens, { fileContents: ctx.fileContents || {} }, { llmInvoke: opts.llmInvoke });
      runs.push({ focusAreaId: run.focusAreaId, lens: run.lens, degraded: run.degraded, reason: run.reason, candidateCount: run.candidates.length });
      if (run.degraded && run.reason) reasons.push(`${area.label} × ${lens.key}: ${run.reason}`);
      if (!run.degraded) hunted.add(area.id);
      candidates = candidates.concat(run.candidates);
    }
  }

  const taintProbe = makeTaintProbe(ctx.perFileIR, ctx.callGraph);
  const confirmed = await confirmAll(candidates, { taintProbe });
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke: opts.llmInvoke });
  const { fresh, duplicates, suppressed } = judgeCandidates(survivors, ctx.priorScan, ctx.triageFeedback);

  return {
    schema: 'agentic-security/discovery@1',
    focusAreas: areas.map(a => ({ id: a.id, label: a.label, files: a.files.length, size: a.size })),
    runs,
    fresh,
    duplicates,
    suppressed,
    refuted,
    coverage: {
      areasPlanned: areas.length,
      areasHunted: hunted.size,
      lensesPerArea: lenses.length,
      degradedRuns: runs.filter(r => r.degraded).length,
      reasons,
    },
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/discovery-run.test.js`
Expected: PASS, 5/5.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/discovery/index.js scanner/test/discovery-run.test.js
git commit -m "feat(discovery): orchestrator with taint probe and coverage disclosure"
```

---

### Task 8: Wire into the CLI, the `/scan` dispatcher, and the docs

Expose the pipeline as `/scan --hunt`, register the test scope, and record the subsystem where a future contributor will look for it.

**Files:**
- Create: `scanner/src/discovery/CLAUDE.md`
- Modify: `scanner/package.json` (add `test:discovery`; add it to the `test` chain)
- Modify: `commands/scan.md` (add the `--hunt` mode row and its section)
- Modify: `CLAUDE.md` (repository layout table — add the `scanner/src/discovery/` row)
- Modify: `hooks/session-stop-drift-check.js` (watch the new directory)
- Test: `scanner/test/discovery-wiring.test.js`

**Interfaces:**
- Consumes: `runDiscovery` (Task 7).
- Produces: no new JS exports; this task wires existing ones.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/discovery-wiring.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const REPO = path.resolve(SCANNER, '..');

test('a test:discovery scope exists and is part of the full test chain', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
  assert.ok(pkg.scripts['test:discovery'], 'missing test:discovery script');
  assert.match(pkg.scripts.test, /test:discovery/, 'test:discovery must run in the full gate');
});

test('the discovery subsystem has a local CLAUDE.md', () => {
  assert.ok(fs.existsSync(path.join(SCANNER, 'src', 'discovery', 'CLAUDE.md')));
});

test('the scan command documents the --hunt mode', () => {
  const md = fs.readFileSync(path.join(REPO, 'commands', 'scan.md'), 'utf8');
  assert.match(md, /--hunt/);
});

test('the repository layout table lists the discovery subsystem', () => {
  const md = fs.readFileSync(path.join(REPO, 'CLAUDE.md'), 'utf8');
  assert.match(md, /scanner\/src\/discovery\//);
});

test('no external tool names leak into the new subsystem', () => {
  const dir = path.join(SCANNER, 'src', 'discovery');
  const banned = /\b(semgrep|snyk|codeql|coccinelle|vulnhunter|raptor|mantis|deepsec)\b/i;
  for (const f of fs.readdirSync(dir)) {
    const txt = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.ok(!banned.test(txt), `${f} names an external tool`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/discovery-wiring.test.js`
Expected: FAIL — `missing test:discovery script`.

- [ ] **Step 3: Wire it up**

Add to `scanner/package.json` scripts, and append `&& npm run test:discovery` to the existing `test` chain:

```json
"test:discovery": "node --test test/discovery-partition.test.js test/discovery-lenses.test.js test/discovery-hunter.test.js test/discovery-confirm.test.js test/discovery-disprove.test.js test/discovery-judge.test.js test/discovery-run.test.js test/discovery-wiring.test.js"
```

Create `scanner/src/discovery/CLAUDE.md`:

```markdown
# scanner/src/discovery/

LLM-driven candidate discovery, gated by the deterministic engine.

`partition.js` splits the call graph into disjoint focus areas · `lenses.js`
holds the seven hunting lenses and the prompt builder · `hunter.js` runs one
bounded (area × lens) pass · `confirm.js` routes each candidate back through
the taint engine · `disprove.js` runs the three-angle majority-vote refutation
panel · `judge.js` shapes findings and dedupes against the prior scan ·
`index.js` composes them.

## Rules

- **A hunter proposes; it never decides.** Nothing reaches a report without
  passing `confirm.js` and surviving `disprove.js`.
- **Every LLM call is an injected `llmInvoke`.** No module may import an SDK or
  hard-code an endpoint. Absence of an LLM degrades to an empty, well-formed
  result — it never throws and never blocks a scan.
- **Silence never refutes.** A probe that says nothing lowers a candidate to
  `unconfirmed`; only an argued majority refutes. A voter that errors is
  excluded from the denominator, not counted as agreement.
- **Severity comes from evidence, not from the model.** The confirmation tier
  sets it: taint-confirmed → high, sink-adjacent → medium, unconfirmed → low.
  This layer never emits `critical`.
- **Ids are content digests.** No clock, no randomness, anywhere in an id, a
  digest, or a sort key.
- **Coverage is reported.** Degraded runs and their reasons appear in every
  report. A half-failed pass must never read as a clean one.
```

Add to the `commands/scan.md` mode table:

```markdown
| `--hunt` | LLM-driven discovery over the call-graph partition — seven lenses, deterministic confirmation, adversarial refutation. Advisory: never gates CI. Requires `AGENTIC_SECURITY_LLM_ENDPOINT`; without it, reports its own degradation and finds nothing. |
```

Add to the `CLAUDE.md` repository layout table, after the `scanner/src/dataflow/` row:

```markdown
| `scanner/src/discovery/` | LLM candidate discovery, gated by the deterministic engine. Propose → confirm → refute → judge. | `scanner/src/discovery/CLAUDE.md` |
```

In `hooks/session-stop-drift-check.js`, the watched directories are a table of
`[dir, claudeMdPath]` pairs at lines 33–35. Add a fourth row:

```js
  ['scanner/src/discovery/', 'scanner/src/discovery/CLAUDE.md'],
```

and update the comment at line 3 to read `scanner/src/{sast,posture,dataflow,discovery}/`.

- [ ] **Step 4: Run the full gate**

```bash
cd scanner && npm run test:discovery && npm test
```

Expected: `test:discovery` PASS 5/5 on the wiring file and green across all seven earlier files; `npm test` green. Read the actual output — do not infer.

- [ ] **Step 5: Rebuild the bundle and run the push gate**

```bash
cd scanner && npm run build
find ../bench/cve-replay -type d -name .agentic-security -prune -exec rm -rf {} +
npm run bench:cve-replay:check; echo "corpus exit=$?"
npm run bench:self-scan:check; echo "self-scan exit=$?"
```

Expected: both exit 0. The self-scan baseline may legitimately move — this task
adds source files that the scanner scans. If it moves, review each new finding
by hand and only then run `npm run bench:self-scan:update-baseline`.

- [ ] **Step 6: Commit**

```bash
git add scanner/package.json scanner/src/discovery/CLAUDE.md scanner/test/discovery-wiring.test.js \
        commands/scan.md CLAUDE.md hooks/session-stop-drift-check.js scanner/dist/
git commit -m "feat(discovery): wire the discovery layer into /scan --hunt, tests, and docs"
```

---

## Deferred, deliberately

These belong to the discovery layer but are out of scope for this plan; each is
a follow-on that needs the pipeline above to exist first.

- **Parallel hunter execution.** Tasks 3 and 7 run hunters sequentially. The
  interfaces are already independent per (area × lens), so parallelising is a
  change to one loop — but concurrency limits and token budgeting deserve their
  own plan alongside the cost-governance work.
- **Cost governance.** A hard token/dollar ceiling across a discovery run,
  extending `hooks/model-cost-advisor.js`. Do not run this pipeline against a
  large repository until that exists.
- **Loop-until-dry.** Re-running hunters until K consecutive rounds surface
  nothing new, deduping against everything seen rather than everything
  confirmed.
- **Promotion into `last-scan.json`.** Discovery output currently stands beside
  the scan rather than inside it. Merging the two touches the integrity
  signature and the CI gate contract, and needs its own plan.

## Related plans (not written yet)

- **Plan A — independent evaluation population.** Decided inputs: real
  fix-commit datasets (third-party CVE/CWE labels, source fetched at eval time
  rather than committed) **and** held-out real repositories labelled by someone
  who did not write the detectors. Reported as a track separate from the
  regression corpus, never merged into it.
- **Plan B — third-party-verifiable attestation.** Extend
  `posture/attestation.js` from per-install symmetric HMAC to asymmetric
  signing over per-finding evidence bundles, verifiable without the signer's
  key.
