#!/usr/bin/env node
// Measured construct matrix for the Layer-1 IR (E2-01): for each language and each construct, does the IR model a minimal probe?
//   node scripts/engineering-excellence/ir-matrix.mjs            write data/ir-matrix.json and docs/engineering-excellence/IR_CONTRACT.md
//   node scripts/engineering-excellence/ir-matrix.mjs --check    fail when the committed matrix no longer matches a fresh measurement
//
// A probe is a few lines of source for ONE construct. "Modelled" means the IR holds the structure the construct implies (a function record,
// a call record, an assignment source that is not `unknown`, ...). It does not mean the taint engine tracks it end to end; that is a separate
// question the dataflow layer answers and this matrix does not. A failing probe may also be a badly written probe; the snippets are in the
// data file so a reader can check.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProjectIRAsync } from '../../scanner/src/ir/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const DATA = path.join(HERE, 'data/ir-matrix.json');
const DOC = path.join(REPO, 'docs/engineering-excellence/IR_CONTRACT.md');

export const CONSTRUCTS = ['function-definition', 'call-site', 'assignment-origin', 'member-access', 'string-concatenation', 'closure-as-own-function', 'import'];

// predicate names: fn(name) function record exists | call(name) a call to `name` is recorded (as a call or inside an assignment source) |
// origin(var) the variable has a write whose source is not unknown | kind(k) some recorded expression has kind k | fnCount(n) at least n function records besides the module
export const PROBES = {
  javascript: { file: 'p.js', c: {
    'function-definition': ['function target(a) { return a; }\n', 'fn:target'],
    'call-site': ['function f(x) { sink(x); }\n', 'call:sink'],
    'assignment-origin': ['function f(x) { const v = x.id; sink(v); }\n', 'origin:v'],
    'member-access': ['function f(req) { sink(req.query.id); }\n', 'kind:member'],
    'string-concatenation': ['function f(x) { const v = "a" + x; sink(v); }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['function f(x) { const g = (y) => sink(y + x); g(1); }\n', 'fnCount:2'],
    'import': ['const m = require("./m");\nfunction f(x) { m.go(x); }\n', 'call:require'],
  } },
  typescript: { file: 'p.ts', c: {
    'function-definition': ['export function target(a: string): string { return a; }\n', 'fn:target'],
    'call-site': ['export function f(x: string) { sink(x); }\n', 'call:sink'],
    'assignment-origin': ['export function f(x: any) { const v: string = x.id; sink(v); }\n', 'origin:v'],
    'member-access': ['export function f(req: any) { sink(req.query.id); }\n', 'kind:member'],
    'string-concatenation': ['export function f(x: string) { const v = `a${x}`; sink(v); }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['export function f(x: string) { const g = (y: string) => sink(y + x); g("1"); }\n', 'fnCount:2'],
    'import': ['import { go } from "./m";\nexport function f(x: string) { go(x); }\n', 'call:go'],
  } },
  python: { file: 'p.py', c: {
    'function-definition': ['def target(a):\n    return a\n', 'fn:target'],
    'call-site': ['def f(x):\n    sink(x)\n', 'call:sink'],
    'assignment-origin': ['def f(x):\n    v = x.id\n    sink(v)\n', 'origin:v'],
    'member-access': ['def f(req):\n    sink(req.args.id)\n', 'kind:member'],
    'string-concatenation': ['def f(x):\n    v = "a" + x\n    sink(v)\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['def f(x):\n    g = lambda y: sink(y + x)\n    g(1)\n', 'fnCount:2'],
    'import': ['import os\ndef f(x):\n    os.system(x)\n', 'call:os.system'],
  } },
  java: { file: 'P.java', c: {
    'function-definition': ['class P { String target(String a) { return a; } }\n', 'fn:target'],
    'call-site': ['class P { void f(String x) { sink(x); } }\n', 'call:sink'],
    'assignment-origin': ['class P { void f(Req x) { String v = x.id(); sink(v); } }\n', 'origin:v'],
    'member-access': ['class P { void f(Req r) { sink(r.id); } }\n', 'kind:member'],
    'string-concatenation': ['class P { void f(String x) { String v = "a" + x; sink(v); } }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['class P { void f(String x) { Runnable g = () -> sink(x); g.run(); } }\n', 'fnCount:2'],
    'import': ['import java.io.File;\nclass P { void f(String x) { new File(x); } }\n', 'call:File'],
  } },
  go: { file: 'p.go', c: {
    'function-definition': ['package p\nfunc target(a string) string { return a }\n', 'fn:target'],
    'call-site': ['package p\nfunc f(x string) { sink(x) }\n', 'call:sink'],
    'assignment-origin': ['package p\nfunc f(x Req) { v := x.ID\n sink(v) }\n', 'origin:v'],
    'member-access': ['package p\nfunc f(r Req) { sink(r.ID) }\n', 'kind:member'],
    'string-concatenation': ['package p\nfunc f(x string) { v := "a" + x\n sink(v) }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['package p\nfunc f(x string) { g := func(y string) { sink(y + x) }\n g("1") }\n', 'fnCount:2'],
    'import': ['package p\nimport "os/exec"\nfunc f(x string) { exec.Command(x) }\n', 'call:exec.Command'],
  } },
  ruby: { file: 'p.rb', c: {
    'function-definition': ['def target(a)\n  a\nend\n', 'fn:target'],
    'call-site': ['def f(x)\n  sink(x)\nend\n', 'call:sink'],
    'assignment-origin': ['def f(x)\n  v = x.id\n  sink(v)\nend\n', 'origin:v'],
    'member-access': ['def f(req)\n  sink(req.params)\nend\n', 'kind:member'],
    'string-concatenation': ['def f(x)\n  v = "a" + x\n  sink(v)\nend\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['def f(x)\n  g = ->(y) { sink(y + x) }\n  g.call(1)\nend\n', 'fnCount:2'],
    'import': ['require "open3"\ndef f(x)\n  Open3.capture2(x)\nend\n', 'call:Open3.capture2'],
  } },
  php: { file: 'p.php', c: {
    'function-definition': ['<?php\nfunction target($a) { return $a; }\n', 'fn:target'],
    'call-site': ['<?php\nfunction f($x) { sink($x); }\n', 'call:sink'],
    'assignment-origin': ['<?php\nfunction f($x) { $v = $x["id"]; sink($v); }\n', 'origin:$v'],
    'member-access': ['<?php\nfunction f($r) { sink($r->id); }\n', 'kind:member'],
    'string-concatenation': ['<?php\nfunction f($x) { $v = "a" . $x; sink($v); }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['<?php\nfunction f($x) { $g = function($y) use ($x) { sink($y . $x); }; $g(1); }\n', 'fnCount:2'],
    'import': ['<?php\nrequire "m.php";\nfunction f($x) { go($x); }\n', 'call:go'],
  } },
  csharp: { file: 'P.cs', c: {
    'function-definition': ['class P { string Target(string a) { return a; } }\n', 'fn:Target'],
    'call-site': ['class P { void F(string x) { Sink(x); } }\n', 'call:Sink'],
    'assignment-origin': ['class P { void F(Req x) { var v = x.Id; Sink(v); } }\n', 'origin:v'],
    'member-access': ['class P { void F(Req r) { Sink(r.Id); } }\n', 'kind:member'],
    'string-concatenation': ['class P { void F(string x) { var v = "a" + x; Sink(v); } }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['class P { void F(string x) { Action<string> g = y => Sink(y + x); g("1"); } }\n', 'fnCount:2'],
    'import': ['using System.Diagnostics;\nclass P { void F(string x) { Process.Start(x); } }\n', 'call:Process.Start'],
  } },
  kotlin: { file: 'p.kt', c: {
    'function-definition': ['fun target(a: String): String { return a }\n', 'fn:target'],
    'call-site': ['fun f(x: String) { sink(x) }\n', 'call:sink'],
    'assignment-origin': ['fun f(x: Req) { val v = x.id\n sink(v) }\n', 'origin:v'],
    'member-access': ['fun f(r: Req) { sink(r.id) }\n', 'kind:member'],
    'string-concatenation': ['fun f(x: String) { val v = "a" + x\n sink(v) }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['fun f(x: String) { val g = { y: String -> sink(y + x) }\n g("1") }\n', 'fnCount:2'],
    'import': ['import java.io.File\nfun f(x: String) { File(x) }\n', 'call:File'],
  } },
  rust: { file: 'p.rs', c: {
    'function-definition': ['fn target(a: &str) -> &str { a }\n', 'fn:target'],
    'call-site': ['fn f(x: &str) { sink(x); }\n', 'call:sink'],
    'assignment-origin': ['fn f(x: Req) { let v = x.id;\n sink(v); }\n', 'origin:v'],
    'member-access': ['fn f(r: Req) { sink(r.id); }\n', 'kind:member'],
    'string-concatenation': ['fn f(x: &str) { let v = format!("a{}", x);\n sink(&v); }\n', 'kind:binary|tpl'],
    'closure-as-own-function': ['fn f(x: &str) { let g = |y: &str| sink(y);\n g(x); }\n', 'fnCount:2'],
    'import': ['use std::process::Command;\nfn f(x: &str) { Command::new(x); }\n', 'call:Command.new'],
  } },
};

function exprs(e, acc) { if (!e || typeof e !== 'object') return acc; acc.push(e); for (const k of ['object', 'callee', 'left', 'right']) if (e[k]) exprs(e[k], acc); for (const k of ['args', 'parts', 'elements']) if (Array.isArray(e[k])) e[k].forEach((x) => exprs(x, acc)); return acc; }
const nameOf = (e) => (typeof e === 'string' ? e : e?.kind === 'ident' ? e.name : e?.kind === 'member' ? `${nameOf(e.object)}.${e.prop}` : '');
// The CFG is the one structure every language's IR shares: assignment nodes carry { target, source, line }, call nodes carry { callee, args }.
const cfgNodes = (f) => Object.values(f.cfg?.nodes || {});
function judge(ir, spec) {
  const fns = Object.values(ir.perFile).flatMap((pf) => pf.functions || []);
  const real = fns.filter((f) => f.name !== '<module>');
  const [kind, arg] = spec.split(':');
  const calls = [];
  const kinds = new Set();
  const origins = new Set();
  for (const f of fns) {
    for (const c of f.calls || []) { calls.push(nameOf(c.callee)); for (const a of c.args || []) exprs(a, []).forEach((x) => kinds.add(x.kind)); }
    for (const n of cfgNodes(f)) {
      if (n.kind === 'assign' && n.source) { exprs(n.source, []).forEach((x) => { kinds.add(x.kind); if (x.kind === 'call') calls.push(nameOf(x.callee)); }); if (n.source.kind !== 'unknown') origins.add(n.target); }
      if (n.kind === 'call') { calls.push(nameOf(n.callee)); for (const a of n.args || []) exprs(a, []).forEach((x) => kinds.add(x.kind)); }
    }
  }
  switch (kind) {
    case 'fn': return real.some((f) => f.name === arg || String(f.name).endsWith(`.${arg}`) || String(f.name).endsWith(`::${arg}`));
    case 'call': return calls.some((c) => c === arg || c.endsWith(`.${arg}`));
    case 'origin': return origins.has(arg);
    case 'kind': return arg.split('|').some((k) => kinds.has(k));
    case 'fnCount': return real.length >= Number(arg);
    default: return false;
  }
}

export async function measure() {
  const out = { schema: 'agentic-security/ir-matrix', version: 1, constructs: CONSTRUCTS, languages: {} };
  for (const [lang, p] of Object.entries(PROBES)) {
    out.languages[lang] = {};
    for (const c of CONSTRUCTS) {
      const [src, spec] = p.c[c];
      let state; let note = null;
      try {
        const ir = await buildProjectIRAsync({ [p.file]: src });
        state = judge(ir, spec) ? 'modelled' : 'not-modelled';
      } catch (e) { state = 'error'; note = String(e.message).slice(0, 120); }
      out.languages[lang][c] = { state, probe: src, expects: spec, ...(note ? { note } : {}) };
    }
  }
  return out;
}

function render(m) {
  const L = [];
  L.push('# IR and dataflow contract (E2-01)', '', 'Part generated by `node scripts/engineering-excellence/ir-matrix.mjs`, part written. The matrix below is measured; the rest is the contract the new semantic graph adds.', '');
  L.push('## Layers', '');
  L.push('| Layer | Where | What it holds | Consumers |', '|---|---|---|---|');
  L.push('| Layer 1: per-file IR | `scanner/src/ir/parser-*.js`, `index.js` | per function: `qid`, `name`, `line`, `params`, a CFG, `calls[]` (statement-level calls), `writes{var:[{node,source}]}` (assignment sources as expression trees), `returns[]`; per project: a call graph and a class hierarchy | the taint engine, reachability, the DCI symbol graph (separately) |');
  L.push('| Layer 2: dataflow | `scanner/src/dataflow/` | k=1 monovariant return-taint, summaries, access paths, points-to, guard dominance, sanitizer gates, path feasibility, symbolic execution, cross-service taint | `ir-taint` findings and their `chain[]` |');
  L.push('| Layer 3: validation | `scanner/src/llm-validator/` | optional model judgement over a finding | confidence only |');
  L.push('| **Semantic graph (new, additive)** | `scanner/src/ir/semantic-graph.js` | typed entities with stable ids over Layer 1, see below | none yet; opt-in |', '');
  L.push('## Measured IR construct matrix', '');
  L.push('Each cell is one minimal probe through `buildProjectIRAsync`. `modelled` means the IR holds the structure the construct implies; it does not mean the taint engine follows it end to end. The probes are in `scripts/engineering-excellence/data/ir-matrix.json`.', '');
  L.push(`| Language | ${m.constructs.join(' | ')} |`, `|---|${m.constructs.map(() => '---').join('|')}|`);
  for (const [lang, cells] of Object.entries(m.languages)) L.push(`| ${lang} | ${m.constructs.map((c) => cells[c].state).join(' | ')} |`);
  const total = Object.values(m.languages).flatMap((cells) => Object.values(cells));
  L.push('', `${total.filter((x) => x.state === 'modelled').length} of ${total.length} probes modelled, ${total.filter((x) => x.state === 'not-modelled').length} not modelled, ${total.filter((x) => x.state === 'error').length} errored. Languages not probed: C and C++ (their IR is a separate preprocessor-driven path), Solidity, Swift and Dart (tree-sitter sink matching only, no IR).`, '');
  L.push('## Known structural gaps in Layer 1 (observed, not inferred)', '');
  L.push('- A call nested inside an assignment source (`const cmd = h.build(x)`) is recorded under `writes`, not in `calls[]`, so a consumer that reads only `calls[]` misses it. The semantic graph reads both.');
  L.push('- `exports.run = function run(){}` records the assignment source as `unknown`; the function itself is a separate record, and nothing links the export name to it.');
  L.push('- The call graph has no edge for `h.build(...)` where `h` is a `require` result: the callee is `null`. Cross-file resolution is E2-02.');
  L.push('- The IR carries line numbers only, never columns.', '');
  L.push('## The semantic graph contract', '');
  L.push('`buildSemanticGraph(projectIR)` returns `agentic-security/semantic-graph` version `1.0.0`. It is additive: it reads the IR, never changes it, and is not part of findings, `chain[]` or `last-scan.json`.', '');
  L.push('| Entity list | Populated from the IR today | Identity (never includes a line) |', '|---|---|---|');
  L.push('| `symbols` | yes: modules and functions | file, qualified name without the `@line` suffix, order among same-named |');
  L.push('| `callSites` | yes: `calls[]` plus calls inside assignment sources | caller symbol, callee text, order within the caller |');
  L.push('| `allocations` | yes: object, array and function-valued expressions | owning symbol, kind, order |');
  L.push('| `fieldAccesses` | yes: member reads and dotted writes | owning symbol, base, path, mode, order |');
  L.push('| `valueOrigins` | yes: every call argument and every assignment source | owning symbol, variable, origin kind, text, order |');
  L.push('| `serviceBoundaries`, `storageEdges` | schema only: the IR carries none; E2-07 | |');
  L.push('| `sanitizers`, `guards` | schema only: decided by the dataflow layer, not recorded; E2-08 | |', '');
  L.push('Every entity has `file`, `line`, `column` (always `null` today, with `locationPrecision: "line"`) and `confidence: { tier, basis }` where tier is `observed`, `inferred` or `unresolved`. A call resolved only by a same-file name match is `inferred`; an unresolved call says so and has no callee. The `coverage` block says, per list, `populated` or `schema-only` and why. The wire format is canonical JSON (sorted keys, entities sorted by id); a different major version is refused, not guessed at, and `migrateGraph` brings an older minor up to date.', '');
  return L.join('\n');
}

async function main() {
  const check = process.argv.includes('--check');
  const m = await measure();
  if (check) {
    const stored = JSON.parse(fs.readFileSync(DATA, 'utf8'));
    const diff = [];
    for (const [l, cells] of Object.entries(m.languages)) for (const c of CONSTRUCTS) if (stored.languages?.[l]?.[c]?.state !== cells[c].state) diff.push(`${l}/${c}: ${stored.languages?.[l]?.[c]?.state} -> ${cells[c].state}`);
    if (diff.length) { console.error(`the IR matrix changed:\n${diff.join('\n')}`); process.exit(1); }
    if (fs.readFileSync(DOC, 'utf8') !== render(m)) { console.error('IR_CONTRACT.md is stale'); process.exit(1); }
    console.log('IR matrix matches'); return;
  }
  fs.writeFileSync(DATA, JSON.stringify(m, null, 2) + '\n');
  fs.writeFileSync(DOC, render(m));
  const t = Object.values(m.languages).flatMap((c) => Object.values(c));
  console.log(`wrote matrix: ${t.filter((x) => x.state === 'modelled').length}/${t.length} modelled`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((e) => { console.error(e); process.exit(2); });
