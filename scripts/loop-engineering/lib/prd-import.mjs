// Deterministic importer for PRD section 8 (LOOP-001). It parses the markdown
// requirement blocks, cross-checks them against the totals the PRD itself
// declares, and refuses (never repairs) anything malformed: a duplicate ID, a
// missing weight, a dependency on an unknown ID, a cycle, a lost criterion.
import { readFileSync } from 'node:fs';
import { sha256 } from './util.mjs';

export class ImportError extends Error {
  constructor(problems) {
    super(`PRD import failed:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ImportError';
    this.problems = problems;
  }
}

const HEAD = /^### ([A-Z]+(?:-\d+)?) — (.+)$/;
const META = /^Weight:\s*(\d+)\s*\|\s*Dependencies:\s*(.+?)\s*\|\s*Verification suite:\s*`([^`]+)`\s*$/;
const AC = /^- \*\*([A-Z]+-\d+\.AC\d{2}):\*\*\s*(.+)$/;
const CATEGORY = { LOOP: 'loop', CORE: 'shared', X: 'shared', HS: 'haskell', NIX: 'nix', QA: 'quality', DOC: 'documentation', REL: 'release' };

export function parsePrd(text) {
  const problems = [];
  const lines = text.split('\n');
  const start = lines.findIndex((l) => /^## 8\. /.test(l));
  const end = lines.findIndex((l, i) => i > start && /^## 9\. /.test(l));
  if (start < 0 || end < 0) throw new ImportError(['section 8 (Atomic implementation requirements) not found']);
  const sec = lines.slice(start, end);

  const declared = /\*\*(\d+) required requirements,\s*(\d+) total weight points,\s*(\d+) acceptance criteria\*\*/.exec(sec.join('\n'));
  const reqs = [];
  let cur = null;
  let inAcc = false;
  for (let i = 0; i < sec.length; i++) {
    const line = sec[i];
    const h = HEAD.exec(line);
    if (h) {
      cur = { id: h[1], title: h[2].trim(), description: [], criteria: [], line: start + i + 1 };
      reqs.push(cur); inAcc = false; continue;
    }
    if (!cur) continue;
    const m = META.exec(line);
    if (m) {
      cur.weight = Number(m[1]);
      cur.dependencies = /^none$/i.test(m[2].trim()) ? [] : m[2].split(',').map((s) => s.trim()).filter(Boolean);
      cur.suite = m[3];
      continue;
    }
    if (/^Acceptance:\s*$/.test(line)) { inAcc = true; continue; }
    const a = AC.exec(line);
    if (a && inAcc) { cur.criteria.push({ id: a[1], text: a[2].trim() }); continue; }
    if (!inAcc && line.trim() && !line.startsWith('#')) cur.description.push(line.trim());
    else if (inAcc && line.trim() && /^- /.test(line)) problems.push(`${cur.id}: malformed acceptance bullet: ${line.slice(0, 80)}`);
  }

  const seen = new Set();
  for (const r of reqs) {
    if (seen.has(r.id)) problems.push(`duplicate requirement ID ${r.id}`);
    seen.add(r.id);
    if (!Number.isInteger(r.weight)) problems.push(`${r.id}: missing or malformed Weight/Dependencies/Verification suite line`);
    else if (r.weight < 1 || r.weight > 5) problems.push(`${r.id}: weight ${r.weight} outside 1..5`);
    if (!r.suite) problems.push(`${r.id}: missing verification suite`);
    if (!r.criteria.length) problems.push(`${r.id}: no acceptance criteria`);
    const prefix = r.id.split('-')[0];
    if (!CATEGORY[prefix]) problems.push(`${r.id}: unknown category prefix ${prefix}`);
    const cseen = new Set();
    r.criteria.forEach((c, idx) => {
      if (!c.id.startsWith(r.id + '.')) problems.push(`${c.id}: does not belong to ${r.id}`);
      if (cseen.has(c.id)) problems.push(`duplicate criterion ${c.id}`);
      cseen.add(c.id);
      const want = `${r.id}.AC${String(idx + 1).padStart(2, '0')}`;
      if (c.id !== want) problems.push(`${r.id}: criterion #${idx + 1} is ${c.id}, expected ${want} (bullet order)`);
    });
  }
  const ids = new Set(reqs.map((r) => r.id));
  for (const r of reqs) for (const d of r.dependencies || []) if (!ids.has(d)) problems.push(`${r.id}: depends on unknown ID ${d}`);
  problems.push(...findCycles(reqs));

  const totals = { requirements: reqs.length, criteria: reqs.reduce((n, r) => n + r.criteria.length, 0), weight: reqs.reduce((n, r) => n + (r.weight || 0), 0) };
  if (!declared) problems.push('PRD does not declare its initial manifest totals; cannot cross-check');
  else {
    const [d1, d2, d3] = [Number(declared[1]), Number(declared[2]), Number(declared[3])];
    if (d1 !== totals.requirements) problems.push(`PRD declares ${d1} requirements but ${totals.requirements} were parsed`);
    if (d2 !== totals.weight) problems.push(`PRD declares ${d2} weight points but ${totals.weight} were parsed`);
    if (d3 !== totals.criteria) problems.push(`PRD declares ${d3} acceptance criteria but ${totals.criteria} were parsed`);
  }
  if (problems.length) throw new ImportError(problems);
  return { requirements: reqs, totals, declared: declared ? { requirements: +declared[1], weight: +declared[2], criteria: +declared[3] } : null };
}

export function findCycles(reqs) {
  const byId = new Map(reqs.map((r) => [r.id, r]));
  const state = new Map();
  const problems = [];
  const visit = (id, stack) => {
    if (state.get(id) === 2) return;
    if (state.get(id) === 1) { problems.push(`dependency cycle: ${[...stack, id].slice(stack.indexOf(id)).join(' -> ')}`); return; }
    state.set(id, 1);
    for (const d of byId.get(id)?.dependencies || []) if (byId.has(d)) visit(d, [...stack, id]);
    state.set(id, 2);
  };
  for (const r of reqs) visit(r.id, []);
  return [...new Set(problems)];
}

export function categoryOf(id) { return CATEGORY[id.split('-')[0]]; }

export function readPrd(path) {
  const text = readFileSync(path, 'utf8');
  return { text, sha256: sha256(text) };
}
