// Capability ledger checker (HASKELL_NIXOS PRD, CORE-001).
//
// Crawls the documentation entry points of the checkout (the README
// Documentation section, docs/README.md, commands/*.md and the README Commands
// section), then compares what it found with docs/capability-ledger.json.
// Nothing here is hardcoded to the current doc set: a link added to an index,
// a command added under commands/, or a doc dropped into docs/ that no index
// links shows up as a failure until the ledger accounts for it.
//
// Static only. Reads files; never runs anything it reads.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const LEDGER_PATH = 'docs/capability-ledger.json';
export const PRD_PATH = 'HASKELL_NIXOS_FULL_CAPABILITY_PRD.md';

const ECOSYSTEM_BLOCKS = ['haskell', 'nix', 'nixosExecution'];
const REQ_ID = /^[A-Z]+-\d{3}$/;

const read = (root, rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const toPosix = (p) => p.split(path.sep).join('/');

export function loadLedger(root = REPO_ROOT) {
  return JSON.parse(read(root, LEDGER_PATH));
}

// ---------------------------------------------------------------------------
// PRD parsing
// ---------------------------------------------------------------------------

function expandIds(text) {
  const out = [];
  for (const m of text.matchAll(/\b([A-Z]+)-(\d{3})(?:–\1-(\d{3}))?/g)) {
    const from = Number(m[2]);
    const to = m[3] ? Number(m[3]) : from;
    for (let n = from; n <= to; n++) out.push(`${m[1]}-${String(n).padStart(3, '0')}`);
  }
  return out;
}

export function parsePrd(root = REPO_ROOT) {
  const lines = read(root, PRD_PATH).split('\n');
  const ids = [];
  const suiteByRequirement = {};
  let current = null;
  let inSection3 = false;
  const section3Ids = new Set();
  for (const line of lines) {
    if (/^## /.test(line)) {
      inSection3 = /^## 3\./.test(line);
      current = null;
    }
    const h = line.match(/^### ([A-Z]+-\d{3}) /);
    if (h) {
      current = h[1];
      ids.push(current);
      continue;
    }
    if (/^### /.test(line)) current = null;
    if (current) {
      const s = line.match(/Verification suite: `([^`]+)`/);
      if (s) suiteByRequirement[current] = s[1];
    }
    if (inSection3 && line.startsWith('|') && !/^\|[\s-|]+$/.test(line)) {
      const cells = line.split('|').map((c) => c.trim()).filter(Boolean);
      const last = cells[cells.length - 1] || '';
      for (const id of expandIds(last)) section3Ids.add(id);
    }
  }
  return {
    ids,
    suiteByRequirement,
    suiteNames: new Set(Object.values(suiteByRequirement)),
    section3Ids,
  };
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

function sectionOf(text, headingRe) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => headingRe.test(l));
  if (start < 0) return '';
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^## /.test(lines[i])) { end = i; break; }
  }
  return lines.slice(start, end).join('\n');
}

// Internal repo-relative link targets of one markdown file. Directories keep
// a trailing slash. A link that resolves to nothing is reported, not skipped.
function linkTargets(root, fromRel, text) {
  const found = [];
  const broken = [];
  for (const m of text.matchAll(/\]\(([^)\s]+)\)/g)) {
    let target = m[1];
    if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#')) continue;
    target = target.replace(/[#?].*$/, '');
    if (!target) continue;
    const rel = toPosix(path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), target)));
    const abs = path.join(root, rel);
    if (!fs.existsSync(abs)) { broken.push({ from: fromRel, target: m[1] }); continue; }
    found.push(fs.statSync(abs).isDirectory() ? `${rel.replace(/\/+$/, '')}/` : rel);
  }
  return { found, broken };
}

function walkMarkdown(root, relDir) {
  const base = path.join(root, relDir);
  if (!fs.existsSync(base)) return [];
  return fs.readdirSync(base, { recursive: true })
    .map(toPosix)
    .filter((p) => p.endsWith('.md'))
    // `.agentic-security/` holds scanner runtime state written by running the
    // tool from a docs directory; it is generated output, not a documented capability.
    .filter((p) => !p.split('/').includes('.agentic-security'))
    .map((p) => `${relDir}/${p}`);
}

export function discoverCapabilities(root = REPO_ROOT, { excludedDocPrefixes = [] } = {}) {
  const sources = new Map();
  const brokenLinks = [];
  const add = (key, origin) => { if (!sources.has(key)) sources.set(key, origin); };

  const readme = read(root, 'README.md');
  const docsSection = sectionOf(readme, /^## Documentation\b/);
  const fromReadme = linkTargets(root, 'README.md', docsSection);
  const fromIndex = linkTargets(root, 'docs/README.md', read(root, 'docs/README.md'));
  brokenLinks.push(...fromReadme.broken, ...fromIndex.broken);
  for (const k of fromReadme.found) add(k, 'README.md#documentation');
  for (const k of fromIndex.found) add(k, 'docs/README.md');

  // Commands: every dispatcher file plus every command the README lists.
  const commands = new Set();
  const modes = {};
  const commandsDir = path.join(root, 'commands');
  if (fs.existsSync(commandsDir)) {
    for (const f of fs.readdirSync(commandsDir)) {
      if (f.endsWith('.md')) commands.add(f.slice(0, -3));
    }
  }
  const cmdSection = sectionOf(readme, /^## Commands\b/);
  for (const line of cmdSection.split('\n')) {
    const m = line.match(/^- \*\*`([a-z][a-z-]*)`\*\*/);
    if (!m) continue;
    commands.add(m[1]);
    const md = line.match(/Modes:\s*([a-z\- /]+)/);
    if (md) modes[m[1]] = md[1].split('/').map((s) => s.trim()).filter(Boolean);
  }
  for (const c of commands) add(`command:${c}`, 'commands');

  // Docs that exist but no index links to them.
  const linked = [...sources.keys()].filter((k) => !k.startsWith('command:'));
  const dirs = linked.filter((k) => k.endsWith('/'));
  const unindexedDocs = walkMarkdown(root, 'docs')
    .filter((p) => !excludedDocPrefixes.some((pre) => p.startsWith(pre)))
    .filter((p) => !linked.includes(p) && !dirs.some((d) => p.startsWith(d)))
    .sort();

  return { sources, commands, modes, brokenLinks, unindexedDocs };
}

// ---------------------------------------------------------------------------
// Checks. Each returns an array of human-readable errors (empty = pass).
// ---------------------------------------------------------------------------

export function checkCoverage(ledger, discovered, prd, root = REPO_ROOT) {
  const errors = [];
  const entries = Array.isArray(ledger.entries) ? ledger.entries : [];
  if (entries.length === 0) errors.push('ledger has no entries');

  const seen = new Set();
  const covered = new Set();
  const usedRequirements = new Set();
  const taskIds = new Set((ledger.additionalRequiredTasks || []).map((t) => t.id));

  for (const e of entries) {
    const where = `entry ${e.id}`;
    if (!e.id || seen.has(e.id)) errors.push(`${where}: missing or duplicate id`);
    seen.add(e.id);
    if (!e.title) errors.push(`${where}: missing title`);
    if (!Array.isArray(e.sources) || e.sources.length === 0) errors.push(`${where}: no sources`);
    for (const s of e.sources || []) {
      covered.add(s);
      if (!discovered.sources.has(s)) errors.push(`${where}: source no longer documented or discoverable: ${s}`);
    }
    for (const block of ECOSYSTEM_BLOCKS) {
      const b = e[block];
      if (!b || typeof b !== 'object') { errors.push(`${where}: missing ${block} block`); continue; }
      const reqs = Array.isArray(b.requirements) ? b.requirements : [];
      for (const r of reqs) {
        usedRequirements.add(r);
        if (!REQ_ID.test(r) || !prd.ids.includes(r)) errors.push(`${where}.${block}: unknown requirement ${r}`);
      }
      if (b.applicability === 'applicable') {
        if (reqs.length === 0) errors.push(`${where}.${block}: applicable but no requirement IDs`);
        if (b.status !== 'proposed') errors.push(`${where}.${block}: status must be "proposed", got ${JSON.stringify(b.status)}`);
      } else if (b.applicability === 'not-applicable') {
        if (typeof b.justification !== 'string' || b.justification.trim().length < 30) {
          errors.push(`${where}.${block}: not-applicable needs a justification of at least 30 characters`);
        }
      } else {
        errors.push(`${where}.${block}: applicability must be "applicable" or "not-applicable"`);
      }
    }
    for (const field of ['entryPoints', 'documents']) {
      const list = e[field];
      if (!Array.isArray(list) || list.length === 0) { errors.push(`${where}: empty ${field}`); continue; }
      for (const p of list) if (!fs.existsSync(path.join(root, p))) errors.push(`${where}: ${field} path does not exist: ${p}`);
    }
    if (!Array.isArray(e.suites) || e.suites.length === 0) errors.push(`${where}: no suites`);
    for (const s of e.suites || []) if (!prd.suiteNames.has(s)) errors.push(`${where}: suite not defined by the PRD: ${s}`);

    // Command modes: the ledger must carry exactly the modes the README lists.
    for (const s of e.sources || []) {
      if (!s.startsWith('command:')) continue;
      const name = s.slice('command:'.length);
      const found = discovered.modes[name] || [];
      if (found.length > 0) {
        if (JSON.stringify(e.modes || []) !== JSON.stringify(found)) {
          errors.push(`${where}: modes for ${name} differ from README (ledger ${JSON.stringify(e.modes || [])}, README ${JSON.stringify(found)})`);
        }
      } else if (e.modesInventoryTask) {
        if (!taskIds.has(e.modesInventoryTask)) errors.push(`${where}: modesInventoryTask ${e.modesInventoryTask} is not a ledger task`);
      } else if (typeof e.modesJustification !== 'string' || e.modesJustification.trim().length < 15) {
        errors.push(`${where}: ${name} lists no modes; needs modesInventoryTask or modesJustification`);
      }
    }
  }

  for (const key of discovered.sources.keys()) {
    if (!covered.has(key)) errors.push(`unmapped capability: ${key}`);
  }
  for (const id of prd.section3Ids) {
    if (!usedRequirements.has(id)) errors.push(`PRD section 3 requirement never mapped by the ledger: ${id}`);
  }
  for (const b of discovered.brokenLinks) errors.push(`broken documentation link in ${b.from}: ${b.target}`);
  return errors;
}

export function checkAdditionalTasks(ledger, discovered, prd, root = REPO_ROOT) {
  const errors = [];
  const tasks = Array.isArray(ledger.additionalRequiredTasks) ? ledger.additionalRequiredTasks : [];
  const ids = new Set();
  for (const t of tasks) {
    const where = `task ${t.id}`;
    if (!/^CORE-001-T\d{2}$/.test(t.id || '')) errors.push(`${where}: id must look like CORE-001-T01`);
    if (ids.has(t.id)) errors.push(`${where}: duplicate id`);
    ids.add(t.id);
    if (t.required !== true) errors.push(`${where}: discovered tasks must be required: true`);
    if (typeof t.version !== 'string' || !t.version) errors.push(`${where}: missing version`);
    if (!t.title || !t.reason) errors.push(`${where}: missing title or reason`);
    if (t.discoveredBy !== 'checkout-crawl') errors.push(`${where}: discoveredBy must be "checkout-crawl"`);
    if (!Array.isArray(t.acceptance) || t.acceptance.length === 0) errors.push(`${where}: no acceptance criteria`);
  }

  const mapped = new Map();
  for (const u of ledger.unindexedDocs || []) {
    mapped.set(u.path, u);
    if (!ids.has(u.taskId)) errors.push(`unindexed doc ${u.path}: taskId ${u.taskId} is not a ledger task`);
    if (!fs.existsSync(path.join(root, u.path))) errors.push(`unindexed doc listed but missing: ${u.path}`);
  }
  for (const p of discovered.unindexedDocs) {
    if (!mapped.has(p)) errors.push(`doc present in the checkout but neither linked from an index nor tracked: ${p}`);
  }
  for (const p of mapped.keys()) {
    if (!discovered.unindexedDocs.includes(p)) errors.push(`ledger tracks ${p} as unindexed, but it is now indexed or gone; update the ledger`);
  }

  for (const x of ledger.excludedDocPrefixes || []) {
    if (!x.prefix || typeof x.reason !== 'string' || x.reason.trim().length < 20) errors.push(`excluded prefix ${x.prefix}: needs a reason`);
    else if (!fs.existsSync(path.join(root, x.prefix))) errors.push(`excluded prefix does not exist: ${x.prefix}`);
  }

  const crawl = ledger.crawl || {};
  if (!ids.has(crawl.followUpTask)) errors.push('crawl.followUpTask must name a ledger task');
  if (!Number.isInteger(crawl.depth) || crawl.depth < 1) errors.push('crawl.depth must be a positive integer');

  const d = ledger.denominator || {};
  if (d.planningRequirements !== prd.ids.length) {
    errors.push(`denominator.planningRequirements ${d.planningRequirements} != PRD requirement count ${prd.ids.length}`);
  }
  if (d.additionalRequiredTasks !== tasks.length) {
    errors.push(`denominator.additionalRequiredTasks ${d.additionalRequiredTasks} != task count ${tasks.length}`);
  }
  if (d.frozenRequiredScope !== prd.ids.length + tasks.length) {
    errors.push(`denominator.frozenRequiredScope ${d.frozenRequiredScope} != ${prd.ids.length + tasks.length}`);
  }
  return errors;
}

const FORBIDDEN_KEYS = new Set(['measuredAt', 'freshMeasurement', 'measuredResult', 'measuredValue']);
const SOURCE_KINDS = new Set(['source-observation', 'documented-metric']);

function* walkJson(value, trail = '$') {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) yield* walkJson(value[i], `${trail}[${i}]`);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      yield { key: k, value: v, trail: `${trail}.${k}`, parent: value };
      yield* walkJson(v, `${trail}.${k}`);
    }
  }
}

export function checkBaselineSeparation(ledger, root = REPO_ROOT) {
  const errors = [];
  const base = Array.isArray(ledger.existingBehavior) ? ledger.existingBehavior : [];
  const baseIds = new Set();
  let sourceObservations = 0;
  for (const b of base) {
    const where = `baseline ${b.id}`;
    if (!/^BASE-\d{3}$/.test(b.id || '') || baseIds.has(b.id)) errors.push(`${where}: id must be unique BASE-nnn`);
    baseIds.add(b.id);
    if (!SOURCE_KINDS.has(b.kind)) errors.push(`${where}: unknown kind ${b.kind}`);
    if (b.measuredThisRun !== false) errors.push(`${where}: measuredThisRun must be false; this ledger measures nothing`);
    if (b.kind === 'documented-metric' && b.status !== 'documented-not-remeasured') {
      errors.push(`${where}: a documented metric must carry status "documented-not-remeasured"`);
    }
    if (b.kind === 'source-observation') sourceObservations++;
    if (!b.statement) errors.push(`${where}: missing statement`);
    if (!b.file || !fs.existsSync(path.join(root, b.file))) { errors.push(`${where}: file missing: ${b.file}`); continue; }
    if (b.expect !== 'present' && b.expect !== 'absent') { errors.push(`${where}: expect must be present or absent`); continue; }
    let re;
    try { re = new RegExp(b.pattern, b.flags || ''); } catch { errors.push(`${where}: bad pattern`); continue; }
    const holds = re.test(read(root, b.file)) === (b.expect === 'present');
    if (!holds) errors.push(`${where}: no longer true against the checkout (${b.file} ${b.expect} /${b.pattern}/); reconcile the ledger`);
  }
  if (sourceObservations < 6) errors.push(`expected at least 6 source observations reconciling the PRD baseline, found ${sourceObservations}`);

  for (const { key, value, trail, parent } of walkJson(ledger)) {
    if (FORBIDDEN_KEYS.has(key)) errors.push(`${trail}: ledger must not carry fresh-measurement field ${key}`);
    if (key === 'measuredThisRun' && value === true) errors.push(`${trail}: measuredThisRun true is not allowed`);
    if (key === 'status' && typeof value === 'string' && parent && parent.applicability === 'applicable'
        && value !== 'proposed') errors.push(`${trail}: proposed support may not claim "${value}"`);
  }
  for (const e of ledger.entries || []) {
    for (const ref of e.baselineRefs || []) {
      if (!baseIds.has(ref)) errors.push(`entry ${e.id}: baselineRef ${ref} does not exist`);
    }
  }
  return errors;
}
