// Repair recipes (verified-remediation PRD FR-11, section 6.6, M3-01, M3-02): a structural transformation with preconditions, a
// declared scope and its own evidence, under a signed, reviewable lifecycle.
//
// What a recipe is here. The TRANSFORMATION is code shipped with the scanner and registered by id below; a recipe document names one,
// declares where it applies (family, language, runtime and driver ranges), the preconditions it checks, the obligations a candidate it
// produces must pass, its examples (positive, safe-negative, unsupported-version, and independent held-out ones) and its
// contraindications. A document cannot carry code or a command: it can only narrow a registered transformation (fewer files, an extra
// contraindication), never widen it (AC-11.3). Every candidate a recipe proposes still goes through the scope gate and every obligation
// of the contract; a recipe is a proposer, never a verifier ("a merged PR alone is not evidence").
//
// Identity. `recipeDigest` covers the document AND the source text of its transformation, so a changed transformation is a different
// recipe. An evaluation records the recipe digest, every example fixture's digest and every obligation digest of the contract each
// example was judged against; promotion records the evaluation digest. A recipe is used automatically only when its latest promotion's
// evidence still matches what the code and fixtures are now (AC-11.4).
//
// Lifecycle. Shipped recipes start `shipped` (evaluated by this repository's own recipe gate, `bench/repair/recipes.mjs`) and are used
// automatically until the operator retires or rolls one back. An operator's draft starts `draft` and is used automatically only once
// `promoted`. Retiring or rolling back stops new automatic use; the ledger keeps every past record (AC-11.6). The ledger is append-only,
// hash-chained and signed with the per-install key, like the rule compiler's; a ledger that fails either check refuses every change.
//
// Not claimed: no recipe is learned from examples. The two transformations were written by hand; "generalization" below means a
// transformation verified on a held-out project it was not developed against, authored by the same people (synthetic evidence).
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { digestOf } from '../posture/assurance/identity.js';
import { statePath, ensureStateDir } from '../posture/state-dir.js';
import { signLastScan, verifyLastScan } from '../posture/integrity.js';
import { parameterizeTemplateSql } from './candidates.js';

export const RECIPE_SCHEMA = 'agentic-security/repair-recipe';
export const RECIPE_LEDGER_SCHEMA = 'agentic-security/repair-recipe-ledger';
export const RECIPE_STATES = Object.freeze(['shipped', 'draft', 'evaluated', 'promoted', 'retired', 'rolled-back']);
const EDGES = Object.freeze({
  shipped: ['evaluated', 'retired', 'rolled-back'], draft: ['evaluated', 'retired'], evaluated: ['promoted', 'draft', 'retired'],
  promoted: ['retired', 'rolled-back'], 'rolled-back': ['evaluated', 'retired'], retired: [],
});
const USABLE = new Set(['shipped', 'promoted']);

// ---------------------------------------------------------------- registered transformations

/**
 * Path containment: `const <v> = path.resolve|join(<root>, <parts>);` becomes `const <v> = containedPath(<root>, '<mode>', <parts>);`
 * and one helper is appended. The helper resolves links before checking containment; a path that would leave the root becomes the
 * root itself, so the read the application already makes fails (a directory cannot be read as a file) and its existing error handling
 * refuses the request. Preconditions, all required: `fs` and `path` are bound by those names; the variable's next use is a read
 * (`readFile` with a callback, `readFileSync` inside a try block, `createReadStream`, or `promises.readFile`) whose failure the code
 * already handles; the root argument is an identifier or a member expression, not a literal.
 */
const CONTAIN_HELPER = [
  '',
  '// Added by the path-realpath-containment recipe: the real path of the joined parts under `root`, links resolved. A path that would',
  '// leave the root becomes the root itself, so reading it fails (a directory is not a file) and the existing error handling refuses it.',
  'function containedPath(root, mode, ...parts) {',
  '  const base = fs.realpathSync(root);',
  "  const target = mode === 'join' ? path.join(base, ...parts.map(String)) : path.resolve(base, ...parts.map(String));",
  '  let real;',
  '  try { real = fs.realpathSync(target); } catch { real = target; }',
  '  return real.startsWith(base + path.sep) ? real : base;',
  '}',
  '',
].join('\n');

const BINDS_FS = /^\s*import\s+fs\s+from\s+['"](?:node:)?fs['"]|^\s*const\s+fs\s*=\s*require\(\s*['"](?:node:)?fs['"]\s*\)/m;
const BINDS_PATH = /^\s*import\s+path\s+from\s+['"](?:node:)?path['"]|^\s*const\s+path\s*=\s*require\(\s*['"](?:node:)?path['"]\s*\)/m;
const DECL = /^([ \t]*)const ([A-Za-z_$][\w$]*) = path\.(resolve|join)\(\s*([A-Za-z_$][\w$.]*)\s*,\s*([^;\n]+?)\s*\);[ \t]*$/gm;

export function containPathTransform(text) {
  const refused = [];
  if (!BINDS_FS.test(text) || !BINDS_PATH.test(text)) return { text, applied: 0, refused: ['fs and path are not bound by those names'] };
  if (/\bfunction\s+containedPath\s*\(/.test(text)) return { text, applied: 0, refused: ['a containedPath function already exists'] };
  let applied = 0;
  const out = text.replace(DECL, (whole, ind, v, mode, root, parts, offset) => {
    const rest = text.slice(offset + whole.length);
    const use = new RegExp(`\\bfs\\.(readFile|readFileSync|createReadStream|promises\\.readFile)\\(\\s*${v.replace(/\$/g, '\\$')}\\b([^\\n]*)`).exec(rest);
    if (!use) { refused.push(`${v}: its next use is not a file read this recipe can make fail`); return whole; }
    const before = text.slice(Math.max(0, offset - 400), offset) + rest.slice(0, use.index);
    const handled = use[1] === 'readFile' ? /\(\s*err\b/.test(use[2]) || /\(\s*err\b/.test(rest.slice(use.index, use.index + 200))
      : use[1] === 'createReadStream' ? /\.on\(\s*['"]error['"]/.test(rest.slice(use.index, use.index + 600))
        : /\btry\s*\{[^}]*$/.test(before) && /\bcatch\b/.test(rest.slice(use.index, use.index + 600));
    if (!handled) { refused.push(`${v}: the read's failure is not handled, so a refusal could not be expressed`); return whole; }
    applied++;
    return `${ind}const ${v} = containedPath(${root}, '${mode}', ${parts});`;
  });
  return applied ? { text: `${out.replace(/\s*$/, '\n')}${CONTAIN_HELPER}`, applied, refused } : { text, applied: 0, refused: refused.length ? refused : ['no path.resolve or path.join declaration matched'] };
}

export const TRANSFORMS = Object.freeze({
  'sql-parameterize-template': { family: 'sql-injection', apply: parameterizeTemplateSql, source: parameterizeTemplateSql.toString() },
  'path-realpath-containment': { family: 'path-traversal', apply: containPathTransform, source: containPathTransform.toString() + CONTAIN_HELPER },
});

// ---------------------------------------------------------------- shipped recipe documents

const FIX = 'test/fixtures/repair';
export const SHIPPED_RECIPES = Object.freeze([
  {
    schema: RECIPE_SCHEMA, recipeId: 'sql-parameterize-template', version: '2', transform: 'sql-parameterize-template',
    provenance: { origin: 'shipped', author: 'agentic-security maintainers', note: 'hand-written; not learned from examples' }, signer: 'shipped-with-scanner',
    supports: { family: 'sql-injection', languages: ['javascript'], runtime: { name: 'node', min: '22.5.0' }, driver: 'node:sqlite (prepare(sql).all|get|run|iterate with ? placeholders)', engine: 'sqlite' },
    preconditions: ['every interpolation sits exactly inside a single-quoted SQL literal', 'the statement is called immediately with no arguments', 'an interpolation in any other position (an identifier, a number, ORDER BY) is refused: a placeholder cannot carry it'],
    editScope: { maxFiles: 3, files: 'the contract\'s allowed files' },
    obligations: ['app-attack-blocked', 'app-attack-sealed', 'app-behaviour-preserved', 'app-behaviour-after', 'project-tests'],
    examples: [
      { id: 'notes', kind: 'positive', fixture: `${FIX}/sql-notes`, family: 'sql-injection', expect: 'verified-for-contract' },
      { id: 'tasks', kind: 'independent', fixture: `${FIX}/sql-tasks`, family: 'sql-injection', expect: 'verified-for-contract' },
      { id: 'sort-column', kind: 'safe-negative', fixture: `${FIX}/sql-sort`, entry: 'src/app.mjs', expect: 'refused' },
      { id: 'node-22.4', kind: 'unsupported-version', fixture: `${FIX}/sql-notes`, family: 'sql-injection', nodeVersion: '22.4.0', expect: 'not-applicable' },
    ],
    contraindications: ['a driver whose placeholder is not `?`', 'an identifier or keyword built from input'],
    rollback: 'retire the recipe: nothing it proposed was applied without its own verified record, and each applied patch has an apply-service backup',
  },
  {
    schema: RECIPE_SCHEMA, recipeId: 'path-realpath-containment', version: '1', transform: 'path-realpath-containment',
    provenance: { origin: 'shipped', author: 'agentic-security maintainers', note: 'hand-written; not learned from examples' }, signer: 'shipped-with-scanner',
    supports: { family: 'path-traversal', languages: ['javascript'], runtime: { name: 'node', min: '20.0.0' }, driver: 'node:fs and node:path bound as fs and path' },
    preconditions: ['fs and path are bound by those names', 'the joined path is declared with const from path.resolve or path.join of an identifier root', 'its next use is a read whose failure the code already handles'],
    editScope: { maxFiles: 1, files: 'the contract\'s allowed files' },
    obligations: ['app-attack-blocked', 'app-attack-sealed', 'app-behaviour-preserved', 'project-tests'],
    examples: [
      { id: 'downloads', kind: 'positive', fixture: `${FIX}/files-download`, family: 'path-traversal', expect: 'verified-for-contract' },
      { id: 'avatars', kind: 'independent', fixture: `${FIX}/avatar-store`, family: 'path-traversal', expect: 'verified-for-contract' },
      { id: 'unhandled-read', kind: 'safe-negative', text: "import fs from 'node:fs';\nimport path from 'node:path';\nexport const read = (root, n) => {\n  const p = path.join(root, n);\n  return fs.readFileSync(p, 'utf8');\n};\n", expect: 'refused' },
      { id: 'node-18', kind: 'unsupported-version', fixture: `${FIX}/files-download`, family: 'path-traversal', nodeVersion: '18.19.0', expect: 'not-applicable' },
    ],
    contraindications: ['an application that must serve links pointing outside its root', 'a read whose error handling reveals the reason'],
    rollback: 'retire the recipe; applied patches have apply-service backups',
  },
]);

const RECIPE_FIELDS = ['schema', 'recipeId', 'version', 'transform', 'provenance', 'signer', 'supports', 'preconditions', 'editScope', 'obligations', 'examples', 'contraindications', 'rollback'];

export function validateRecipe(r) {
  const errs = [];
  if (!r || typeof r !== 'object' || Array.isArray(r)) return ['a recipe must be an object'];
  for (const k of Object.keys(r)) if (!RECIPE_FIELDS.includes(k)) errs.push(`unknown field '${k}'`);
  if (r.schema !== RECIPE_SCHEMA) errs.push(`schema must be '${RECIPE_SCHEMA}'`);
  if (typeof r.recipeId !== 'string' || !/^[a-z][a-z0-9-]{2,63}$/.test(r.recipeId)) errs.push('recipeId must be a slug');
  if (typeof r.version !== 'string' || !/^\d{1,4}(?:\.\d{1,4}){0,2}$/.test(r.version)) errs.push('version must be a dotted number');
  const t = TRANSFORMS[r.transform];
  if (!t) errs.push(`transform must be one of ${Object.keys(TRANSFORMS).join(', ')}: a recipe document cannot carry code`);
  if (t && r.supports?.family !== t.family) errs.push(`supports.family must be ${t?.family}`);
  // a document may narrow a shipped recipe of the same transformation, never widen it
  const base = SHIPPED_RECIPES.find((s) => s.transform === r.transform);
  if (base && (!Number.isInteger(r.editScope?.maxFiles) || r.editScope.maxFiles > base.editScope.maxFiles || r.editScope.maxFiles < 1)) errs.push(`editScope.maxFiles must be 1 to ${base.editScope.maxFiles}`);
  if (base && JSON.stringify(r.supports?.runtime) !== JSON.stringify(base.supports.runtime) && !(r.supports?.runtime?.name === 'node' && cmpVersion(r.supports.runtime.min, base.supports.runtime.min) >= 0)) errs.push('supports.runtime may only raise the minimum version');
  if (!Array.isArray(r.examples) || !r.examples.length) errs.push('examples must list at least one example');
  else for (const e of r.examples) if (!['positive', 'independent', 'safe-negative', 'unsupported-version', 'mutation'].includes(e?.kind)) errs.push(`example ${e?.id}: unknown kind`);
  if (!Array.isArray(r.obligations) || !r.obligations.includes('project-tests')) errs.push('obligations must include project-tests');
  return errs;
}

const cmpVersion = (a, b) => {
  const pa = String(a).split('.').map(Number); const pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
};

/** The recipe's identity: the document and the source of its transformation. */
export const recipeDigest = (r) => digestOf({ doc: r, transform: digestOf(TRANSFORMS[r.transform]?.source || '') });

/** Does this recipe apply to this contract on this runtime? Returns {ok, reasons}. Pure. */
export function applicability(recipe, contract, { nodeVersion = process.versions.node } = {}) {
  const reasons = [];
  if (contract.family !== recipe.supports.family) reasons.push(`the recipe repairs ${recipe.supports.family}, not ${contract.family}`);
  if ((contract.profile?.runtime || 'node') !== recipe.supports.runtime.name) reasons.push(`the recipe supports the ${recipe.supports.runtime.name} runtime only`);
  else if (cmpVersion(nodeVersion, recipe.supports.runtime.min) < 0) reasons.push(`node ${nodeVersion} is below the supported ${recipe.supports.runtime.min}`);
  if (recipe.supports.engine && contract.profile?.database?.engine !== recipe.supports.engine) reasons.push(`the recipe supports the ${recipe.supports.engine} driver only`);
  return { ok: reasons.length === 0, reasons };
}

/** A recipe as a proposer: one candidate in round 1, over at most `editScope.maxFiles` of the contract's allowed files. */
export function recipeProposer(recipe, { nodeVersion } = {}) {
  const t = TRANSFORMS[recipe.transform];
  const identity = `${recipe.recipeId}@${recipe.version}#${recipeDigest(recipe).slice(7, 19)}`;
  return {
    id: identity,
    async propose({ contract, files, round }) {
      if (round !== 1) return { proposals: [], notes: [] };
      const a = applicability(recipe, contract, { nodeVersion });
      if (!a.ok) return { proposals: [], notes: a.reasons.map((x) => `${recipe.recipeId}: ${x}`) };
      const out = {}; const notes = [];
      for (const rel of contract.editScope.allowed) {
        if (!/\.(?:m?js|cjs|ts)$/.test(rel) || typeof files[rel] !== 'string') continue;
        const r = t.apply(files[rel]);
        if (r.applied) out[rel] = r.text;
        notes.push(...r.refused.map((x) => `${rel} ${x}`));
      }
      const changed = Object.keys(out);
      if (!changed.length) return { proposals: [], notes: notes.length ? notes : [`${recipe.recipeId}: the recipe matched nothing`] };
      if (changed.length > recipe.editScope.maxFiles) return { proposals: [], notes: [`${recipe.recipeId}: the recipe would change ${changed.length} files, more than its scope of ${recipe.editScope.maxFiles}`] };
      return { proposals: [{ generator: 'deterministic-recipe', generatorIdentity: identity, files: out, strategy: recipe.recipeId, rationale: recipe.preconditions.join('; ') }], notes };
    },
  };
}

// ---------------------------------------------------------------- the signed lifecycle ledger

const ledgerFile = (root) => statePath(root, 'repair-recipes', 'ledger.json');
const hashOf = (e) => crypto.createHash('sha256').update(JSON.stringify(e)).digest('hex');

function verifyChain(ledger) {
  let prev = null;
  for (const [i, e] of ledger.entries.entries()) {
    const { hash, ...rest } = e;
    if (rest.prev !== prev) return { ok: false, reason: `entry ${i} does not link the previous entry` };
    if (hashOf(rest) !== hash) return { ok: false, reason: `entry ${i} was modified` };
    prev = hash;
  }
  return { ok: true };
}

/** The ledger, verified: hash chain and the per-install signature. A ledger failing either is returned with `tampered`. */
export function loadRecipeLedger(root) {
  const f = ledgerFile(root);
  let text; let ledger;
  try { text = fs.readFileSync(f, 'utf8'); } catch (e) {
    if (e?.code === 'ENOENT') return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {} };
    return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {}, tampered: true, tamperReason: `the ledger cannot be read: ${String(e.message).slice(0, 80)}` };
  }
  try { ledger = JSON.parse(text); } catch (e) { return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {}, tampered: true, tamperReason: `the ledger cannot be read: ${String(e.message).slice(0, 80)}` }; }
  if (!Array.isArray(ledger?.entries)) return { schema: RECIPE_LEDGER_SCHEMA, entries: [], drafts: {}, tampered: true, tamperReason: 'the ledger has no entries' };
  const v = verifyChain(ledger);
  if (!v.ok) return { ...ledger, tampered: true, tamperReason: v.reason };
  if (verifyLastScan(text, `${f}.sig`) !== true) return { ...ledger, tampered: true, tamperReason: 'the ledger signature does not verify under this installation\'s key' };
  return { drafts: {}, ...ledger };
}

function saveRecipeLedger(root, ledger) {
  if (ledger.tampered) throw new Error(`refusing to write a ledger that failed verification: ${ledger.tamperReason}`);
  ensureStateDir(root);
  const f = ledgerFile(root);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  const text = `${JSON.stringify({ schema: RECIPE_LEDGER_SCHEMA, entries: ledger.entries, drafts: ledger.drafts || {} }, null, 2)}\n`;
  const tmp = `${f}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, f);
  fs.writeFileSync(`${f}.sig`, signLastScan(text));
}

/** Every recipe the ledger knows: shipped documents plus operator drafts. */
export function allRecipes(ledger) {
  return [...SHIPPED_RECIPES, ...Object.values(ledger.drafts || {})];
}

export function stateOf(ledger, recipe) {
  for (let i = ledger.entries.length - 1; i >= 0; i--) {
    const e = ledger.entries[i];
    if (e.recipeId === recipe.recipeId && e.version === recipe.version) return { state: e.to, entry: e };
  }
  return { state: recipe.provenance?.origin === 'shipped' ? 'shipped' : 'draft', entry: null };
}

/**
 * Record a transition the caller decided. Refuses an edge not in the lifecycle, a promotion without an evaluation of THIS recipe digest
 * that passed every example, and any change to a tampered ledger. Never throws.
 */
export function transition(root, recipe, to, { reason, actor, evaluation = null }) {
  const ledger = loadRecipeLedger(root);
  if (ledger.tampered) return { ok: false, reason: ledger.tamperReason };
  if (!reason || !String(reason).trim()) return { ok: false, reason: 'a reason is required' };
  const { state, entry } = stateOf(ledger, recipe);
  if (!(EDGES[state] || []).includes(to)) return { ok: false, reason: `${recipe.recipeId}@${recipe.version} cannot go from ${state} to ${to}` };
  const digest = recipeDigest(recipe);
  let evidence = null;
  if (to === 'evaluated') {
    if (!evaluation?.ok || evaluation.recipeDigest !== digest) return { ok: false, reason: 'an evaluation of this exact recipe in which every example met its expectation is required' };
    evidence = evaluation.evaluationDigest;
  }
  if (to === 'promoted') {
    if (!entry || entry.to !== 'evaluated' || entry.recipeDigest !== digest) return { ok: false, reason: 'the recipe changed since it was evaluated: evaluate it again' };
    evidence = entry.evidence;
  }
  const rest = { recipeId: recipe.recipeId, version: recipe.version, recipeDigest: digest, from: state, to, reason: String(reason).slice(0, 500), actor: String(actor || os.userInfo().username || 'operator').slice(0, 80), evidence, prev: ledger.entries.length ? ledger.entries[ledger.entries.length - 1].hash : null };
  ledger.entries.push({ ...rest, hash: hashOf(rest) });
  try { saveRecipeLedger(root, ledger); } catch (e) { return { ok: false, reason: String(e.message).slice(0, 200) }; }
  return { ok: true, from: state, to };
}

/** Add an operator draft (a narrowed document over a registered transformation). */
export function draftRecipe(root, doc, { reason, actor }) {
  const errs = validateRecipe(doc);
  if (errs.length) return { ok: false, reason: errs.join('; ') };
  if (doc.provenance?.origin === 'shipped' || SHIPPED_RECIPES.some((s) => s.recipeId === doc.recipeId && s.version === doc.version)) return { ok: false, reason: 'a draft cannot reuse a shipped recipe id and version, or claim shipped provenance' };
  const ledger = loadRecipeLedger(root);
  if (ledger.tampered) return { ok: false, reason: ledger.tamperReason };
  const key = `${doc.recipeId}@${doc.version}`;
  if (ledger.drafts?.[key]) return { ok: false, reason: `${key} already exists; drafts are immutable, draft a new version` };
  ledger.drafts = { ...(ledger.drafts || {}), [key]: doc };
  const rest = { recipeId: doc.recipeId, version: doc.version, recipeDigest: recipeDigest(doc), from: null, to: 'draft', reason: String(reason || 'drafted').slice(0, 500), actor: String(actor || 'operator').slice(0, 80), evidence: null, prev: ledger.entries.length ? ledger.entries[ledger.entries.length - 1].hash : null };
  ledger.entries.push({ ...rest, hash: hashOf(rest) });
  try { saveRecipeLedger(root, ledger); } catch (e) { return { ok: false, reason: String(e.message).slice(0, 200) }; }
  return { ok: true };
}

/**
 * The recipes a run may use automatically for a family: shipped ones that are not retired or rolled back, and promoted ones whose
 * promotion evidence names the recipe as it is now. A tampered ledger allows nothing but is reported.
 */
export function usableRecipes(root, family) {
  const ledger = loadRecipeLedger(root);
  if (ledger.tampered) return { recipes: [], notes: [`the recipe ledger failed verification (${ledger.tamperReason}); no recipe is used`] };
  const recipes = []; const notes = [];
  for (const r of allRecipes(ledger).filter((x) => x.supports?.family === family)) {
    const { state, entry } = stateOf(ledger, r);
    if (!USABLE.has(state)) { notes.push(`${r.recipeId}@${r.version} is ${state}: not used`); continue; }
    if (state === 'promoted' && entry.recipeDigest !== recipeDigest(r)) { notes.push(`${r.recipeId}@${r.version} changed after promotion: not used`); continue; }
    recipes.push(r);
  }
  return { recipes, notes };
}

// ---------------------------------------------------------------- evaluation

/**
 * Evaluate a recipe on its examples. Positive and independent examples are planned and run through the full coordinator with the recipe
 * as the only proposer and must be `verified-for-contract`; a safe-negative must be refused by the transformation; an unsupported version
 * must be not-applicable. `deps.run({recipe, example, root})` performs a positive run (injected so this module adds no execution path).
 * Returns the evaluation with a digest over the recipe digest, every fixture digest and every obligation digest.
 */
export async function evaluateRecipe(recipe, { repoRoot, run }) {
  const errs = validateRecipe(recipe);
  if (errs.length) return { ok: false, recipeId: recipe?.recipeId, problems: errs };
  const results = [];
  for (const ex of recipe.examples) {
    const dir = ex.fixture ? path.resolve(repoRoot, ex.fixture) : null;
    if (dir && !fs.existsSync(dir)) { results.push({ id: ex.id, kind: ex.kind, expect: ex.expect, outcome: 'example-unavailable', ok: false }); continue; }
    const fixtureDigest = dir ? digestOf(readTree(dir)) : digestOf(ex.text || '');
    let outcome; let obligations = null; let detail = null;
    if (ex.kind === 'safe-negative') {
      const text = ex.text ?? fs.readFileSync(path.join(dir, ex.entry), 'utf8');
      const r = TRANSFORMS[recipe.transform].apply(text);
      outcome = r.applied ? 'applied' : 'refused';
      detail = r.refused.slice(0, 3);
    } else if (ex.kind === 'unsupported-version') {
      const r = await run({ recipe, example: ex, dir, planOnly: true });
      const a = applicability(recipe, r.contract, { nodeVersion: ex.nodeVersion });
      outcome = a.ok ? 'applicable' : 'not-applicable';
      detail = a.reasons;
    } else {
      const r = await run({ recipe, example: ex, dir });
      outcome = r.disposition;
      obligations = r.obligationDigests;
      detail = r.reasons?.slice(0, 3) || null;
    }
    results.push({ id: ex.id, kind: ex.kind, expect: ex.expect, outcome, ok: outcome === ex.expect, fixtureDigest, ...(obligations ? { obligations } : {}), ...(detail ? { detail } : {}) });
  }
  const digest = recipeDigest(recipe);
  const evaluation = { recipeId: recipe.recipeId, version: recipe.version, recipeDigest: digest, results, ok: results.every((r) => r.ok) };
  evaluation.evaluationDigest = digestOf({ recipeDigest: digest, results: results.map(({ id, outcome, fixtureDigest, obligations }) => ({ id, outcome, fixtureDigest, obligations: obligations ?? null })) });
  return evaluation;
}

function readTree(dir) {
  const out = {};
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r);
      else if (e.isFile()) out[r] = fs.readFileSync(path.join(d, e.name), 'utf8');
    }
  };
  walk(dir, '');
  return out;
}
