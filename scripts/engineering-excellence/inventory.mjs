#!/usr/bin/env node
// Repository inventory for the Engineering Excellence program (E0-01).
//   node inventory.mjs --check             verify the capability map against the checkout; exit 1 on any problem
//   node inventory.mjs --verify [--only id,id]   run each capability's declared tests (bounded) and record the results
//   node inventory.mjs --render            write docs/engineering-excellence/INVENTORY.md and inventory.json
//   node inventory.mjs --facts             print the mechanical facts as JSON
//
// Mechanical facts (counts, versions, command lists) are computed from the checkout. The capability map in data/capabilities.json is
// curated, but it is checked: every listed path must exist, every capability needs source, and a maturity of VERIFIED is only ever
// computed from a recorded passing test run at this version, never written by hand.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import * as os from 'node:os';
import { atomicWriteFile, atomicWriteJson, nowIso } from '../loop-engineering/lib/util.mjs';
import { runBounded } from '../loop-engineering/lib/proc.mjs';
import { REPO_ROOT } from './lib/model.mjs';
import { checkoutInfo } from './lib/store.mjs';

export const MATURITY = Object.freeze(['ABSENT', 'EXISTS-UNVERIFIED', 'PARTIAL', 'VERIFIED', 'BLOCKED']);
const DATA = (root) => join(root, 'scripts', 'engineering-excellence', 'data');
const VERIFICATION = (root) => join(DATA(root), 'inventory.verification.json');
const OUT_DIR = (root) => join(root, 'docs', 'engineering-excellence');

const git = (root, args) => { try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024, timeout: 60000 }); } catch { return ''; } };
const readJson = (p, fb = null) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return fb; } };

export function loadCapabilities(root = REPO_ROOT) {
  const doc = readJson(join(DATA(root), 'capabilities.json'));
  if (!doc || !Array.isArray(doc.capabilities)) throw new Error('data/capabilities.json is missing or malformed');
  return doc;
}

export function loadVerification(root = REPO_ROOT) {
  return readJson(VERIFICATION(root), { schemaVersion: 1, results: {} });
}

// ---- mechanical facts --------------------------------------------------------------------------------------------------

function countBy(lines, keyFn) {
  const m = new Map();
  for (const l of lines) { const k = keyFn(l); if (k) m.set(k, (m.get(k) || 0) + 1); }
  return Object.fromEntries([...m.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
}

/** The tools the server really registers (ALL_TOOLS), read by loading the module in a child process. Null when it cannot be loaded. */
function registeredMcpTools(root) {
  const mod = join(root, 'scanner', 'src', 'mcp', 'tools.js');
  if (!existsSync(mod)) return null;
  try {
    const out = execFileSync(process.execPath, ['--input-type=module', '-e', `import(${JSON.stringify(`file://${mod}`)}).then((m) => console.log(JSON.stringify(m.ALL_TOOLS.map((t) => t.name))))`], { cwd: join(root, 'scanner'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000 });
    const names = JSON.parse(out.trim().split('\n').pop());
    return { count: names.length, names };
  } catch { return null; }
}

export function collectFacts(root = REPO_ROOT) {
  const pkg = readJson(join(root, 'scanner', 'package.json'), {});
  const files = git(root, ['ls-files']).split('\n').filter(Boolean);
  const srcFiles = files.filter((f) => f.startsWith('scanner/src/') && f.endsWith('.js'));
  const testFiles = files.filter((f) => /^scanner\/test\/.*\.test\.js$/.test(f));
  const scripts = pkg.scripts || {};
  const bin = existsSync(join(root, 'scanner/bin/agentic-security.js')) ? readFileSync(join(root, 'scanner/bin/agentic-security.js'), 'utf8') : '';
  const cliCommands = [...new Set([...bin.matchAll(/case '([a-z][a-z0-9-]+)'/g)].map((m) => m[1]))].filter((c) => !['critical', 'high', 'medium', 'low', 'none', 'help', 'version', 'banner'].includes(c)).sort();
  const mcpDir = join(root, 'scanner/src/mcp');
  const mcpTools = {};
  if (existsSync(mcpDir)) for (const f of readdirSync(mcpDir).filter((x) => x.endsWith('.js'))) {
    const names = [...readFileSync(join(mcpDir, f), 'utf8').matchAll(/^\s*name: '([a-z_]+)'/gm)].map((m) => m[1]);
    if (names.length) mcpTools[f] = names;
  }
  const benchDirs = existsSync(join(root, 'bench')) ? readdirSync(join(root, 'bench'), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort() : [];
  const info = checkoutInfo(root);
  return {
    generatedAt: nowIso(),
    commit: info.commit, branch: info.branch, worktreeDirty: info.dirty,
    version: pkg.version || null,
    package: pkg.name || null,
    engines: pkg.engines || null,
    node: process.version, platform: `${os.platform()} ${os.arch()}`, cpus: os.cpus().length, memoryGb: Math.round(os.totalmem() / 2 ** 30),
    sourceFilesByDir: countBy(srcFiles, (f) => (f.split('/').length > 3 ? f.split('/')[2] : '(top level)')),
    sourceFileCount: srcFiles.length,
    testFileCount: testFiles.length,
    testFilesByDir: countBy(testFiles, (f) => (f.split('/').length > 3 ? f.split('/')[2] : '(top level)')),
    npmScripts: { total: Object.keys(scripts).length, test: Object.keys(scripts).filter((s) => s.startsWith('test')).length, bench: Object.keys(scripts).filter((s) => s.startsWith('bench')).length },
    scopedTestScripts: Object.keys(scripts).filter((s) => s.startsWith('test:')).sort(),
    cliCommands,
    mcpTools,
    mcpToolCount: Object.values(mcpTools).flat().length,
    mcpToolsRegistered: registeredMcpTools(root),
    slashCommandFiles: files.filter((f) => /^commands\/[^/]+\.md$/.test(f)).length,
    agentFiles: files.filter((f) => /^agents\/[^/]+\.md$/.test(f)).length,
    benchDirs,
    docsFiles: files.filter((f) => f.startsWith('docs/')).length,
    claudeMdFiles: files.filter((f) => /(^|\/)CLAUDE\.md$/.test(f)),
  };
}

/** Headline claims in the docs that the checkout can be asked about. Each is {doc, claim, expected, actual, ok}. */
export function checkClaims(root, facts) {
  const out = [];
  const claim = (doc, text, expected, actual) => out.push({ doc, claim: text, expected, actual, ok: String(expected) === String(actual) });
  const read = (rel) => (existsSync(join(root, rel)) ? readFileSync(join(root, rel), 'utf8') : '');
  const ver = facts.version;
  const rootClaude = read('CLAUDE.md');
  claim('CLAUDE.md', 'Version line', ver, (/\*\*Version:\*\*\s*([\d.]+)/.exec(rootClaude) || [])[1] || null);
  claim('README.md', 'version badge', ver, (/badge\/version-([\d.]+)-/.exec(read('README.md')) || [])[1] || null);
  claim('.claude-plugin/plugin.json', 'version', ver, readJson(join(root, '.claude-plugin/plugin.json'), {}).version || null);
  claim('gemini-extension.json', 'version', ver, readJson(join(root, 'gemini-extension.json'), {}).version || null);
  const m = /17 dispatchers/.exec(rootClaude);
  if (m) claim('CLAUDE.md', 'slash command dispatchers ("17 dispatchers")', 17, facts.slashCommandFiles);
  // MCP tool count: every document that states one is compared with what the server registers
  const registered = facts.mcpToolsRegistered ? facts.mcpToolsRegistered.count : facts.mcpToolCount;
  for (const doc of ['CLAUDE.md', 'docs/ARCHITECTURE.md', 'docs/HARNESS_COMPATIBILITY.md', '.codex-plugin/plugin.json', '.cursor-plugin/plugin.json']) {
    const t = /(\d+) (?:MCP )?tools/.exec(read(doc));
    if (t) claim(doc, `MCP tool count ("${t[0]}")`, Number(t[1]), registered);
  }
  return out;
}

// ---- verification runs ---------------------------------------------------------------------------------------------------

function parseNodeTestCounts(text) {
  const g = (k) => { const m = new RegExp(`^ℹ ${k} (\\d+)`, 'm').exec(text); return m ? Number(m[1]) : null; };
  return { tests: g('tests'), pass: g('pass'), fail: g('fail'), skipped: g('skipped') };
}

export async function verifyCapability(root, cap, { timeoutMs = 10 * 60 * 1000, log = true } = {}) {
  const files = cap.tests.map((t) => relative(join(root, 'scanner'), join(root, t)));
  const info = checkoutInfo(root);
  const logAbs = join(root, 'scripts', 'engineering-excellence', 'logs', 'E0-01', `inventory-${cap.id}.log`);
  mkdirSync(dirname(logAbs), { recursive: true });
  const res = await runBounded({ argv: [process.execPath, '--test', '--test-concurrency=2', ...files], cwd: join(root, 'scanner'), wallMs: timeoutMs, logPath: log ? logAbs : undefined, redactLog: true, label: `inventory:${cap.id}`, runId: 'ee-inventory' });
  const counts = parseNodeTestCounts(`${res.stdoutTail}\n${res.stderrTail}`);
  let logSha256 = null;
  try { logSha256 = createHash('sha256').update(readFileSync(logAbs)).digest('hex'); } catch { /* no log */ }
  return {
    capability: cap.id, files: cap.tests, argv: ['node', '--test', '--test-concurrency=2', ...files], cwd: 'scanner',
    outcome: res.outcome, exitCode: res.exitCode, durationMs: res.durationMs, counts,
    log: relative(root, logAbs), logSha256, ranAt: res.endedAt, commit: info.commit, worktreeDirty: info.dirty, version: readJson(join(root, 'scanner/package.json'), {}).version,
  };
}

export async function verifyAll(root = REPO_ROOT, { only = null, timeoutMs, onResult = () => {} } = {}) {
  const doc = loadCapabilities(root);
  const store = loadVerification(root);
  for (const cap of doc.capabilities) {
    if (only && !only.includes(cap.id)) continue;
    if (!cap.tests.length) { delete store.results[cap.id]; continue; }
    const r = await verifyCapability(root, cap, { timeoutMs });
    store.results[cap.id] = r;
    onResult(r);
    atomicWriteJson(VERIFICATION(root), store); // checkpoint after every capability: an interrupted run resumes with --only
  }
  return store;
}

// ---- classification and rendering ------------------------------------------------------------------------------------

/** Maturity of one capability, computed from the checkout and the recorded run. Returns { maturity, reasons[] }. */
export function classify(root, cap, verification, version) {
  const reasons = [];
  const missing = cap.source.filter((s) => !existsSync(join(root, s)));
  if (missing.length === cap.source.length) return { maturity: 'ABSENT', reasons: [`none of the listed source paths exist: ${missing.join(', ')}`] };
  const r = verification.results[cap.id];
  if (!cap.tests.length) return { maturity: 'EXISTS-UNVERIFIED', reasons: ['no executable test is mapped to this capability'] };
  if (!r) return { maturity: 'EXISTS-UNVERIFIED', reasons: ['its tests have not been run for this inventory'] };
  if (r.version !== version) return { maturity: 'EXISTS-UNVERIFIED', reasons: [`its recorded test run is for ${r.version}, not ${version}`] };
  if (r.outcome !== 'exited' || r.exitCode !== 0 || !r.counts || !(r.counts.pass > 0) || r.counts.fail) {
    return { maturity: 'BLOCKED', reasons: [`its tests did not pass (${r.outcome}${r.exitCode == null ? '' : `, exit ${r.exitCode}`}${r.counts && r.counts.fail ? `, ${r.counts.fail} failing` : ''}); see ${r.log}`] };
  }
  if (cap.partial) return { maturity: 'PARTIAL', reasons: [cap.partial] };
  return { maturity: 'VERIFIED', reasons: [`${r.counts.pass} tests passed in ${r.files.length} file(s) at ${(r.commit || '').slice(0, 10)}`] };
}

export function problems(root = REPO_ROOT) {
  const out = [];
  const doc = loadCapabilities(root);
  const seen = new Set();
  for (const cap of doc.capabilities) {
    if (seen.has(cap.id)) out.push(`duplicate capability id ${cap.id}`);
    seen.add(cap.id);
    if (!cap.source.length) out.push(`${cap.id}: no source listed`);
    for (const p of [...cap.source, ...cap.tests, ...(cap.docs || [])]) if (!existsSync(join(root, p))) out.push(`${cap.id}: listed path does not exist: ${p}`);
    for (const t of cap.tests) if (!/\.test\.(m?js)$/.test(t)) out.push(`${cap.id}: ${t} is not a test file`);
  }
  return out;
}

export function absentFindings(root, doc) {
  return (doc.absent || []).map((a) => {
    const hits = [];
    for (const term of a.terms) {
      const files = git(root, ['grep', '-l', '-F', '-e', term, '--', 'scanner/src', 'scripts', 'bench']).split('\n').filter(Boolean).filter((f) => !f.startsWith('scripts/engineering-excellence/'));
      if (files.length) hits.push({ term, files: files.slice(0, 3) });
    }
    return { ...a, status: hits.length ? 'FOUND-ELSEWHERE' : 'ABSENT', hits };
  });
}

export function buildInventory(root = REPO_ROOT) {
  const facts = collectFacts(root);
  const doc = loadCapabilities(root);
  const verification = loadVerification(root);
  const caps = doc.capabilities.map((c) => ({ ...c, ...classify(root, c, verification, facts.version), run: verification.results[c.id] || null }));
  const counts = Object.fromEntries(MATURITY.map((m) => [m, caps.filter((c) => c.maturity === m).length]));
  return { schemaVersion: 1, facts, capabilities: caps, maturityCounts: counts, absent: absentFindings(root, doc), claims: checkClaims(root, facts), problems: problems(root) };
}

export function renderMarkdown(inv) {
  const f = inv.facts;
  const L = [];
  L.push('# Repository inventory', '');
  L.push('> Generated by `node scripts/engineering-excellence/inventory.mjs --render` from the checkout and `scripts/engineering-excellence/data/`. Maturity labels are computed from recorded test runs; they are not edited by hand.', '');
  L.push(`- Package: \`${f.package}\` **${f.version}**, Node ${f.node} on ${f.platform} (${f.cpus} CPUs, ${f.memoryGb} GB)`);
  L.push(`- Commit: \`${f.commit}\` on \`${f.branch}\`; worktree ${f.worktreeDirty ? '**dirty** at generation (not release evidence)' : 'clean'}`);
  L.push(`- Source: ${f.sourceFileCount} JavaScript files under scanner/src; tests: ${f.testFileCount} test files; npm scripts: ${f.npmScripts.total} (${f.npmScripts.test} test, ${f.npmScripts.bench} bench)`);
  L.push(`- CLI commands (cases in bin): ${f.cliCommands.length}; MCP tools registered at runtime: ${f.mcpToolsRegistered ? f.mcpToolsRegistered.count : 'unknown'} (${f.mcpToolCount} declarations in source); slash command files: ${f.slashCommandFiles}; agent prompts: ${f.agentFiles}; benches: ${f.benchDirs.length}`, '');
  L.push('## Maturity', '', '| Label | Capabilities |', '|---|---|');
  for (const m of MATURITY) L.push(`| ${m} | ${inv.maturityCounts[m]} |`);
  L.push('', 'Labels: **VERIFIED** = source present and every mapped test passed at this version; **PARTIAL** = verified, with a stated gap against the program PRD; **EXISTS-UNVERIFIED** = source present but tests not run or not mapped; **BLOCKED** = tests did not pass; **ABSENT** = no source.', '');
  L.push('## Capabilities', '', '| Capability | Maturity | Source | Tests | Notes |', '|---|---|---|---|---|');
  for (const c of inv.capabilities) {
    L.push(`| ${c.name} (\`${c.id}\`; ${c.epics.join(', ')}) | ${c.maturity} | ${c.source.map((s) => `\`${s}\``).join('<br>')} | ${c.tests.length ? c.tests.map((s) => `\`${s}\``).join('<br>') : 'none mapped'} | ${c.reasons.join(' ').replace(/\|/g, '/')} |`);
  }
  L.push('', '## PRD items searched for and not found', '', 'Each row names the search terms; the generator re-runs them (`git grep` over scanner/src, scripts and bench, excluding this program\'s own tooling) so the claim is reproducible.', '', '| Item | Status | Terms | Note |', '|---|---|---|---|');
  for (const a of inv.absent) L.push(`| ${a.name} | ${a.status} | ${a.terms.map((t) => `\`${t}\``).join(', ')} | ${a.status === 'FOUND-ELSEWHERE' ? `found in ${[...new Set(a.hits.flatMap((h) => h.files))].slice(0, 3).join(', ')}. ${a.note}` : a.note} |`);
  L.push('', '## Documentation claims checked against the checkout', '', '| Document | Claim | Expected | Actual | Result |', '|---|---|---|---|---|');
  for (const c of inv.claims) L.push(`| \`${c.doc}\` | ${c.claim} | ${c.expected} | ${c.actual} | ${c.ok ? 'matches' : '**MISMATCH**'} |`);
  L.push('', '## Source files by directory', '', '| Directory | Files |', '|---|---|');
  for (const [k, v] of Object.entries(f.sourceFilesByDir)) L.push(`| scanner/src/${k} | ${v} |`);
  L.push('', '## CLI commands', '', f.cliCommands.map((c) => `\`${c}\``).join(', '), '');
  L.push('## MCP tools declared', '');
  for (const [file, names] of Object.entries(f.mcpTools)) L.push(`- \`${file}\`: ${names.map((n) => `\`${n}\``).join(', ')}`);
  L.push('', '## Scoped test scripts', '', f.scopedTestScripts.map((s) => `\`${s}\``).join(', '), '');
  L.push('## Benchmarks', '', f.benchDirs.map((b) => `\`bench/${b}\``).join(', '), '');
  return L.join('\n');
}

export function render(root = REPO_ROOT) {
  const inv = buildInventory(root);
  mkdirSync(OUT_DIR(root), { recursive: true });
  atomicWriteFile(join(OUT_DIR(root), 'INVENTORY.md'), renderMarkdown(inv) + '\n', 0o644);
  const { generatedAt, ...stableFacts } = inv.facts;
  void generatedAt;
  atomicWriteJson(join(OUT_DIR(root), 'inventory.json'), { ...inv, facts: { ...stableFacts, generatedAt } });
  return inv;
}

const arg = (a, k) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : null; };
if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const root = a.includes('--root') ? resolve(arg(a, '--root')) : REPO_ROOT;
  (async () => {
    if (a.includes('--facts')) { console.log(JSON.stringify(collectFacts(root), null, 2)); return 0; }
    if (a.includes('--verify')) {
      const only = arg(a, '--only');
      const store = await verifyAll(root, { only: only ? only.split(',') : null, timeoutMs: Number(arg(a, '--timeout-ms')) || undefined, onResult: (r) => console.log(`${r.capability}: ${r.outcome} exit ${r.exitCode} ${r.counts ? `pass ${r.counts.pass} fail ${r.counts.fail}` : ''} (${r.durationMs} ms)`) });
      return Object.values(store.results).every((r) => r.exitCode === 0) ? 0 : 1;
    }
    if (a.includes('--render')) { const inv = render(root); console.log(`inventory: ${inv.capabilities.length} capabilities; ${Object.entries(inv.maturityCounts).map(([k, v]) => `${v} ${k}`).join(', ')}; ${inv.problems.length} problem(s); ${inv.claims.filter((c) => !c.ok).length} claim mismatch(es)`); return inv.problems.length ? 1 : 0; }
    const p = problems(root);
    for (const x of p) console.error(`inventory: ${x}`);
    if (!p.length) console.log('inventory: capability map is consistent with the checkout');
    return p.length ? 1 : 0;
  })().then((c) => process.exit(c)).catch((e) => { console.error(`inventory failed: ${e.message}`); process.exit(2); });
}
