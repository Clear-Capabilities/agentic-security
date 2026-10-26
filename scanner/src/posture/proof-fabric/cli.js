// CLI surface for the proof fabric: `proof show|replay|doctor`, `triage exploit|validate`. Non-interactive by design: no
// command reads stdin, every run is bounded by the policy timeouts, and a missing reproducer is a typed exit code, not a
// prompt. Exit codes: 0 confirmed/ok, 1 not confirmed (any reason), 4 usage/precondition.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { statePath } from '../state-dir.js';
import { proveFinding } from './orchestrator.js';
import { saveProof, latestProof, listProofs, findingKey, scrubDeep } from './store.js';
import { selectEnvironment, hostTools, languageSupport } from './runner.js';
import { validateReproducer } from './reproducer.js';
import { LANGUAGES } from './reproducer.js';
import { generateReproducer } from './generate.js';

function loadFinding(root, id) {
  const p = statePath(root, 'last-scan.json');
  if (!fs.existsSync(p)) return null;
  const last = JSON.parse(fs.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

/**
 * The reproducer for a finding: the one the person or agent supplied (or stored), else one built from the finding's own evidence.
 * A generated reproducer is a proposal; it earns nothing until it is executed, and the result says it was generated.
 */
export function resolveReproducer(root, finding, flagPath) {
  const supplied = loadReproducer(root, finding.stableId ?? finding.id, flagPath) ?? (finding.stableId && finding.id !== finding.stableId ? loadReproducer(root, finding.id, flagPath) : null);
  if (supplied) return { ...supplied, generated: null };
  const g = generateReproducer({ finding, root });
  if (!g.ok) return { reproducer: null, reason: g.reason };
  return { reproducer: g.reproducer, file: null, generated: g.basis };
}

function loadReproducer(root, id, flagPath) {
  const candidates = [flagPath && path.resolve(String(flagPath)), statePath(root, 'reproducers', `${findingKey(id)}.json`)].filter(Boolean);
  for (const c of candidates) {
    try { return { reproducer: JSON.parse(fs.readFileSync(c, 'utf8')), file: c }; } catch { /* next */ }
  }
  return null;
}

function formatResult(r) {
  const env = r.environment ? `${r.environment.mode} (${r.environment.assurance} assurance)` : 'none';
  return [
    `Finding: ${r.findingId}`,
    `Evidence: ${r.state}`,
    `Oracle: ${r.oracle}`,
    `Reproductions: ${r.attempts?.successes ?? 0}/${r.attempts?.run ?? 0} (required ${r.attempts?.required})`,
    `Independent replay: ${r.independentReplay?.status ?? 'not-run'}`,
    `Environment: ${env}`,
    `Completeness: ${r.completeness}`,
    `Duration: ${(r.timing.proofMs / 1000).toFixed(1)}s`,
    ...(r.degradation?.length ? [`Degraded: ${r.degradation.join(', ')}`] : []),
    ...(r.note ? [`Note: ${r.note}`] : []),
  ].join('\n');
}

export async function cmdProve(args, root, { json = false } = {}) {
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: triage exploit <finding-id> --prove [--reproducer file] [--attempts N] [--required N]'); return 4; }
  const finding = loadFinding(root, id);
  if (!finding) { console.error(`Finding ${id} not found in last scan.`); return 4; }
  const loaded = resolveReproducer(root, finding, args.flags.reproducer);
  if (!loaded.reproducer) { console.error(`No reproducer for ${id}, and none could be generated from the finding: ${loaded.reason}. Supply one with --reproducer <file> or place it at .agentic-security/reproducers/. Nothing was executed.`); return 4; }
  if (loaded.generated) console.error(`Generated a reproducer from the finding (${loaded.generated.shape}, ${loaded.generated.class}). It is a proposal: it counts only if executing it confirms the exploit.`);
  const errs = validateReproducer(loaded.reproducer);
  if (errs.length) { console.error(`Invalid reproducer: ${errs.join('; ')}`); return 4; }
  const policy = {};
  if (args.flags.attempts) policy.attempts = Number(args.flags.attempts);
  if (args.flags.required) policy.required = Number(args.flags.required);
  if (args.flags.timeout) policy.timeoutMs = Number(args.flags.timeout) * 1000;
  if (args.flags['require-container']) policy.requireContainer = true;
  const ac = new AbortController();
  const onSig = () => ac.abort();
  process.once('SIGINT', onSig);
  let result;
  try { result = await proveFinding({ finding, reproducer: loaded.reproducer, revision: args.flags.revision ?? null, policy, signal: ac.signal, sourceRoot: root }); } finally { process.off('SIGINT', onSig); }
  const saved = saveProof(root, { ...result, reproducer: loaded.reproducer, ...(loaded.generated ? { generatedFrom: loaded.generated } : {}) });
  // Printed output gets the same secret-scrubbing pass as what is persisted (defense in depth: a free-text reason/note
  // field that captured something from stdout/stderr should never reach a terminal unredacted either).
  if (json || args.flags.json) console.log(JSON.stringify(scrubDeep({ ...result, stored: saved.ok ? saved.file : null }), null, 2));
  else { console.log(formatResult(result)); if (!saved.ok) console.log(`(proof not stored: ${saved.reason})`); }
  return result.state === 'EXPLOIT_CONFIRMED' ? 0 : 1;
}

export async function cmdProof(args, root) {
  const sub = args._[1];
  if (sub === 'doctor') return doctor(args);
  if (sub === 'generate') {
    const gid = String(args._[2] ?? '');
    const finding = gid ? loadFinding(root, gid) : null;
    if (!finding) { console.error(gid ? `Finding ${gid} not found in last scan.` : 'usage: proof generate <finding-id> [--out file]'); return 4; }
    const g = generateReproducer({ finding, root });
    if (!g.ok) { console.error(`No reproducer could be generated: ${g.reason}`); return 1; }
    const text = JSON.stringify({ ...g.reproducer, findingId: gid }, null, 2);
    if (args.flags.out) { fs.writeFileSync(path.resolve(String(args.flags.out)), `${text}\n`); console.log(`Wrote ${path.resolve(String(args.flags.out))} (${g.basis.shape}, ${g.basis.class}). Nothing was executed.`); } else console.log(text);
    for (const a of g.basis.assumptions) console.error(`assumption: ${a}`);
    return 0;
  }
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: proof show <finding-id> | proof replay <finding-id> | proof generate <finding-id> | proof doctor'); return 4; }
  if (sub === 'show') {
    const all = listProofs(root, id);
    if (!all.length) { console.error(`No stored proof for ${id}.`); return 4; }
    const latest = all.find((p) => p.record);
    if (all.some((p) => p.tampered)) console.error(`WARNING: ${all.filter((p) => p.tampered).length} stored record(s) failed their integrity check and are not trusted.`);
    const good = all.find((p) => p.record && !p.tampered);
    if (!good) { console.error('No intact proof record.'); return 1; }
    if (args.flags.json) console.log(JSON.stringify(good.record, null, 2)); else console.log(formatResult(good.record));
    // the detection generated from this finding's proof (detection-and-response loop), when there is one
    try {
      const det = (await import('../dnr/store.js')).latestRecord(root, id, 'detection');
      if (det && !args.flags.json) console.log(`Detection: ${det.record.ir?.id ?? 'unknown'} (${det.record.validation?.status ?? 'not validated'}${det.record.enabled ? ', enabled' : ''})`);
    } catch { /* the proof output does not depend on it */ }
    void latest;
    return 0;
  }
  if (sub === 'replay') {
    const stored = latestProof(root, id);
    if (!stored?.record?.reproducer) { console.error(`No stored reproducer for ${id}.`); return 4; }
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proof-replay-'));
    const tmp = path.join(tmpDir, 'reproducer.json');
    fs.writeFileSync(tmp, JSON.stringify(stored.record.reproducer));
    args.flags.reproducer = tmp;
    args._ = ['triage', 'exploit', id];
    try { return await cmdProve(args, root); } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
  }
  console.error('usage: proof show|replay <finding-id> | proof doctor');
  return 4;
}

function doctor(args) {
  const tools = hostTools();
  const rows = LANGUAGES.map((l) => ({ lang: l, ...languageSupport(l, tools) }));
  const envs = ['javascript', 'python', 'haskell'].map((l) => ({ lang: l, ...selectEnvironment({ lang: l }) }));
  if (args.flags.json) { console.log(JSON.stringify({ tools, languages: rows, environments: envs }, null, 2)); return 0; }
  console.log('Proof fabric doctor');
  for (const r of rows) console.log(`  ${r.lang.padEnd(11)} ${r.supported ? 'supported' : `unsupported (${r.reason})`}`);
  for (const e of envs) console.log(`  environment for ${e.lang}: ${e.mode}, ${e.assurance} assurance${e.reason ? ` (${e.reason})` : ''}${e.containerSkipped ? `; container skipped: ${e.containerSkipped}` : ''}`);
  const usable = envs.some((e) => e.mode !== 'unavailable');
  if (!usable) console.log('  RESULT: no execution environment available; proofs will report blocked, never clean.');
  return usable ? 0 : 1;
}
