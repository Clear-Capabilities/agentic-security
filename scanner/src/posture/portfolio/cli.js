// `agentic-security portfolio <progress|retention|backend|export|import>` (X-707, X-708 CLI surface).
//
//   portfolio progress  --store <file> [--budgets <file>] [--findings <file>] [--blocking-severity <s>] [--now <ms>] [--json]
//       The coverage-aware progress view (see portfolio/progress.js). Exit 0, 1 refused (feature off, store failed verification), 2 usage.
//   portfolio retention plan|apply --records <file> --root <dir> [--policy <file>] [--holds <file>] [--store <file>]
//                                  [--log <file> --actor <name>] [--now <ms>] [--json]
//       Retention by class with legal holds (see portfolio/retention.js). `plan` deletes nothing. `apply` needs --log and --actor, logs
//       each deletion first, and exits 1 if anything it should have deleted could not be deleted. Exit 0 ok, 1 refused or incomplete, 2 usage.
//   portfolio retention verify-log --log <file>     checks the hash chain of the deletion log. Exit 0 intact, 1 broken.
//   portfolio backend probe --mode local|shared --dir <dir>
//       Reports whether a backend is usable. An unusable shared backend is the typed `blocked` state, exit 1; nothing is created.
//   portfolio export --store <file> --out <file> [--retention-log <file>]    one self-checking, secret-free file for an air-gapped machine
//   portfolio import --from <file> --mode local|shared --dir <dir>            verifies first; never overwrites a store
//
// Every subcommand is off unless the `portfolio-assurance` feature is on (assurance/config.js), so a default install behaves exactly as
// before. Nothing here makes a network call: the whole command works air-gapped. The logic lives here, not in bin/, so tests run it
// without spawning the CLI; bin/ only dispatches. Paths are the operator's own and resolve against the working directory (the MCP
// tool, which takes paths from an agent, confines them to its session root instead).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { resolveAssuranceConfig, featureStatus } from '../assurance/config.js';
import { FEATURE_ID } from './wording.js';
import { readStore } from './work-units.js';
import { readLedger } from './scheduler.js';
import { buildProgressView } from './progress.js';
import { applyRetention, planRetention, verifyRetentionLog } from './retention.js';
import { openBackend, exportState, importState, verifyStateExport } from './backend.js';

const USAGE = [
  'Usage: agentic-security portfolio progress  --store <file> [--budgets <file>] [--findings <file>] [--blocking-severity <s>] [--now <ms>] [--json]',
  '       agentic-security portfolio retention plan|apply --records <file> --root <dir> [--policy <file>] [--holds <file>] [--store <file>] [--log <file> --actor <name>] [--now <ms>] [--json]',
  '       agentic-security portfolio retention verify-log --log <file>',
  '       agentic-security portfolio backend probe --mode local|shared --dir <dir>',
  '       agentic-security portfolio export --store <file> --out <file> [--retention-log <file>]',
  '       agentic-security portfolio import --from <file> --mode local|shared --dir <dir>',
].join('\n');

const abs = (cwd, p) => path.resolve(cwd, String(p));
const readJsonFile = (file) => {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile() || st.size > 32 * 1024 * 1024) throw new Error('not a regular JSON file within the size limit');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
};

/**
 * @param {{ _: string[], flags: object }} args
 * @param {{ cwd?: string, out?: (s: string) => void, err?: (s: string) => void, env?: object, now?: () => number }} [io]
 * @returns {Promise<number>} the exit code
 */
export async function runPortfolioCommand(args, io = {}) {
  const cwd = io.cwd || process.cwd();
  const out = io.out || ((s) => process.stdout.write(s));
  const err = io.err || ((s) => process.stderr.write(s));
  const sub = args._[1];
  const flags = args.flags || {};
  const clock = io.now || (() => Date.now());
  const emit = (value, lines) => out(flags.json ? `${JSON.stringify(value, null, 2)}\n` : `${lines.join('\n')}\n`);
  if (!['progress', 'retention', 'backend', 'export', 'import'].includes(sub)) { err(`${USAGE}\n`); return 2; }

  const config = resolveAssuranceConfig({ scanRoot: cwd, env: io.env || process.env });
  const gate = featureStatus(config, FEATURE_ID);
  if (gate.status !== 'ok') { err(`agentic-security portfolio ${sub}: ${gate.status}: ${gate.reason ?? gate.code}\n`); return 1; }
  const nowMs = flags.now !== undefined ? Number(flags.now) : clock();

  try {
    if (sub === 'progress') {
      if (typeof flags.store !== 'string') { err(`${USAGE}\n`); return 2; }
      const storePath = abs(cwd, flags.store);
      const store = readStore(storePath);
      if (!store) { err('agentic-security portfolio progress: no portfolio store at that path\n'); return 1; }
      const r = buildProgressView({
        store, ledger: readLedger(storePath), now: nowMs,
        budgets: typeof flags.budgets === 'string' ? readJsonFile(abs(cwd, flags.budgets)) : null,
        findings: typeof flags.findings === 'string' ? readJsonFile(abs(cwd, flags.findings)) : null,
        blockingSeverity: typeof flags['blocking-severity'] === 'string' ? flags['blocking-severity'] : undefined,
      });
      if (!r.ok) { err(`agentic-security portfolio progress: ${r.errors[0].message}\n`); return 1; }
      emit(r.view, r.view.lines);
      return 0;
    }

    if (sub === 'retention') {
      const mode = args._[2];
      if (mode === 'verify-log') {
        if (typeof flags.log !== 'string') { err(`${USAGE}\n`); return 2; }
        const v = verifyRetentionLog(abs(cwd, flags.log));
        emit(v, [v.ok ? `Deletion log verified: ${v.entries.length} entr${v.entries.length === 1 ? 'y' : 'ies'}, chain intact.` : `Deletion log FAILED verification: ${v.errors[0].message}`]);
        return v.ok ? 0 : 1;
      }
      if (!['plan', 'apply'].includes(mode) || typeof flags.records !== 'string' || typeof flags.root !== 'string') { err(`${USAGE}\n`); return 2; }
      const input = {
        records: readJsonFile(abs(cwd, flags.records)), now: nowMs,
        policy: typeof flags.policy === 'string' ? readJsonFile(abs(cwd, flags.policy)) : undefined,
        holds: typeof flags.holds === 'string' ? readJsonFile(abs(cwd, flags.holds)) : [],
        store: typeof flags.store === 'string' ? readStore(abs(cwd, flags.store)) : null,
      };
      if (mode === 'plan') {
        const plan = planRetention(input);
        if (!plan.ok) { err(`agentic-security portfolio retention: ${plan.errors[0].message}\n`); return 1; }
        emit(plan, [`Retention plan (policy ${plan.policyVersion}): ${plan.summary.delete} to delete, ${plan.summary.keep} kept (${plan.summary.heldByLegalHold} under legal hold), ${plan.summary.protect} protected as required current receipts${plan.summary.expiredButRequired ? ` (${plan.summary.expiredButRequired} past retention but required: deletion blocked)` : ''}.`, 'Nothing was deleted.']);
        return 0;
      }
      if (typeof flags.log !== 'string' || typeof flags.actor !== 'string') { err(`${USAGE}\n`); return 2; }
      const r = applyRetention({ ...input, root: abs(cwd, flags.root), logFile: abs(cwd, flags.log), actor: flags.actor });
      if (!r.ok) { err(`agentic-security portfolio retention: ${r.errors[0].message}\n`); return 1; }
      emit(r, [`Retention applied: ${r.deleted.length} deleted and logged, ${r.blocked.length} blocked as required current receipts, ${r.failed.length} could not be deleted.`, ...r.failed.map((f) => `  ${f.id}: ${f.code}: ${f.message}`)]);
      return r.failed.length ? 1 : 0;
    }

    if (sub === 'backend') {
      if (args._[2] !== 'probe' || typeof flags.dir !== 'string') { err(`${USAGE}\n`); return 2; }
      const b = openBackend({ mode: flags.mode, dir: abs(cwd, flags.dir) });
      if (!b.ok) { emit(b, [`Backend ${flags.mode ?? '?'}: ${b.state} (${b.code}): ${b.reason}`, 'Nothing was created and no other location is used instead.']); return 1; }
      const d = b.backend.describe();
      emit({ ok: true, ...d }, [`Backend ${d.kind} at ${d.root}: usable.`, `  Network filesystems: ${d.consistency.networkFilesystem}.`]);
      return 0;
    }

    if (sub === 'export') {
      if (typeof flags.store !== 'string' || typeof flags.out !== 'string') { err(`${USAGE}\n`); return 2; }
      const r = exportState({ storeFile: abs(cwd, flags.store), outFile: abs(cwd, flags.out), retentionLog: typeof flags['retention-log'] === 'string' ? abs(cwd, flags['retention-log']) : null, now: nowMs });
      emit(r, [`Exported ${r.units} unit(s) to ${flags.out} (${r.digest}).`]);
      return 0;
    }

    if (sub === 'import') {
      if (typeof flags.from !== 'string' || typeof flags.dir !== 'string') { err(`${USAGE}\n`); return 2; }
      const b = openBackend({ mode: flags.mode, dir: abs(cwd, flags.dir) });
      if (!b.ok) { err(`agentic-security portfolio import: ${b.state} (${b.code}): ${b.reason}\n`); return 1; }
      const v = verifyStateExport(abs(cwd, flags.from));
      if (!v.ok) { err(`agentic-security portfolio import: ${v.code}: ${v.reason}\n`); return 1; }
      const r = importState({ from: abs(cwd, flags.from), backend: b.backend });
      if (!r.ok) { err(`agentic-security portfolio import: ${r.code}: ${r.reason}\n`); return 1; }
      emit(r, [`Imported ${r.units} unit(s) into ${r.file}.`]);
      return 0;
    }
  } catch (e) {
    err(`agentic-security portfolio ${sub}: ${e.code ?? 'error'}: ${String(e.message).slice(0, 300)}\n`);
    return 1;
  }
  return 2;
}
