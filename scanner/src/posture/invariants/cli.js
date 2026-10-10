// `agentic-security invariants <export|coverage|regress>` (X-405 to X-407 CLI surface).
//
//   invariants export   --invariant <file> --fixture <dir> [--ledger <file>] [--commit <sha>] [--seed <n>] [--output <file>] [--json]
//       The reproducible scenario package for one contract (see export.js). Builds nothing and runs nothing when the
//       `invariant-scenarios` feature is off. Exit 0 ok, 1 refused (disabled, rejected, unsupported, blocked), 2 usage.
//   invariants coverage --invariant <file> | --invariants-dir <dir> [--ledger <file>] [--results <file>] [--json]
//       The bounded business-coverage report (see coverage.js). `--results` is a JSON array of `{ invariantId, result }` where
//       `result` is what `verifyInvariant` returned; without it the report is the static inventory with every contract's
//       transitions listed as untested, which is the honest answer when nothing was run. Exit 0, 1 refused, 2 usage.
//   invariants regress  <artifact.json>
//       Re-execute a regression artifact from the file alone (see repair.js). Exit 0 every leg settled as recorded, 1 a leg did
//       not (or the artifact is invalid), 3 not run (a prerequisite is unmet or the feature is off): not-run is not a pass.
//
// The logic lives here, not in bin/, so the same functions are exercised by tests without spawning the CLI; bin/ only
// dispatches. Paths are the operator's own and are resolved against the working directory (the MCP tool, which takes paths from
// an agent, confines them to its session root instead).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { resolveAssuranceConfig } from '../assurance/config.js';
import { exportFromFiles } from './export.js';
import { businessCoverage } from './coverage.js';
import { runRegressionArtifact } from './repair.js';
import { readJsonFile } from './project-input.js';

const USAGE = [
  'Usage: agentic-security invariants export   --invariant <file> --fixture <dir> [--ledger <file>] [--commit <sha>] [--seed <n>] [--output <file>] [--json]',
  '       agentic-security invariants coverage --invariant <file> | --invariants-dir <dir> [--ledger <file>] [--results <file>] [--json]',
  '       agentic-security invariants regress  <artifact.json>',
].join('\n');

const abs = (cwd, p) => path.resolve(cwd, String(p));

/**
 * @param {{ _: string[], flags: object }} args  parsed arguments; `_[0]` is `invariants`, `_[1]` the sub-command
 * @param {{ cwd?: string, out?: (s: string) => void, err?: (s: string) => void, env?: object }} [io]
 * @returns {Promise<number>} the exit code
 */
export async function runInvariantsCommand(args, io = {}) {
  const cwd = io.cwd || process.cwd();
  const out = io.out || ((s) => process.stdout.write(s));
  const err = io.err || ((s) => process.stderr.write(s));
  const sub = args._[1];
  const flags = args.flags || {};
  const config = resolveAssuranceConfig({ scanRoot: cwd, env: io.env || process.env });
  const emit = (value, lines) => out(flags.json ? `${JSON.stringify(value, null, 2)}\n` : `${lines.join('\n')}\n`);

  if (sub === 'export') {
    if (typeof flags.invariant !== 'string' || typeof flags.fixture !== 'string') { err(`${USAGE}\n`); return 2; }
    const r = exportFromFiles({
      invariantPath: abs(cwd, flags.invariant), fixturePath: abs(cwd, flags.fixture), ledgerPath: typeof flags.ledger === 'string' ? abs(cwd, flags.ledger) : undefined,
      commit: typeof flags.commit === 'string' ? flags.commit : undefined, seed: flags.seed !== undefined ? Number(flags.seed) : undefined, config,
    });
    if (r.status !== 'ok') { err(`agentic-security invariants export: ${r.status}: ${r.reason ?? ''}\n`); return 1; }
    const text = `${JSON.stringify(r.export, null, 2)}\n`;
    if (typeof flags.output === 'string') {
      fs.writeFileSync(abs(cwd, flags.output), text);
      out(`wrote ${r.export.scenarios.length} scenario(s) to ${flags.output}${r.withheld.length ? `; ${r.withheld.length} withheld (secret-looking content)` : ''}\n`);
    } else out(text);
    return 0;
  }

  if (sub === 'coverage') {
    let files = [];
    if (typeof flags.invariant === 'string') files = [abs(cwd, flags.invariant)];
    else if (typeof flags['invariants-dir'] === 'string') {
      try { files = fs.readdirSync(abs(cwd, flags['invariants-dir'])).filter((f) => f.endsWith('.json')).sort().map((f) => path.join(abs(cwd, flags['invariants-dir']), f)); } catch { err('agentic-security invariants coverage: the invariants directory is unreadable\n'); return 1; }
    } else { err(`${USAGE}\n`); return 2; }
    const docs = [];
    for (const f of files) {
      const j = readJsonFile(f);
      if (!j.ok) { err(`agentic-security invariants coverage: ${path.basename(f)}: ${j.reason}\n`); return 1; }
      docs.push(j.value);
    }
    let ledger; let results = [];
    if (typeof flags.ledger === 'string') { const l = readJsonFile(abs(cwd, flags.ledger)); if (!l.ok) { err(`agentic-security invariants coverage: the ledger: ${l.reason}\n`); return 1; } ledger = l.value; }
    if (typeof flags.results === 'string') { const rr = readJsonFile(abs(cwd, flags.results)); if (!rr.ok || !Array.isArray(rr.value)) { err('agentic-security invariants coverage: --results must be a JSON array of { invariantId, result }\n'); return 1; } results = rr.value; }
    const byId = new Map(results.filter((x) => x && typeof x.invariantId === 'string').map((x) => [x.invariantId, x.result]));
    const cov = businessCoverage({ entries: docs.map((invariant) => ({ invariant, result: byId.get(invariant.id) ?? null })), ledger });
    emit(cov, cov.lines);
    return 0;
  }

  if (sub === 'regress') {
    const file = args._[2];
    if (!file) { err(`${USAGE}\n`); return 2; }
    const a = readJsonFile(abs(cwd, file));
    if (!a.ok) { err(`agentic-security invariants regress: ${a.reason}\n`); return 1; }
    const r = await runRegressionArtifact(a.value, { config });
    emit(r, [`regression artifact: ${r.status}`, r.summary, ...r.legs.map((l) => `  ${l.matched ? 'ok ' : 'FAIL'} ${l.role}: expected ${l.expected}, got ${l.outcome ?? l.status}`)]);
    return r.status === 'passed' ? 0 : (r.status === 'prerequisite-unmet' || r.status === 'disabled') ? 3 : 1;
  }

  err(`agentic-security invariants: unrecognized sub-command "${sub}"\n${USAGE}\n`);
  return 2;
}
