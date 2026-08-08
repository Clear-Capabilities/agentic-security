#!/usr/bin/env node
// PRD Epic 4.1 — the autopilot CLI.
//
// `posture/autopilot.js` owns the loop and its gates; it knows nothing about
// scanning, sandboxes or test runners because every stage is injected. This
// file is where the real stages get injected, and it is deliberately the only
// place that decides what "prove", "fix" and "re-verify" MEAN in production.
//
// Usage:
//   node scripts/autopilot.mjs [path] [options]
//
//   --apply             Write patches that re-verified. OFF by default.
//   --severities a,b    Severity floor set (default critical,high).
//   --max <n>           Cap findings considered (default 25).
//   --state <path>      Checkpoint file (default .agentic-security/autopilot.json).
//   --no-resume         Ignore an existing checkpoint.
//   --no-tests          Skip the project test leg (see the honesty note below).
//   --allow-dirty       Proceed with uncommitted changes.
//   --json <path>       Write the full per-finding record set.
//
// Exit codes: 0 everything in scope ended VERIFIED_FIXED (or there was nothing
// in scope), 1 something needs review, 2 usage/IO error.
//
// WHY THE TEST LEG TOUCHES THE WORKING TREE. A patch's effect on the test
// suite cannot be measured without the patch being on disk. So the tree IS
// mutated during verification and restored in a `finally` — and because a
// crash between those two points would leave a patched file behind, the CLI
// refuses to start on a dirty tree unless told otherwise. `git diff` is then
// the recovery path, which is why a clean tree is the price of entry.
//
// WHAT `--no-tests` COSTS, STATED PLAINLY. Without the test leg the loop can
// still see that the exploit stopped working, but not that the patch left the
// application working. That is a weaker claim, so it is reported as one: those
// findings are counted separately and the summary says so rather than folding
// them into the same VERIFIED_FIXED total.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const mod = (rel) => import(path.join(REPO, 'scanner', 'src', rel));

const { runAutopilot, renderAutopilotSummary } = await mod('posture/autopilot.js');
const { runScan } = await mod('runScan.js');
const { normalizeFindings } = await mod('report/index.js');
const { synthesizeInProcessPoc } = await mod('posture/poc-inprocess.js');
const { mergePocFiles } = await mod('posture/prove-findings.js');
const { proveFinding } = await mod('posture/execution-proof.js');
const { sandboxAvailable } = await mod('sandbox/index.js');
const { synthesizeDeterministicPatch } = await mod('posture/deterministic-fix.js');
const { runProjectTests } = await mod('posture/fix-verify-loop.js');
const { resolveProvider, buildProviderRequest } = await mod('llm-validator/providers.js');

// Flags that consume the next argument. Listed explicitly so a value can never
// be mistaken for the scan path — `--max 25 .` and `--max 25` must not disagree
// about what is being scanned.
const VALUED = new Set(['severities', 'max', 'state', 'json']);

const argv = process.argv.slice(2);
const flags = new Map();
const positionals = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (!a.startsWith('--')) { positionals.push(a); continue; }
  const name = a.slice(2);
  if (VALUED.has(name)) flags.set(name, argv[++i] ?? null);
  else flags.set(name, true);
}
const arg = (name, fallback = null) => (flags.has(name) ? flags.get(name) : fallback);
const has = (name) => flags.get(name) === true;

const root = path.resolve(positionals[0] || process.cwd());
if (!fs.existsSync(root)) {
  process.stderr.write(`no such path: ${root}\n`);
  process.exit(2);
}

const apply = has('apply');
const runTests = !has('no-tests');
const severities = (arg('severities', 'critical,high') || '').split(',').map((s) => s.trim()).filter(Boolean);
const max = Number(arg('max', '25')) || 25;
const stateFile = path.resolve(arg('state', path.join(root, '.agentic-security', 'autopilot.json')));

// A confinement backend is not optional here. Every fix decision this CLI makes
// rests on running an exploit before and after the patch; with nothing to run
// it in, the loop would degrade to "the scanner stopped complaining", which is
// the exact failure the gate exists to prevent.
if (!sandboxAvailable()) {
  process.stderr.write('no confinement backend available — refusing to run.\n'
    + 'The fix gate is "the exploit no longer fires", and that verdict requires executing it.\n');
  process.exit(2);
}

// Dirty-tree refusal. The test leg writes the candidate patch to disk, so a
// crash mid-verification leaves an edit behind; a clean tree makes that
// recoverable with `git checkout`.
if (runTests && !has('allow-dirty')) {
  let dirty = null;
  try {
    // stderr ignored: outside a repository git says so loudly, and that is not
    // a condition the operator needs to hear about.
    dirty = execFileSync('git', ['status', '--porcelain'],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch { dirty = null; /* not a git repo — nothing to protect, nothing to promise */ }
  if (dirty) {
    process.stderr.write('the working tree has uncommitted changes.\n'
      + 'Verification writes candidate patches to disk and restores them afterwards; on a dirty\n'
      + 'tree a crash would be indistinguishable from your own edits. Commit, stash, or pass\n'
      + '--allow-dirty (or --no-tests, which never writes).\n');
    process.exit(2);
  }
}

const readFile = (rel) => {
  try { return fs.readFileSync(path.resolve(root, rel), 'utf8'); } catch { return null; }
};

// PoCs are synthesized once per finding and reused for re-verification. Using
// the SAME artifact both times is what makes the second run evidence about the
// patch: a freshly synthesized PoC could differ for reasons unrelated to it.
const pocs = new Map();
const keyOf = (f) => f.stableId || `${f.file}:${f.line}:${f.vuln}`;

// Ask a model for the whole patched file. Whole-file rather than a diff because
// a diff has to apply cleanly before it can be judged, and a failed application
// is an ambiguous outcome; a full file either parses and passes the gate or it
// does not. The response is never trusted — it goes straight into the same
// re-verification every other patch faces.
async function _modelPatch(config, finding, content) {
  const prompt = [
    'You are fixing ONE security defect. Return ONLY the complete corrected file.',
    'No prose, no markdown fences, no explanation, no placeholder comments.',
    'Change as little as possible and preserve the existing exports and behaviour.',
    '',
    `Defect: ${finding.vuln} (${finding.cwe || 'no CWE'}) at ${finding.file}:${finding.line}`,
    finding.remediation ? `Suggested remediation: ${finding.remediation}` : '',
    '',
    '--- FILE ---',
    content,
  ].filter(Boolean).join('\n');

  const req = buildProviderRequest(config, prompt, 4096);
  let text;
  try {
    // This engine flags the call below as SSRF because `config.endpoint`
    // originates in the environment, which it treats as a taint source. Here
    // the environment IS the operator: naming your own fix endpoint is the
    // documented way to configure this CLI, and there is no path by which
    // scanned code influences it. Suppressed with the reason rather than
    // absorbed into the drift baseline, which is a tripwire and not a
    // reviewed-and-accepted list.
    const r = await fetch(config.endpoint, { // agentic-security-ignore: SSRF
      method: 'POST',
      headers: { 'content-type': 'application/json', ...req.headers },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(120000),
    });
    if (!r.ok) return null;
    text = req.extractText(await r.json());
  } catch { return null; }
  if (typeof text !== 'string' || !text.trim()) return null;

  // Strip a fenced block if the model added one anyway.
  const fenced = text.match(/```(?:[\w-]*)\n([\s\S]*?)```/);
  const out = (fenced ? fenced[1] : text).trim() + '\n';
  // An unchanged file is not a fix, and an empty one is a deletion wearing a
  // fix's clothes. Both would sail through "the exploit no longer fires".
  if (out.trim() === content.trim()) return null;
  if (out.trim().length < Math.min(40, content.trim().length / 4)) return null;
  return out;
}

let testsSkipped = 0;

const stages = {
  async scan() {
    const { scan } = await runScan(root);
    return { findings: normalizeFindings(scan) };
  },

  async prove(finding) {
    const content = readFile(finding.file);
    if (content === null) return { proofTier: null, proofEvidence: { ran: false, reason: 'source unreadable' } };
    const syn = synthesizeInProcessPoc(finding, content);
    if (!syn.ok) return { proofTier: null, proofEvidence: { ran: false, reason: syn.reason } };
    pocs.set(keyOf(finding), { poc: syn.poc, content });
    const r = await proveFinding({ ...finding, poc: syn.poc },
      { files: mergePocFiles(syn.poc, content) });
    return { proofTier: r.proofTier, proofEvidence: r.proofEvidence, poc: syn.poc };
  },

  // Deterministic first, model second. The deterministic rules are exact
  // literal swaps and are preferred wherever one applies — a model cannot beat
  // a transformation that is already known-correct, and it can differ run to
  // run. The model is the fallback for the classes no rule covers, which today
  // is most of the ones that can actually be proven.
  //
  // The patch is not trusted either way. Both routes feed the same gate.
  async synthesizeFix(finding) {
    const held = pocs.get(keyOf(finding));
    const content = held?.content ?? readFile(finding.file);
    if (content === null) return null;

    const deterministic = synthesizeDeterministicPatch(finding, content);
    if (deterministic) return { ...deterministic, source: 'deterministic' };

    const provider = resolveProvider({ role: 'fix' });
    if (!provider.ok) {
      // Reported as NO_FIX with the reason, not as a clean finding.
      return null;
    }
    const patched = await _modelPatch(provider.config, finding, content);
    return patched ? { patch: { [finding.file]: patched }, source: `model:${provider.config.provider}` } : null;
  },

  async verifyFix(finding, patch) {
    const held = pocs.get(keyOf(finding));
    if (!held) return { ok: false, reason: 'no proof-of-concept was retained for this finding' };
    const patched = patch.patch[finding.file];
    if (typeof patched !== 'string') {
      return { ok: false, reason: 'the patch does not touch the file the exploit runs against' };
    }

    // Leg 1 — the exploit, re-run against the patched source.
    const r = await proveFinding({ ...finding, poc: held.poc },
      { files: mergePocFiles(held.poc, patched) });
    if (r.proofEvidence?.ran !== true) {
      // The PoC did not execute, so nothing was learned about the patch. That
      // is not "fixed" — an unexecuted exploit is silence, not absence.
      return { ok: false, reason: `re-verification did not execute: ${r.proofEvidence?.reason || 'unknown'}` };
    }
    const pocStillFires = r.proofTier === 'execution-proven';
    if (pocStillFires) return { ok: false, pocStillFires: true, testsPass: true };

    // Leg 2 — the project's own tests, with the patch on disk.
    if (!runTests) {
      testsSkipped++;
      return { ok: true, pocStillFires: false, testsPass: true, testsRan: false };
    }
    const abs = path.resolve(root, finding.file);
    const original = fs.readFileSync(abs, 'utf8');
    let t;
    try {
      fs.writeFileSync(abs, patched, 'utf8');
      t = runProjectTests(root);
    } finally {
      fs.writeFileSync(abs, original, 'utf8');
    }
    if (t.skipped) {
      testsSkipped++;
      return { ok: true, pocStillFires: false, testsPass: true, testsRan: false, testRunner: t.reason || 'none' };
    }
    return {
      ok: t.ok, pocStillFires: false, testsPass: t.ok, testsRan: true, testRunner: t.runner,
      reason: t.ok ? null : `the ${t.runner} suite failed with this patch`,
    };
  },

  async applyFix(finding, patch) {
    for (const [rel, content] of Object.entries(patch.patch)) {
      const abs = path.resolve(root, rel);
      if (abs !== root && !abs.startsWith(root + path.sep)) {
        throw new Error(`refusing to write outside the project: ${rel}`);
      }
      fs.writeFileSync(abs, content, 'utf8');
    }
  },
};

process.stderr.write(`autopilot: ${root}\n`
  + `  gates: ${apply ? 'APPLY (verified patches will be written)' : 'on (nothing will be written)'}\n`
  + `  severities: ${severities.join(', ')}; test leg: ${runTests ? 'on' : 'OFF'}\n`);

const res = await runAutopilot({
  stages, stateFile, apply, severities, maxFindings: max,
  resume: !has('no-resume'),
  onStage: (e) => {
    if (e.stage === 'scan') process.stderr.write(`  scanned: ${e.count} finding(s)\n`);
    else if (e.key) process.stderr.write(`  ${e.stage}: ${e.key} → ${e.outcome || e.verdict}\n`);
  },
});

if (!res.ok) { process.stderr.write(`autopilot refused: ${res.reason}\n`); process.exit(2); }

process.stdout.write('\n' + (renderAutopilotSummary(res.summary) || 'nothing in scope.') + '\n');

// A VERIFIED_FIXED that never ran a test suite is a weaker claim than one that
// did. Kept separate rather than averaged into the same number.
if (testsSkipped) {
  process.stdout.write(`${testsSkipped} verified patch(es) had NO test suite run `
    + `(${runTests ? 'no runner detected' : '--no-tests'}) — the exploit stopped firing, `
    + 'but nothing checked the application still works.\n');
}

const jsonOut = arg('json');
if (jsonOut) {
  fs.mkdirSync(path.dirname(path.resolve(jsonOut)), { recursive: true });
  fs.writeFileSync(jsonOut, JSON.stringify({ summary: res.summary, results: res.results, testsSkipped }, null, 2));
  process.stderr.write(`wrote ${jsonOut}\n`);
}

const unresolved = res.results.filter((r) => r.outcome !== 'VERIFIED_FIXED');
if (unresolved.length) {
  process.stdout.write('\nNot fixed:\n');
  for (const r of unresolved) {
    process.stdout.write(`  [${r.outcome}] ${r.file}:${r.line} ${r.vuln} — ${r.reason || 'no reason recorded'}\n`);
  }
  process.exit(1);
}
process.exit(0);
