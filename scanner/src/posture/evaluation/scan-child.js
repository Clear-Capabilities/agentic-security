// Child-process entry for ONE engine scan inside an evaluation run (QA-003).
//
// `node scan-child.js <workspace> <layer-config>` where the layer config is one
// of the ablation names in runner.js. It exists as a separate process so that:
//   - a timeout can KILL the scan (an in-process scan cannot be interrupted);
//   - the environment is exactly what the runner passed, with no label paths;
//   - state writes cannot touch the host's scan state.
//
// A third argument `diagnose` adds a `diagnostics` block to the result (why-missed.js): the suppression ledger with its
// identities, the filter and dedupe stage evidence, the sources and sinks the engine recognised, and how the intermediate
// representation fared on the files named in AGENTIC_SECURITY_DIAG_FILES. Diagnose mode only OBSERVES; the findings it returns are
// the same findings the plain mode returns (pinned by test).
//
// It reads only the staged workspace. Exit codes: 0 ok (JSON on stdout between
// the markers), 3 the requested layer is unavailable here (a model-assisted run
// with no configured endpoint), 1 anything else.

import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

export const RESULT_BEGIN = '@@EVAL-RESULT-BEGIN@@';
export const RESULT_END = '@@EVAL-RESULT-END@@';

export const LAYER_ENV = {
  'deterministic-only': { AGENTIC_SECURITY_DEEP: '0', AGENTIC_SECURITY_LLM_VALIDATE: '0' },
  'deep-taint': { AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_LLM_VALIDATE: '0' },
  'model-assisted': { AGENTIC_SECURITY_DEEP: '1' },
};

async function diagnosticsOf(scan) {
  const slim = (x) => ({ file: x.file ?? null, line: Number.isInteger(x.line) ? x.line : null, vuln: x.vuln ?? x.label ?? null, category: x.category ?? null });
  const diag = {
    suppressions: (scan.suppressions || []).map((x) => ({ vuln: x.vuln ?? null, file: x.file ?? null, line: Number.isInteger(x.line) ? x.line : null, reason: String(x.reason ?? ''), id: x.id ?? null, cwe: x.cwe ?? null, family: x.family ?? null })),
    stageEvidence: scan.stageEvidence || { dedupe: [], guard: [] },
    sources: (scan.sources || []).map(slim), sinks: (scan.sinks || []).map(slim),
    ir: { files: {}, parseFailures: [] },
  };
  let wanted = [];
  try { wanted = JSON.parse(process.env.AGENTIC_SECURITY_DIAG_FILES || '[]'); } catch { wanted = []; }
  if (wanted.length) {
    try {
      const irMod = await import('../../ir/index.js');
      irMod._resetIrParseFailures();
      const ir = await irMod.buildProjectIRAsync(Object.fromEntries(wanted.filter((f) => scan.fc && typeof scan.fc[f] === 'string').map((f) => [f, scan.fc[f]])));
      for (const f of wanted) {
        const entry = ir.perFile?.[f];
        diag.ir.files[f] = entry ? { lowered: true, functions: (entry.functions || []).map((fn) => ({ line: fn.line, name: fn.name })) } : { lowered: false, functions: [] };
      }
      diag.ir.parseFailures = irMod.irParseFailures();
    } catch (e) { diag.ir.error = String(e?.message || e).slice(0, 200); }
  }
  return diag;
}

async function main() {
  const [dir, layer, mode] = process.argv.slice(2);
  if (!dir || !LAYER_ENV[layer]) { process.stderr.write(`usage: scan-child <workspace> <${Object.keys(LAYER_ENV).join('|')}>\n`); process.exit(1); }
  if (layer === 'model-assisted' && !process.env.AGENTIC_SECURITY_LLM_ENDPOINT) {
    process.stderr.write('model-assisted requires AGENTIC_SECURITY_LLM_ENDPOINT; none is configured\n');
    process.exit(3);
  }
  Object.assign(process.env, LAYER_ENV[layer]);
  if (mode === 'diagnose') process.env.AGENTIC_SECURITY_STAGE_EVIDENCE = '1';
  const { setStateWritesEnabled } = await import('../state-dir.js');
  setStateWritesEnabled(false);
  const { runScan } = await import('../../runScan.js');
  const { scan } = await runScan(path.resolve(dir), { deep: layer !== 'deterministic-only' });
  const findings = (scan.findings || []).map((f) => ({
    id: f.id ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null,
    family: f.family ?? null, cwe: f.cwe ?? null, severity: f.severity ?? null, parser: f.parser ?? null, vuln: f.vuln ?? null,
  }));
  const result = { findings };
  if (mode === 'diagnose') result.diagnostics = await diagnosticsOf(scan);
  process.stdout.write(`${RESULT_BEGIN}${JSON.stringify(result)}${RESULT_END}\n`);
}

// Only when run as a script: runner.js imports the markers and must not start a scan.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(() => process.exit(0), (e) => { process.stderr.write(`${e?.stack || e}\n`); process.exit(1); });
}
