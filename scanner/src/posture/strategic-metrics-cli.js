// `agentic-security metrics [path] [--format text|json]`: the strategic metrics for the last scan and the recorded fix attempts.
// Exit codes: 0 reported; 1 the last scan failed its integrity check; 2 no scan to report on, or a usage problem.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath } from './state-dir.js';
import { verifyLastScan } from './integrity.js';
import { loadFixAttempts } from './fix-metrics.js';
import { computeStrategicMetrics, renderStrategicMetrics } from './strategic-metrics.js';

export async function cmdMetrics(args, io = {}) {
  const out = io.out || ((s) => process.stdout.write(s));
  const err = io.err || ((s) => console.error(s));
  const root = path.resolve(args._[1] || '.');
  const format = String(args.flags.format || 'text');
  if (!['text', 'json'].includes(format)) { err('Unknown --format. Use text or json.'); return 2; }
  const file = statePath(root, 'last-scan.json');
  let body;
  try { body = fs.readFileSync(file, 'utf8'); } catch { err(`No scan found at ${file}. Run a scan first.`); return 2; }
  if (verifyLastScan(body, file + '.sig') === false) { err('The last scan failed its integrity check, so no metric is reported from it.'); return 1; }
  let scan;
  try { scan = JSON.parse(body); } catch { err('The last scan is not valid JSON.'); return 1; }
  const m = computeStrategicMetrics({ scan, fixAttempts: loadFixAttempts(root) });
  out(format === 'json' ? JSON.stringify(m, null, 2) + '\n' : renderStrategicMetrics(m) + '\n');
  return 0;
}
