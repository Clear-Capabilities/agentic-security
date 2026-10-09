// Recapture the previous-schema fixtures from another checkout's sources.
//   node capture.mjs <path-to-a-scanner-directory>
// Prints one JSON document with the three previous outputs. The compatibility test pins the committed copies; this exists so
// they can be reproduced and reviewed, not to run in CI.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { COMMIT, META, scanInput, autopilotStages } from './inputs.mjs';

const scanner = path.resolve(process.argv[2] || '.');
const imp = (rel) => import(pathToFileURL(path.join(scanner, 'src', rel)).href);

const { toJSON, normalizeFindings } = await imp('report/index.js');
const { runAutopilot } = await imp('posture/autopilot.js');
const { createServer } = await imp('mcp/server.js');
const { signLastScan } = await imp('posture/integrity.js');

const report = toJSON(scanInput(), META);
const normalized = normalizeFindings(scanInput());

const auto = await runAutopilot({ stages: autopilotStages(), commit: COMMIT });

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-capture-'));
fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"compat"}');
const body = JSON.stringify(report);
fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), body);
fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
const { handleRequest } = createServer({ sessionRoot: dir });
const r = await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'explain_finding', arguments: { finding_id: 'F-compat-1' } } });
const mcp = JSON.parse(r.result.content[0].text);
fs.rmSync(dir, { recursive: true, force: true });

console.log(JSON.stringify({
  capturedFrom: 'commit 0a03121b scanner/src',
  reportJson: { topLevelKeys: Object.keys(report).sort(), finding: normalized[0] },
  mcpExplainFinding: mcp,
  autopilot: { result: auto.results[0], summary: auto.summary },
}, null, 2));
