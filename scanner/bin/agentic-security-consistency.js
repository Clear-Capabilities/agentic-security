#!/usr/bin/env node
// CLI front-end for the LLM-validator consistency harness.
//
// Reads .agentic-security/last-scan.json from the project root, picks the
// top-N findings with precise file:line locations (validator preflight
// requires them), and runs N trials of the validator on the same finding
// set. Reports pass^N (unanimous-verdict rate) and per-finding flap detail.
//
// The validator endpoint is configured via the usual env vars:
//   AGENTIC_SECURITY_LLM_VALIDATE=1
//   AGENTIC_SECURITY_LLM_ENDPOINT=https://...
//   AGENTIC_SECURITY_LLM_API_KEY=...
//   AGENTIC_SECURITY_LLM_MODEL=...
//
// When the validator is off (env unset), every verdict will be 'unvalidated'
// and pass^N is trivially 100%. That's an honest signal; deploy with the
// validator on if you care about its behavior.
//
// Usage:
//   agentic-security-consistency               # uses last-scan, 5 trials, 5 findings
//   agentic-security-consistency --trials 10
//   agentic-security-consistency --top 3
//   agentic-security-consistency --json
'use strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { measureConsistency, summarize } from '../src/llm-validator/consistency.js';

import { statePath } from '../src/posture/state-dir.js';
function args() {
  const a = process.argv.slice(2);
  const out = { trials: 5, top: 5, json: false, root: process.cwd() };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--trials') out.trials = parseInt(a[++i], 10);
    else if (a[i] === '--top') out.top = parseInt(a[++i], 10);
    else if (a[i] === '--json') out.json = true;
    else if (a[i] === '--root') out.root = a[++i];
  }
  return out;
}

async function main() {
  const opts = args();
  const scanFile = statePath(opts.root, 'last-scan.json');
  if (!fs.existsSync(scanFile)) {
    console.error(`no last-scan.json at ${scanFile} — run a scan first`);
    process.exit(2);
  }
  let scan;
  try { scan = JSON.parse(fs.readFileSync(scanFile, 'utf8')); }
  catch (e) { console.error(`failed to parse last-scan.json: ${e.message}`); process.exit(2); }
  // Pick findings the validator can actually grade: must have precise file+line.
  const candidates = (scan.findings || [])
    .filter(f => f && typeof f.file === 'string' && f.file.length > 0 &&
                 typeof f.line === 'number' && f.line > 0)
    .slice(0, opts.top);
  if (!candidates.length) {
    console.error('no findings with precise locations in last-scan.json');
    process.exit(2);
  }
  // Build fileContents map from scan.fc if present, otherwise read from disk.
  const fileContents = (scan.fc && typeof scan.fc === 'object') ? scan.fc : {};
  for (const f of candidates) {
    if (fileContents[f.file]) continue;
    try {
      const fp = path.join(opts.root, f.file);
      if (fs.existsSync(fp)) fileContents[f.file] = fs.readFileSync(fp, 'utf8');
    } catch { /* skip */ }
  }
  const r = await measureConsistency({
    findings: candidates, fileContents,
    scanRoot: opts.root, trials: opts.trials,
  });
  if (opts.json) {
    console.log(JSON.stringify(r, null, 2));
    return;
  }
  console.log(summarize(r));
}

main().catch(e => { console.error(e); process.exit(1); });
