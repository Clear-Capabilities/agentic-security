#!/usr/bin/env node
// PreToolUse (Task|Agent|mcp__*) capability advisory (X-505.AC01).
//
// Delegation and MCP tool calls are explained against the capability policy with
// the same decision function the runner and the MCP tool gate use. ADVISORY ONLY:
// this hook always exits 0 and never blocks. Inert (no output) unless the operator
// enabled `capability-enforcement` in the environment and named a manifest.
'use strict';
const { capabilityAdvice, operatorGate } = require('./lib/capability-advice.js');

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

(async () => {
  if (!operatorGate(process.env)) process.exit(0);
  const evt = await readStdinJSON();
  try {
    const adv = await capabilityAdvice(evt);
    if (adv) process.stderr.write(adv.join('\n') + '\n');
  } catch { /* advice is best-effort */ }
  process.exit(0);
})();
