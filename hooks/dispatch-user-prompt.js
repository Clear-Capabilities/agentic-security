#!/usr/bin/env node
// UserPromptSubmit dispatcher (#24 — hook process consolidation).
//
// Runs BOTH UserPromptSubmit hooks in ONE node process instead of two: it reads
// stdin once, runs the legacy-alias redirect and the model-cost advisor
// in-process, and emits a single merged hook output. Both sub-hooks are purely
// advisory (neither can block a prompt), so the merge is a plain union:
//   • legacy-alias-redirect → hookSpecificOutput.additionalContext
//   • model-cost-advisor    → systemMessage (never additionalContext → 0 tokens)
//
// Halving the per-prompt process spawns (2 → 1) removes a latency tax paid on
// every single user turn. Behaviour is otherwise identical to the two standalone
// hooks; each is wrapped so one failing never suppresses the other.
'use strict';
const { resolveAlias, buildContext } = require('./legacy-alias-redirect.js');
const { advise } = require('./model-cost-advisor.js');

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    // Never hang the prompt submit if stdin is empty.
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

// Pure merge — importable for tests. Given the two sub-hook results, produce the
// single UserPromptSubmit hook-output object (or {} when neither fired).
function mergeOutputs({ aliasHit, tip }) {
  const out = {};
  if (aliasHit) {
    out.hookSpecificOutput = {
      hookEventName: 'UserPromptSubmit',
      additionalContext: buildContext(aliasHit),
    };
  }
  if (tip) out.systemMessage = tip;
  return out;
}

async function main() {
  const input = await readStdinJSON();
  let aliasHit = null;
  let tip = null;
  try { aliasHit = resolveAlias(input.prompt || ''); } catch { /* best-effort */ }
  try { tip = await advise(input); } catch { /* best-effort */ }
  const out = mergeOutputs({ aliasHit, tip });
  if (Object.keys(out).length) process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = { mergeOutputs };
