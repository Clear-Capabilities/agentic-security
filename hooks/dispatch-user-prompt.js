#!/usr/bin/env node
// UserPromptSubmit dispatcher (#24 — hook process consolidation).
//
// The single UserPromptSubmit hook. It reads stdin once, runs the legacy-alias
// redirect in-process and emits its output:
//   • legacy-alias-redirect → hookSpecificOutput.additionalContext
// The per-prompt model-cost advisor that also ran here was removed in 0.195.34.
// The redirect is purely advisory and cannot block a prompt; a failure writes
// nothing and exits 0.
'use strict';
const { resolveAlias, buildContext } = require('./legacy-alias-redirect.js');

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

// Pure — importable for tests. Given the redirect's result, produce the
// UserPromptSubmit hook-output object (or {} when it did not fire).
function mergeOutputs({ aliasHit }) {
  if (!aliasHit) return {};
  return { hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: buildContext(aliasHit) } };
}

async function main() {
  const input = await readStdinJSON();
  let aliasHit = null;
  try { aliasHit = resolveAlias(input.prompt || ''); } catch { /* best-effort */ }
  const out = mergeOutputs({ aliasHit });
  if (Object.keys(out).length) process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = { mergeOutputs };
