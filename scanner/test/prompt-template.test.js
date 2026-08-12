// Prompt template security audit — F1 over labelled fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateF1 } from './helpers/f1.js';
import { scanPromptTemplate } from '../src/sast/prompt-template.js';

const LABELS = [
  { file: 'vuln-fstring-prompt.py',     positive: true,  matcher: /Prompt Template:.*interpolated/i },
  { file: 'vuln-template-literal.js',   positive: true,  matcher: /Prompt Template:.*interpolated/i },
  { file: 'prompts/vuln-prompt.j2',     positive: true,  matcher: /Prompt Template:.*isolation markers/i },
  { file: 'safe-messages-array.py',     positive: false, matcher: /^Prompt Template:/i },
  { file: 'safe-messages-array.js',     positive: false, matcher: /^Prompt Template:/i },
  { file: 'prompts/safe-isolated.j2',   positive: false, matcher: /^Prompt Template:/i },
];

test('Prompt template — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Prompt-template',
    fixtureDir: 'prompt-template',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});

// Stage 4 correctness audit: `hasRoleSeparation = isCodeFile &&
// ROLE_SEPARATION_RE.test(raw)` checks the WHOLE FILE for a properly
// role-separated messages:[{role, content}] call, and CASE 2 (inline
// f-string / template-literal prompt scanning) is skipped ENTIRELY when
// hasRoleSeparation is true — `if (isCodeFile && !hasRoleSeparation)`. One
// well-formed LLM call anywhere in a file suppresses every OTHER inline
// prompt-injection candidate in that same file, including ones with zero
// isolation and raw user input. Pre-existing F1 fixtures can't catch this:
// each fixture file contains either the safe pattern or the vulnerable one,
// never both, so this same-file interaction was never exercised.
test('prompt-template: a properly role-separated call elsewhere in the file does not blanket-suppress an unrelated, unisolated inline prompt', () => {
  const filler = Array.from({ length: 30 }, (_, i) => `console.log("filler line ${i}");`).join('\n');
  const src = [
    "function properCall(userInput) {",
    "  return openai.chat({ messages: [{role: 'system', content: SYS_PROMPT}, {role: 'user', content: userInput}] });",
    "}",
    filler,
    "function vulnerableCall(userInput) {",
    "  const prompt = `You are an assistant. Instructions: follow the user. User says: ${userInput}`;",
    "  return callLLM(prompt);",
    "}",
  ].join('\n');
  const out = scanPromptTemplate('app.js', src);
  assert.ok(out.some(f => /interpolated/i.test(f.vuln)),
    `expected the unisolated inline prompt in vulnerableCall to still fire; got ${out.length} findings: ${JSON.stringify(out.map(f => f.vuln))}`);
});
