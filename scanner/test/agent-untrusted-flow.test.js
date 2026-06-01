// R20 — agent-loop taint tests (untrusted content → high-privilege sink).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanAgentUntrustedFlow } from '../src/sast/agent-untrusted-flow.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fix = (p) => fs.readFileSync(path.join(__dirname, 'fixtures', 'agent-untrusted-flow', p), 'utf8');

test('py: retrieved doc body → os.system fires', () => {
  const f = scanAgentUntrustedFlow('a.py', fix('vulnerable/rag_exec.py'));
  assert.equal(f.length, 1, `expected 1 finding, got ${f.length}`);
  assert.equal(f[0].family, 'agent-untrusted-flow');
  assert.equal(f[0].cwe, '94');
  assert.equal(f[0].owaspLlm, 'LLM01');
});

test('py: human-approval mediation between source and sink suppresses it', () => {
  assert.equal(scanAgentUntrustedFlow('a.py', fix('clean/rag_guarded.py')).length, 0);
});

test('js: retrieved doc → exec fires (direct member access)', () => {
  const code = `
    const retriever = vectorstore.asRetriever();
    const docs = await retriever.get_relevant_documents(q);
    exec(docs[0].page_content);
  `;
  assert.equal(scanAgentUntrustedFlow('a.js', code).length, 1);
});

test('js: one assignment hop (cmd = doc.page_content; eval(cmd)) fires', () => {
  const code = `
    const docs = await retriever.similarity_search(q);
    const cmd = docs[0].page_content;
    eval(cmd);
  `;
  const f = scanAgentUntrustedFlow('a.js', code);
  assert.equal(f.length, 1, `expected 1, got ${f.length}`);
});

test('precision: non-agent file does not fire (context gate)', () => {
  const code = `const x = readFileSync('cfg'); exec(x);`; // no retriever/LLM context
  assert.equal(scanAgentUntrustedFlow('a.js', code).length, 0);
});

test('precision: retrieved content NOT reaching a sink does not fire', () => {
  const code = `
    const docs = await retriever.get_relevant_documents(q);
    res.json(docs[0].page_content);  // rendered, not executed
  `;
  assert.equal(scanAgentUntrustedFlow('a.js', code).length, 0);
});

test('precision: a static (non-retrieved) command in agent context does not fire', () => {
  const code = `
    const docs = await retriever.get_relevant_documents(q);   // agent context present
    exec('ls -la /tmp');                                      // literal, not untrusted
  `;
  assert.equal(scanAgentUntrustedFlow('a.js', code).length, 0);
});
