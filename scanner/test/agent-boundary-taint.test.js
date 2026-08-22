// PRD F5.3 — the agent trust boundary as DATAFLOW, not regex.
//
// `agent-untrusted-flow.js` and `agent-tool-escalation.js` are pattern-based, so
// they see a tool argument reaching a sink only when both appear in a shape
// someone anticipated. The real shape is a flow: tool output -> model context ->
// tool invocation, across assignments and helper calls the taint engine already
// follows for HTTP input.
//
// The boundary was modelled for PYTHON ONLY (`@mcp.tool`, `@server.tool`) while
// the TypeScript SDK is the dominant implementation — so the language most
// agent servers are written in had no agent-tool source at all.
//
// WHY A TOOL ARGUMENT IS UNTRUSTED: whatever the model was persuaded to pass —
// by a web page it read, a file it opened, or another tool's output. Treating it
// as trusted because "the model sent it" is the confused-deputy assumption this
// feature exists to reject.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CATALOG } from '../src/dataflow/catalog.js';

const agentSources = () => CATALOG.filter((e) => e.kind === 'source' && e.provenance === 'agent-tool');

test('the agent-tool boundary is modelled in JavaScript, not only Python', () => {
  const langs = new Set(agentSources().map((e) => e.language));
  assert.ok(langs.has('py'), 'python coverage must be retained');
  assert.ok(langs.has('js'), 'the TypeScript SDK is the dominant MCP implementation and had no source at all');
});

test('MCP tool ARGUMENTS are a source', () => {
  const ids = agentSources().map((e) => e.id);
  assert.ok(ids.includes('js-mcp-call-args'), 'request.params.arguments is the CallToolRequest shape');
});

test('MCP tool OUTPUT is a source too — the indirect-injection half', () => {
  // F5.3's shape is tool output -> model context -> tool invocation. With only
  // tool INPUT modelled, a server that reads a resource and passes it onward was
  // invisible: content returned by another tool is third-party text that reached
  // the context window, not the agent's own reasoning.
  const ids = agentSources().map((e) => e.id);
  assert.ok(ids.some((i) => /tool-result|resource-contents/.test(i)),
    'tool result / resource content must be sources or indirect injection is unmodelled');
});

test('every agent-tool source carries a label a report can render', () => {
  for (const e of agentSources()) {
    assert.ok(typeof e.label === 'string' && e.label.length > 3, `${e.id} needs a human-readable label`);
  }
});

test('agent-tool sources have unique ids', () => {
  const ids = agentSources().map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length, 'a duplicate id silently shadows a source');
});

test('the provenance is distinct from http input', () => {
  // The distinction is what lets a report say "this came across the AGENT
  // boundary" rather than lumping it in with web input. Collapsing them would
  // lose the one fact that makes these findings actionable for an agent author.
  for (const e of agentSources()) {
    assert.equal(e.provenance, 'agent-tool');
    assert.notEqual(e.provenance, 'http-body');
  }
});

test('a tool argument flowing to a shell sink is taint-tracked end to end', async () => {
  // The property that separates dataflow from regex: the value moves through an
  // assignment and a helper before reaching the sink, which a pattern rule
  // anchored on one line cannot follow.
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { runScan } = await import('../src/runScan.js');

  // Deep interprocedural taint is opt-in under CI (see bench/mutation/runner.mjs,
  // which sets the same pair). Without it the value is only reachable by the
  // pattern rules — which is precisely what this test exists to prove is not
  // enough, so running it shallow would assert the opposite of the intent.
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentflow-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{"name":"srv","version":"1.0.0"}');
    fs.writeFileSync(path.join(d, 'server.js'), [
      "const { exec } = require('child_process');",
      "const { Server } = require('@modelcontextprotocol/sdk/server/index.js');",
      'const server = new Server({ name: "files", version: "1.0.0" });',
      'function run(cmd) { return exec(cmd, () => {}); }',
      'server.setRequestHandler("tools/call", async (request) => {',
      '  const target = request.params.arguments.path;',   // agent-tool source
      '  const command = `ls -la ${target}`;',             // flows through a template
      '  return run(command);',                            // ...and a helper, into exec
      '});',
      'module.exports = server;',
    ].join('\n'));

    const { scan } = await runScan(d);
    const cmdi = (scan.findings || []).filter((f) => String(f.cwe) === 'CWE-78');
    assert.ok(cmdi.length > 0,
      'a tool argument reaching a shell sink through an assignment and a helper must be reported');
    assert.ok(cmdi.some((f) => f.parser === 'IR-TAINT'),
      'it must be found by the TAINT engine, not a pattern rule — that is the whole point of F5.3');
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
});
