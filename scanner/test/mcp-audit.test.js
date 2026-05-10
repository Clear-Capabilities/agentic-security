// MCP / Agent tool security audit — F1 over labelled fixtures.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

const LABELS = [
  { file: 'vuln-curl-pipe-sh.mcp.json',         positive: true,  matcher: /untrusted install/i },
  { file: 'vuln-floating-pin.mcp.json',         positive: true,  matcher: /floating tag/i },
  { file: 'vuln-hardcoded-cred.mcp.json',       positive: true,  matcher: /hardcoded credential/i },
  { file: 'vuln-fs-overscope.mcp.json',         positive: true,  matcher: /filesystem.*root.*HOME|filesystem server granted root/i },
  { file: 'vuln-dangerous-capability.mcp.json', positive: true,  matcher: /dangerous capability/i },
  { file: 'vuln-prompt-injection-desc.mcp.json',positive: true,  matcher: /prompt-injection/i },
  { file: 'safe-pinned.mcp.json',               positive: false, matcher: /^MCP:/i },
  { file: 'safe-fs-scoped.mcp.json',            positive: false, matcher: /^MCP:/i },
  { file: 'safe-env-from-secret.mcp.json',      positive: false, matcher: /^MCP:/i },
];

test('MCP audit — F1 evaluation', async () => {
  await evaluateF1({
    name: 'MCP-audit',
    fixtureDir: 'mcp-audit',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});
