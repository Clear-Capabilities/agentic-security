#!/usr/bin/env node
// PRD F5.3 exit gate — "agent trust-boundary flow modelled in the taint layer
// WITH A LOCALIZED-TP DELTA".
//
// The modelling landed; the delta was never measured, so the claim was
// "we built it" rather than "it finds things". This measures the second.
//
// ── The sub-population, and why it exists by accident ────────────────────────
//
// `bench/independent` is mined from published advisories, and until the
// population grew from 315 to 1004 (F12.4) it contained essentially no agent
// code. It now carries a real agent-tool sub-population: MCP servers with real
// CVEs, in TypeScript, Python, Go and Java. That was not planned — it is what
// the advisory feed contains once you can page past the first hundred entries.
//
// Membership is COMPUTED here from the tree, never hardcoded, so the set grows
// with the corpus instead of freezing at whatever was true today.
//
// ── What the delta is ────────────────────────────────────────────────────────
//
// The agent-tool boundary is modelled as taint SOURCES (`provenance:
// 'agent-tool'` in the catalog: `@mcp.tool()` parameters, `request.params`,
// `params.arguments`). A finding whose flow starts at one of those sources
// would not exist without the feature — there would be no source, so no flow.
// So:
//
//     delta = localized true positives on this sub-population whose taint
//             source carries agent-tool provenance
//
// Reported against the sub-population's total localized TPs, so the answer is
// a share and not a bare count.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { withEntryTimeout, EntryTimeout } from '../_lib/watchdog.mjs';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, 'cache');
const RESULT = path.join(HERE, 'RESULT-agent-boundary.json');
const BUDGET_MS = Number(process.env.AGENT_DELTA_TIMEOUT_MS || 600_000);

// Markers of an agent-tool boundary in the tree. Deliberately the SDK surfaces
// rather than the string "mcp": a repository can mention the protocol in a
// README without implementing a tool.
const AGENT_MARKER = /@mcp\.tool|@server\.tool|modelcontextprotocol|McpServer|setRequestHandler/;
const SRC_EXT = /\.(?:py|ts|tsx|js|jsx|mjs|cjs|go|java)$/i;

function treeHasAgentCode(dir) {
  const stack = [dir];
  let scanned = 0;
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(cur, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.agentic-security' || e.name === '.git') continue;
        stack.push(p);
        continue;
      }
      if (!SRC_EXT.test(e.name)) continue;
      if (++scanned > 4000) return false;
      let body;
      try { body = fs.readFileSync(p, 'utf8'); } catch { continue; }
      if (AGENT_MARKER.test(body)) return true;
    }
  }
  return false;
}

/** Does this finding's flow start at an agent-tool source? */
function isAgentSourced(f) {
  const src = f && f.source;
  if (!src) return false;
  if (src.provenance === 'agent-tool') return true;
  // The label is the human-readable form of the same catalog entry; matched as
  // a fallback because the provenance field is not carried on every path.
  return /mcp|tool call|@server\.tool|@mcp\.tool/i.test(String(src.label || ''));
}

function pct(n, d) { return d === 0 ? null : Number(((n / d) * 100).toFixed(2)); }

async function main() {
  await disableStateWrites();
  const {
    scanDirRaw, purgeScanState, findMatchingFindings, isLocalized, changedLineRanges, isHeldOut,
  } = await import('./runner.mjs');

  const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
  const rows = [];
  const unscored = [];
  let inspected = 0, members = 0;

  for (const e of manifest.entries) {
    const preDir = path.join(CACHE, e.id, 'pre');
    if (!fs.existsSync(preDir)) continue;
    inspected++;
    if (!treeHasAgentCode(preDir)) continue;
    members++;

    purgeScanState(preDir);
    let findings;
    try {
      ({ findings } = await withEntryTimeout(scanDirRaw(preDir), e.id, BUDGET_MS));
    } catch (err) {
      unscored.push({ id: e.id, reason: err instanceof EntryTimeout ? 'timeout' : err.message });
      continue;
    }

    const matching = findMatchingFindings(findings, e.cwe, e.files);
    let localizedTPs = 0, agentSourced = 0;
    const sourceLabels = new Set();
    for (const f of matching) {
      const rel = e.files.find((x) => String(f.file || '').replace(/\\/g, '/').endsWith(x));
      if (!rel) continue;
      const ranges = changedLineRanges(
        path.join(CACHE, e.id, 'pre', rel), path.join(CACHE, e.id, 'post', rel));
      if (!ranges || !isLocalized(f.line, ranges)) continue;
      localizedTPs++;
      if (isAgentSourced(f)) { agentSourced++; sourceLabels.add(String(f.source?.label || f.source?.provenance || '?')); }
    }
    rows.push({
      id: e.id, cwe: e.cwe, language: e.language, heldOut: isHeldOut(e.id),
      localizedTPs, agentSourced, sourceLabels: [...sourceLabels],
    });
    process.stderr.write(`  ${agentSourced ? '✓' : '·'} ${e.id.padEnd(24)} ${String(e.cwe).padEnd(9)} ` +
      `localizedTP=${localizedTPs} agentSourced=${agentSourced}\n`);
  }

  const sum = (f) => rows.reduce((a, r) => a + f(r), 0);
  const tp = sum((r) => r.localizedTPs), agent = sum((r) => r.agentSourced);
  const heldRows = rows.filter((r) => r.heldOut);

  const result = {
    prd: 'F5.3',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    subPopulation: {
      entriesInspected: inspected,
      entriesWithAgentToolCode: members,
      selectedBy: 'computed from the tree — SDK surfaces, not the word "mcp" in a README',
    },
    localizedTruePositives: { n: tp, d: members },
    delta: { n: agent, d: tp, pct: pct(agent, tp), means: 'localized TPs whose taint source carries agent-tool provenance — findings that would not exist without the boundary being modelled' },
    heldOut: {
      entries: heldRows.length,
      localizedTruePositives: heldRows.reduce((a, r) => a + r.localizedTPs, 0),
      delta: heldRows.reduce((a, r) => a + r.agentSourced, 0),
    },
    unscored, rows,
  };
  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');

  if (process.argv.includes('--json')) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }
  process.stdout.write(`\nbench/independent agent trust-boundary delta — engine ${result.engineVersion}\n\n`);
  process.stdout.write(`entries inspected                 ${inspected}\n`);
  process.stdout.write(`entries WITH agent-tool code      ${members}\n`);
  process.stdout.write(`localized true positives on them  ${tp}\n`);
  process.stdout.write(`  of which agent-tool sourced     ${agent}${tp ? ` = ${pct(agent, tp)}%` : ''}   <- the delta\n`);
  process.stdout.write(`held-out slice                    ${heldRows.length} entries, delta ${result.heldOut.delta}\n`);
  if (unscored.length) process.stdout.write(`UNSCORED: ${unscored.map((u) => `${u.id} (${u.reason})`).join(', ')}\n`);
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main().catch((e) => { process.stderr.write(`agent-boundary delta failed: ${e.stack}\n`); process.exit(1); });
