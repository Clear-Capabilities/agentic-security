// graph-loader.js — Milestone 3, sub-project Server, increment 1.
//
// Reads and VERIFIES the `.agentic-security/lineage-graph.json` artifact
// before `explore` is allowed to serve a single byte of it. Reuses
// `posture/integrity.js`'s `verifyLastScan` DIRECTLY (per the plan and the
// root CLAUDE.md's own instruction) — this module does not implement any
// signature comparison of its own. `verifyLastScan` already uses
// `crypto.timingSafeEqual` internally.
//
// Loaded ONCE at server startup (see bin/agentic-security.js's cmdExplore)
// and held in memory for the life of the process — this is a read-only,
// single-scan-snapshot server; a change to the graph on disk mid-session is
// out of scope for this increment (threat-model doc's own "P0 is
// read-only" framing).

import * as fs from 'node:fs';
import { statePath } from '../posture/state-dir.js';
import { verifyLastScan } from '../posture/integrity.js';

/**
 * @param {string} scanRoot
 * @returns {{ok:true, graph:object} | {ok:false, reason:'missing'|'unsigned'|'tampered'|'malformed', message:string}}
 *
 * Four, and only four, distinct failure reasons — each with its own clear
 * message so an operator knows exactly what to do next:
 *   - 'missing'  — no lineage-graph.json at all. Run a scan with
 *                  AGENTIC_SECURITY_LINEAGE_DEEP=1 first.
 *   - 'unsigned' — the graph exists but its .sig sibling does not
 *                  (verifyLastScan returns null). Refuse to serve an
 *                  unverifiable graph.
 *   - 'tampered' — the graph exists and has a .sig, but the signature does
 *                  not match the body (verifyLastScan returns false). The
 *                  file was modified after signing, or signed under a
 *                  different install key.
 *   - 'malformed' — the body passed signature verification but is not
 *                  valid JSON. Should not happen from a normal scan; the
 *                  file may be corrupted on disk after signing.
 */
export function loadSignedGraph(scanRoot) {
  const graphPath = statePath(scanRoot, 'lineage-graph.json');
  const sigPath = graphPath + '.sig';

  if (!fs.existsSync(graphPath)) {
    return {
      ok: false,
      reason: 'missing',
      message: `No lineage graph found at ${graphPath}. Run a scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 first (e.g. \`AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan\`), then re-run \`agentic-security explore\`.`,
    };
  }

  let body;
  try {
    body = fs.readFileSync(graphPath, 'utf8');
  } catch (e) {
    return {
      ok: false,
      reason: 'missing',
      message: `Lineage graph found at ${graphPath} but could not be read: ${e && e.message ? e.message : e}.`,
    };
  }

  const verified = verifyLastScan(body, sigPath);
  if (verified === null) {
    return {
      ok: false,
      reason: 'unsigned',
      message: `Lineage graph at ${graphPath} has no signature file (${sigPath} is missing). Refusing to serve an unverifiable graph. Re-run the scan (AGENTIC_SECURITY_LINEAGE_DEEP=1) to regenerate both files together.`,
    };
  }
  if (verified === false) {
    return {
      ok: false,
      reason: 'tampered',
      message: `Lineage graph at ${graphPath} FAILED signature verification — its contents do not match ${sigPath}. The file may have been modified after the scan, or signed under a different install key. Refusing to serve a tampered graph. Re-run the scan to regenerate it.`,
    };
  }

  let graph;
  try {
    graph = JSON.parse(body);
  } catch (e) {
    return {
      ok: false,
      reason: 'malformed',
      message: `Lineage graph at ${graphPath} passed signature verification but is not valid JSON (${e && e.message ? e.message : e}). This should not happen from a normal scan — the file may be corrupted. Re-run the scan to regenerate it.`,
    };
  }

  return { ok: true, graph };
}
