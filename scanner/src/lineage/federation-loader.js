// federation-loader.js — M5 deliverable #8 (FR-304's "declared" half):
// loadRemoteGraphExport(filePath) reads an exportGraphJSON-shaped file
// (dataflow export --format json's own artifact) — chosen over the
// local server's signed-graph reader (`scanner/src/server/`, whose
// loadSignedGraph is what `agentic-security explore` uses) for the
// cross-machine reason this deliverable's own scoping investigation
// found: loadSignedGraph authenticates against a PER-INSTALL HMAC key,
// which is the wrong trust model for a file that crossed a repo/machine
// boundary in the common case (two repos scanned on two different
// machines sign under two different keys by default, so pointing
// loadSignedGraph at a second repo's checkout would, in the common case,
// correctly report 'tampered' even though nothing was actually
// tampered with). exportGraphJSON's portable, embedded-digest artifact
// is a SELF-CONSISTENCY check instead — never authentication, disclosed
// as such everywhere this module or its callers describe it.
//
// Mirrors that reader's own four-distinct-outcome discipline, with one
// structural difference: a digest mismatch here is NOT a blocking
// failure (`ok:false`) the way all four of its reasons are — it is a
// WARNING the caller must show, never silently swallowed, and does not
// by itself block a --yes write (the operator is explicitly asserting
// this file). `ok:true, digestMatches:false` is therefore a real,
// valid, non-failing outcome; only `missing`/`malformed`/
// `invalid-graph` set `ok:false`.
//
// The self-consistency check recomputes `computeGraphDigest(parsed.graph)`
// and compares it to the file's own embedded `bodyDigest` (final
// whole-branch review, M5 deliverable #8, B1 — NOT `digest`, a real bug
// that survived five clean task-level reviews). `export-json.js`'s
// `digest` field always identifies the SOURCE graph an export was taken
// from, regardless of redaction/filtering — comparing it against a
// recomputation over `parsed.graph` (which IS the redacted/filtered
// `graph:` body under the CLI's own default settings) fails under the
// exact common case a self-consistency check exists to pass: an
// un-tampered, default-redacted export would permanently read
// `digestMatches: false`, and a genuine tamper would be indistinguishable
// from routine redaction. `bodyDigest` identifies the exact bytes this
// file actually contains, which is what a self-consistency check over a
// received file needs.

import * as fs from 'node:fs';
import { validateGraph } from './validate.js';
import { computeGraphDigest } from './export-json.js';

/**
 * @param {string} filePath
 * @returns {{
 *   ok: boolean,
 *   graph: object|null,
 *   digest: string|null,
 *   digestMatches: boolean|null,
 *   reason: 'missing'|'malformed'|'invalid-graph'|'digest-mismatch'|null,
 *   message: string|null,
 * }}
 */
export function loadRemoteGraphExport(filePath) {
  if (!filePath || typeof filePath !== 'string' || !fs.existsSync(filePath)) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'missing',
      message: `No remote graph export found at ${filePath}. Run \`dataflow export --format json\` in the remote repository and point --remote-graph at the resulting file.`,
    };
  }

  let body;
  try {
    body = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'missing',
      message: `Remote graph export found at ${filePath} but could not be read: ${e && e.message ? e.message : e}.`,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'malformed',
      message: `Remote graph export at ${filePath} is not valid JSON (${e && e.message ? e.message : e}).`,
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
    || typeof parsed.bodyDigest !== 'string' || !parsed.bodyDigest
    || !parsed.graph || typeof parsed.graph !== 'object' || Array.isArray(parsed.graph)) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'malformed',
      message: `Remote graph export at ${filePath} does not look like an \`exportGraphJSON\` artifact — expected top-level "bodyDigest" (string) and "graph" (object) fields. Run \`dataflow export --format json\` to produce a valid one.`,
    };
  }

  const { valid, errors } = validateGraph(parsed.graph);
  if (!valid) {
    return {
      ok: false, graph: null, digest: parsed.bodyDigest, digestMatches: null, reason: 'invalid-graph',
      message: `Remote graph export at ${filePath} does not contain a well-formed DataFlowGraph v1 document: ${errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`,
    };
  }

  const recomputed = computeGraphDigest(parsed.graph);
  const digestMatches = recomputed === parsed.bodyDigest;
  if (!digestMatches) {
    return {
      ok: true, graph: parsed.graph, digest: parsed.bodyDigest, digestMatches: false, reason: 'digest-mismatch',
      message: 'WARNING: the remote export\'s embedded digest does not match its own content (self-consistency check failed) — this is NOT authentication, only a check that the file has not been altered since it was exported. Proceeding is a real trust decision the operator is making explicitly.',
    };
  }

  return { ok: true, graph: parsed.graph, digest: parsed.bodyDigest, digestMatches: true, reason: null, message: null };
}
