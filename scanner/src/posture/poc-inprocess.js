// In-process proof-of-concept synthesis (R2 — closing the automatic loop).
//
// WHY A SECOND POC KIND. `poc-generator.js` emits *HTTP* PoCs: they take a URL
// and a param and hit a running server. Those are the right artifact for a
// human reproducing a bug against a deployed app, but they cannot be executed
// by `execution-proof.js` — the sandbox denies network egress and there is no
// server inside it. That is the concrete reason nothing in the scan pipeline
// ever produced an `execution-proven` finding: the PoCs it generated were
// unrunnable *by construction* in the only place proofs are allowed to run.
//
// This module emits the other kind: a self-contained script that imports the
// vulnerable file directly, calls the exported handler with a crafted request,
// and lets the injected payload write the proof marker. No server, no network,
// no fixture discovery.
//
// DELIBERATELY NARROW. It refuses far more than it accepts, and that is the
// design rather than a gap to close later. A PoC that runs but proves nothing
// is worse than no PoC: `proof-failed` is a triage signal about the FINDING,
// so a template that misfires manufactures evidence against real bugs. Every
// refusal below is a case where the generated script would have been a guess.
//
// SAFETY. The payload is a shell redirect that creates a marker file inside
// the sandbox root (`> PROVEN`). It is the least destructive thing that still
// proves arbitrary command execution: no network, no writes outside the root,
// no privilege attempts, and it is only ever executed inside R1's sandbox with
// egress denied and the filesystem confined.

const MARKER = 'PROVEN';

// Only families where "the injected payload ran" is observable from a marker
// file. Others (XSS, weak crypto) need a browser or a judgement call about
// output, and a marker-file proof would be a category error.
const SUPPORTED = new Set(['command-injection', 'code-injection']);

const JS_EXT = /\.(js|cjs|mjs)$/i;

// A handler we can call: `module.exports = function (req, res)` or
// `module.exports.name = function (req, res)` / `exports.name = ...`.
// Arrow and function forms both count. The two-parameter (req, res) shape is
// required — a one-arg export is not an Express-style handler and calling it
// with a fake request would be inventing an interface.
const HANDLER_RES = [
  /module\.exports\s*=\s*(?:async\s+)?function\s*\w*\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)/,
  /module\.exports\s*=\s*(?:async\s+)?\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>/,
];
const NAMED_HANDLER_RES = [
  /(?:module\.)?exports\.(\w+)\s*=\s*(?:async\s+)?function\s*\w*\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)/,
  /(?:module\.)?exports\.(\w+)\s*=\s*(?:async\s+)?\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>/,
];

// The request property the handler reads. Anchored to the request identifier
// the export actually binds, so a file that reads `req.query` while exporting
// `(request, response)` does not produce a PoC built on the wrong name.
function _requestSource(content, reqIdent) {
  const esc = reqIdent.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const prop of ['query', 'body', 'params']) {
    const re = new RegExp(`\\b${esc}\\.${prop}\\.(\\w+)`);
    const m = content.match(re);
    if (m) return { prop, key: m[1] };
  }
  return null;
}

// The sink must interpolate into a SHELL, not an argv array. `exec`/`execSync`
// run through a shell so `; > PROVEN` executes; `execFile`/`spawn` with an
// array do not, and a marker PoC against those would fail for a reason that
// has nothing to do with whether the finding is real.
const SHELL_SINK = /\b(?:exec|execSync)\s*\(/;
const ARGV_SINK = /\b(?:execFile|execFileSync|spawn|spawnSync)\s*\(/;

/**
 * Synthesize a sandbox-runnable PoC, or return a refusal explaining why not.
 *
 * @returns {{ok:true, poc:object} | {ok:false, reason:string}}
 */
export function synthesizeInProcessPoc(finding, fileContent) {
  if (!finding || typeof finding !== 'object') return { ok: false, reason: 'no finding' };
  if (!SUPPORTED.has(finding.family)) {
    return { ok: false, reason: `family '${finding.family || 'unknown'}' has no marker-observable in-process template` };
  }
  if (!finding.file || !JS_EXT.test(finding.file)) {
    return { ok: false, reason: 'in-process PoCs are JavaScript-only today' };
  }
  if (typeof fileContent !== 'string' || !fileContent.trim()) {
    return { ok: false, reason: 'the vulnerable file content was not available' };
  }
  if (/^\s*(?:import|export)\s/m.test(fileContent) && !/module\.exports/.test(fileContent)) {
    return { ok: false, reason: 'ES-module source: the CommonJS handler shapes do not apply' };
  }

  if (!SHELL_SINK.test(fileContent)) {
    return {
      ok: false,
      reason: ARGV_SINK.test(fileContent)
        ? 'the sink passes an argv array, so a shell-metacharacter payload would not execute — absence of proof here would say nothing about the finding'
        : 'no shell-executing sink found in the file',
    };
  }

  // Default export first, then a named one.
  let call = null, reqIdent = null;
  for (const re of HANDLER_RES) {
    const m = fileContent.match(re);
    if (m) { call = { kind: 'default', name: null }; reqIdent = m[1]; break; }
  }
  if (!call) {
    for (const re of NAMED_HANDLER_RES) {
      const m = fileContent.match(re);
      if (m) { call = { kind: 'named', name: m[1] }; reqIdent = m[2]; break; }
    }
  }
  if (!call) {
    return { ok: false, reason: 'no exported two-argument (req, res) handler found — nothing to call without inventing an interface' };
  }

  const src = _requestSource(fileContent, reqIdent);
  if (!src) {
    return { ok: false, reason: `the handler does not read query/body/params off '${reqIdent}', so the injection point is unknown` };
  }

  const base = finding.file.split(/[\\/]/).pop();
  const imported = call.kind === 'default' ? 'handler' : `{ ${call.name} }`;
  const invoke = call.kind === 'default' ? 'handler' : call.name;

  // The timer is unref'd so the process exits as soon as the handler responds.
  // Without that it stays alive for the full timeout even after the exploit
  // has landed, and on a loaded machine it can outlive the proof budget — at
  // which point `attachProofTier` demotes a real proof to its static tier
  // because `ran` is false. Correct, but it throws away a genuine result.
  const code = [
    `// Auto-generated in-process proof-of-concept for ${finding.file}.`,
    '// Proves arbitrary command execution by having the injected payload',
    `// create the marker file '${MARKER}' inside the sandbox root.`,
    `import ${imported} from './${base}';`,
    'await new Promise((resolve) => {',
    '  const res = {',
    '    send: () => resolve(), json: () => resolve(), end: () => resolve(),',
    '    status: () => ({ send: () => resolve(), json: () => resolve(), end: () => resolve() }),',
    '  };',
    `  const req = { ${src.prop}: ${JSON.stringify({ [src.key]: `x; > ${MARKER}` })} };`,
    `  try { ${invoke}(req, res); } catch { resolve(); }`,
    '  setTimeout(resolve, 4000).unref();',
    '});',
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js',
      kind: 'in-process',
      family: finding.family,
      cwe: finding.cwe || null,
      marker: MARKER,
      paramKey: src.key,
      paramSource: src.prop,
      handler: call.kind === 'default' ? 'module.exports' : `exports.${call.name}`,
      // The file the PoC imports. `execution-proof.js` materialises this into
      // the sandbox root; without it the import fails and nothing is proved.
      requires: [base],
      code,
    },
  };
}

export const _internals = { MARKER, SUPPORTED, _requestSource };
