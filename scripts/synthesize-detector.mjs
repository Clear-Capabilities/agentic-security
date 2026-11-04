#!/usr/bin/env node
// Detector-spec synthesis: a detector-spec PROPOSAL drafted by a model from sample vulnerable files, for a human to review. This is a
// one-time code-generation aid, never runtime detection: the proposal is written to a file you name, and nothing installs it.
//
// Usage:
//   node scripts/synthesize-detector.mjs --cwe CWE-79 --lang csharp --files <path1> <path2> ... [--out <file>] [--force] [--model <name>]
//
// Gating, all enforced in scanner/src/discovery/detector-spec-synthesis.js (this file only parses arguments and prints):
//   - the `detector-spec-synthesis` assurance feature must be on (AGENTIC_SECURITY_ASSURANCE_DETECTOR_SPEC_SYNTHESIS=1, or the project's
//     .agentic-security/assurance.yml), and AGENTIC_SECURITY_LLM_ENDPOINT must name the operator's model endpoint;
//   - the egress policy (deny, local-only) is evaluated BEFORE any sample file is read: a denied call reads nothing;
//   - the samples are read within stated byte limits, the prompt is redacted, sized, sent through the shared bounded model call with a
//     deadline and bounded retries, and the call is audited;
//   - the reply is parsed string-aware and validated closed-world (identifiers only, no patterns); raw model text is never printed.
//
// Exit codes: 0 a valid proposal; 2 the policy or the feature refused (the decision is printed); 3 the reply was not a valid proposal
// (the reasons are printed); 4 a usage or limit problem.
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { synthesizeDetectorSpec, writeProposal, EXIT, LANGUAGES } from '../scanner/src/discovery/detector-spec-synthesis.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const args = { files: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cwe') args.cwe = argv[++i];
    else if (a === '--lang') args.lang = argv[++i];
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--model') args.model = argv[++i];
    else if (a === '--force') args.force = true;
    else if (a === '--files') { while (i + 1 < argv.length && !argv[i + 1].startsWith('--')) args.files.push(argv[++i]); }
    else if (a === '--help' || a === '-h') args.help = true;
    else { args.unknown = a; }
  }
  return args;
}

function usage() {
  console.error(`Usage: synthesize-detector.mjs --cwe CWE-N --lang {${LANGUAGES.join('|')}} --files <paths...> [--out <path>] [--force] [--model <name>]

Required: the detector-spec-synthesis feature on (AGENTIC_SECURITY_ASSURANCE_DETECTOR_SPEC_SYNTHESIS=1) and AGENTIC_SECURITY_LLM_ENDPOINT set.
Optional: AGENTIC_SECURITY_LLM_API_KEY, AGENTIC_SECURITY_LLM_MODEL. The egress policy (AGENTIC_SECURITY_EGRESS_DENY, AGENTIC_SECURITY_EGRESS_MODE=local-only) applies.

Reads the sample files (bounded), asks the model through the shared bounded call for the canonical SINK pattern, validates the reply, and
writes a proposal to --out (inside the working directory, never under scanner/src, never over a file without --force) or prints it.

THE OUTPUT IS A PROPOSAL FOR HUMAN REVIEW. Nothing installs it.`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { usage(); return 0; }
  if (args.unknown || !args.cwe || !args.lang || args.files.length === 0) { usage(); return EXIT.usage; }
  const scanRoot = process.cwd();
  const r = await synthesizeDetectorSpec({
    cwe: args.cwe, lang: args.lang, files: args.files, scanRoot,
    endpoint: process.env.AGENTIC_SECURITY_LLM_ENDPOINT || null,
    model: args.model || process.env.AGENTIC_SECURITY_LLM_MODEL || null,
  });
  if (r.status !== 'ok') {
    console.error(`synthesize-detector: ${r.status}${r.code ? ` (${r.code})` : ''}: ${r.reason}`);
    if (Array.isArray(r.errors)) for (const e of r.errors) console.error(`  - ${e}`);
    return r.exitCode ?? EXIT.refused;
  }
  console.error('synthesize-detector: a valid proposal from', r.filesRead, 'file(s);', r.redactions, 'redaction(s) before the request' + (r.truncated ? '; the reply was truncated at the output cap' : '') + '.');
  if (args.out) {
    const w = writeProposal(r.spec, args.out, { cwd: scanRoot, force: !!args.force });
    if (!w.ok) {
      console.error('synthesize-detector: not written:', w.reason);
      return EXIT.usage;
    }
    console.error('proposal written to', path.relative(scanRoot, w.path) || w.path, '. REVIEW REQUIRED before anything in a detector module uses it.');
    return EXIT.ok;
  }
  process.stdout.write(`${JSON.stringify(r.spec, null, 2)}\n`);
  return EXIT.ok;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code), (e) => { console.error(`synthesize-detector: ${e.message}`); process.exit(EXIT.usage); });
}
export { HERE };
