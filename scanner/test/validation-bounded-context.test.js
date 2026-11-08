// PRD FR 05: the model sees numbered, bounded spans and must cite the lines its verdict rests on. A citation outside what was sent
// voids the reply; no citation is recorded as such; gaps in the context are stated, never implied.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectBoundedContext, checkCitations, renderSpans } from '../src/llm-validator/bounded-context.js';
import { validateMany } from '../src/llm-validator/index.js';
import { assignDisposition } from '../src/llm-validator/disposition.js';
import { withReplayedModel } from './helpers/model-replay.js';
import { mkTestTmp } from './helpers/tmp.js';

const code = (n) => Array.from({ length: n }, (_, i) => `line${i + 1}`).join('\n');
const FILES = { 'a.js': code(200), 'lib.js': code(30) };

test('spans cover the finding, a distant source and sink, and path steps, merged where they touch', () => {
  const f = { file: 'a.js', line: 100, source: { file: 'a.js', line: 10 }, sink: { file: 'a.js', line: 100 }, path: [{ line: 12 }, { file: 'lib.js', line: 20 }] };
  const { spans, gaps } = collectBoundedContext(f, FILES);
  assert.deepEqual(spans.map((s) => [s.id, s.role, s.file, s.start, s.end]), [
    ['S1', 'finding', 'a.js', 80, 120],
    ['S2', 'source', 'a.js', 7, 15],
    ['S3', 'path-step', 'lib.js', 17, 23],
  ]);
  assert.deepEqual(spans[0].alsoRoles, ['sink']);
  assert.deepEqual(spans[1].alsoRoles, ['path-step']);
  assert.match(spans[1].text, /^7: line7\n/);
  assert.ok(gaps.some((g) => /callers .* not collected/.test(g)));
  assert.ok(gaps.some((g) => /configuration files were not collected/.test(g)));
  assert.match(renderSpans(spans), /^\[S1 finding\+sink\] a\.js:80-120\n80: line80/);
});

test('a source in a file that was not supplied is a stated gap', () => {
  const { gaps } = collectBoundedContext({ file: 'a.js', line: 5, source: { file: 'missing.js', line: 3 } }, FILES);
  assert.ok(gaps.includes('source file missing.js was not available'));
});

test('citations are checked against the spans that were sent', () => {
  const { spans } = collectBoundedContext({ file: 'a.js', line: 100 }, FILES);
  assert.deepEqual(checkCitations(['S1:100', ' S1 : 80 '], spans), { status: 'valid', resolved: [{ span: 'S1', file: 'a.js', line: 100 }, { span: 'S1', file: 'a.js', line: 80 }], invalid: [] });
  assert.equal(checkCitations([], spans).status, 'none');
  assert.equal(checkCitations(undefined, spans).status, 'none');
  assert.equal(checkCitations(['S1:79'], spans).status, 'invalid', 'a line just outside the span');
  assert.equal(checkCitations(['S9:100'], spans).status, 'invalid', 'a span that was not sent');
  assert.equal(checkCitations(['a.js:100'], spans).status, 'invalid', 'a bare location is not a span citation');
  assert.equal(checkCitations('S1:100', spans).status, 'invalid', 'not a list');
});

const ENV = { AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:1/v1/x', AGENTIC_SECURITY_LLM_API_KEY: 'k', AGENTIC_SECURITY_LLM_MODEL: 'm' };
async function judge(citations) {
  const was = {};
  for (const k of Object.keys(ENV)) { was[k] = process.env[k]; process.env[k] = ENV[k]; }
  try {
    const f = { id: 'F1', file: 'a.js', line: 100, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'SAST' };
    const reply = { challenge: '{{challenge}}', file: '{{file}}', line: '{{line}}', verdict: 'accept', confidence: 0.9, reasoning: 'reaches the sink', ...(citations ? { citations } : {}) };
    let prompt = '';
    const orig = global.fetch;
    await withReplayedModel({ reply }, async () => {
      const inner = global.fetch;
      global.fetch = async (url, opts) => { prompt = JSON.parse(opts.body).prompt ?? JSON.parse(opts.body).messages?.map((m) => m.content).join('\n') ?? ''; return inner(url, opts); };
      try { await validateMany([f], { fileContents: FILES, scanRoot: mkTestTmp('agsec-cite-') }); } finally { global.fetch = inner; }
    });
    global.fetch = orig;
    return { f, prompt };
  } finally { for (const k of Object.keys(was)) { if (was[k] === undefined) delete process.env[k]; else process.env[k] = was[k]; } }
}

test('through the real validator: the prompt carries the spans and the gaps, and valid citations are recorded', async () => {
  const { f, prompt } = await judge(['S1:100']);
  assert.match(prompt, /\[S1 finding\] a\.js:80-120/);
  assert.match(prompt, /CONTEXT NOT SUPPLIED[\s\S]*callers of the enclosing function were not collected/);
  assert.equal(f.validator_verdict, 'accept');
  assert.equal(f.validator_citation_status, 'valid');
  assert.deepEqual(f.validator_citations, [{ span: 'S1', file: 'a.js', line: 100 }]);
  assert.deepEqual(f.validator_context.spans[0], { id: 'S1', role: 'finding', file: 'a.js', start: 80, end: 120 });
  assignDisposition(f, { fileContents: FILES });
  assert.equal(f.disposition, 'needs-review', 'citations never confirm');
  assert.deepEqual(f.dispositionDetail.evidence, [{ kind: 'model-citations', refs: ['a.js:100'] }]);
});

test('through the real validator: a citation outside the context voids the reply; no citation is recorded as missing evidence', async () => {
  const out = (await judge(['S1:150'])).f;
  assert.equal(out.validator_verdict, 'escalate');
  assert.equal(out.llmValidationStatus, 'malformed');
  assert.equal(out._validatorError, 'citation-out-of-context');
  const none = (await judge(null)).f;
  assert.equal(none.validator_verdict, 'accept');
  assert.equal(none.validator_citation_status, 'none');
  assignDisposition(none, { fileContents: FILES });
  assert.ok(none.dispositionDetail.missingEvidence.includes('the model cited no line of the context it was shown'));
});
