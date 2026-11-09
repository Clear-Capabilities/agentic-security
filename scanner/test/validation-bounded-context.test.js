// PRD FR 05: the model sees numbered, bounded spans and must cite the lines its verdict rests on. A citation outside what was sent
// voids the reply; no citation is recorded as such; gaps in the context are stated, never implied.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectBoundedContext, checkCitations, renderSpans, enclosingFunction } from '../src/llm-validator/bounded-context.js';
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
  assert.ok(gaps.includes('the enclosing function could not be determined, so callers were not collected'));
  assert.ok(gaps.some((g) => /no configuration key is read near the finding/.test(g)));
  assert.ok(gaps.some((g) => /deployment configuration outside the repository/.test(g)));
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
  assert.match(prompt, /CONTEXT NOT SUPPLIED[\s\S]*the enclosing function could not be determined, so callers were not collected/);
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

// PRD FR 05 "collect the relevant function, callers, guards, configuration": callers and configuration are collected by name and
// labelled as such; what could not be collected stays a stated gap.
const APP = {
  'src/db.js': ['import pg from "pg";', 'export function runQuery(id) {', '  const host = process.env.DB_HOST;', '  const key = process.env.API_TOKEN;',
    '  return pg.query("SELECT * FROM t WHERE id=" + id);', '}', ''].join('\n'),
  'src/routes.js': ['import { runQuery } from "./db.js";', 'app.get("/t", (req, res) => {', '  res.send(runQuery(req.query.id));', '});', ''].join('\n'),
  'tools/seed.py': ['def seed():', '    runQuery(1)', ''].join('\n'),
  'config/app.yaml': ['db:', 'DB_HOST: db.internal', 'port: 5432', ''].join('\n'),
  '.env.example': ['API_TOKEN=example-value-123', 'LOG=1', ''].join('\n'),
  '.env': ['DB_HOST=prod.internal', 'API_TOKEN=real-secret', ''].join('\n'),
};

test('callers of the enclosing function are collected by name in the same language, and labelled as unresolved', () => {
  assert.deepEqual(enclosingFunction('src/db.js', APP['src/db.js'], 5), { name: 'runQuery', line: 2 });
  const { spans, gaps } = collectBoundedContext({ file: 'src/db.js', line: 5 }, APP, { window: 2 });
  const callers = spans.filter((s) => s.role === 'caller');
  assert.deepEqual(callers.map((s) => s.file), ['src/routes.js'], 'the import line is not a call, and the Python file is another language');
  assert.match(callers[0].text, /3:\s+res\.send\(runQuery\(req\.query\.id\)\);/);
  assert.ok(gaps.some((g) => /callers of runQuery were matched by name, not resolved/.test(g)));
});

test('configuration that sets a key read near the finding is collected; secret values are masked and a real .env is never read', () => {
  const { spans, gaps } = collectBoundedContext({ file: 'src/db.js', line: 5 }, APP, { window: 2, maxConfig: 10 });
  const conf = spans.filter((s) => s.role === 'configuration');
  assert.deepEqual(conf.map((s) => s.file).sort(), ['.env.example', 'config/app.yaml']);
  const ex = conf.find((s) => s.file === '.env.example').text;
  assert.match(ex, /API_TOKEN=<masked>/); assert.ok(!ex.includes('example-value-123')); assert.match(ex, /LOG=1/);
  assert.match(conf.find((s) => s.file === 'config/app.yaml').text, /DB_HOST: db\.internal/);
  assert.ok(!spans.some((s) => s.file === '.env'), 'a real dotenv file is not configuration evidence and is never sent');
  assert.ok(!gaps.some((g) => /set in no scanned configuration file/.test(g)));
  const { gaps: g2 } = collectBoundedContext({ file: 'src/db.js', line: 5 }, { 'src/db.js': APP['src/db.js'] }, { window: 2 });
  assert.ok(g2.includes('configuration key(s) API_TOKEN, DB_HOST read near the finding are set in no scanned configuration file (they may be set at deploy time)'));
});

test('no caller found, too many callers, and Haskell definitions are all stated', () => {
  const py = { 'app.py': ['import os', 'def handler(req):', '    os.system(req)', ''].join('\n') };
  assert.ok(collectBoundedContext({ file: 'app.py', line: 3 }, py).gaps.some((g) => /^no call site of handler was found by name/.test(g)));
  const many = { 'a.go': ['package a', 'func run(x string) {', '  exec(x)', '}', ''].join('\n'),
    ...Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`c${i}.go`, `package a\nfunc c${i}() { run("x") }\n`])) };
  const m = collectBoundedContext({ file: 'a.go', line: 3 }, many, { stepWindow: 0, maxSpans: 20 });
  assert.equal(m.spans.filter((s) => s.role === 'caller').length, 3);
  assert.ok(m.gaps.includes('2 further call site(s) of run were not sent'));
  const hs = { 'App.hs': ['module App where', 'handler :: Text -> IO ()', 'handler t = system (unpack t)', '', 'main :: IO ()', 'main = getLine >>= handler . pack', ''].join('\n') };
  const h = collectBoundedContext({ file: 'App.hs', line: 3 }, hs, { window: 0, stepWindow: 0 });
  assert.deepEqual(h.spans.filter((s) => s.role === 'caller').map((s) => s.start), [6], 'the type signature is not a call');
});
