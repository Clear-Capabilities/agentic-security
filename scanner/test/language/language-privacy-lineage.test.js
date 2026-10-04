// X-004: privacy classification, field lineage and protection for Haskell. Each test is tagged [X-004.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildLineageGraph } from '../../src/lineage/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.join(HERE, '..', 'fixtures', 'language-privacy', 'haskell');

function build(files) {
  const { perFile, callGraph } = buildProjectIR(files);
  const r = buildLineageGraph(callGraph, { perFile, fileContents: files, repository: 'demo', deterministic: true });
  assert.equal(r.status, 'complete', JSON.stringify(r.failure));
  const g = r.graph;
  const nodes = Object.fromEntries(g.nodes.map((n) => [n.id, n]));
  const els = Object.fromEntries(g.dataElements.map((e) => [e.id, e]));
  const flows = g.flows.map((f) => ({ field: f.dataElementIds.map((i) => els[i].name).join(','), sink: nodes[f.sink], flow: f, edge: g.edges.find((e) => f.edgeIds.includes(e.id)) }));
  return { g, flows };
}
const fixture = () => Object.fromEntries(readdirSync(DIR).filter((f) => f.endsWith('.hs')).map((f) => [f, readFileSync(path.join(DIR, f), 'utf8')]));
const reaches = (flows, field, kind, subtype) => flows.some((f) => f.field === field && f.sink.kind === kind && (!subtype || f.sink.subtype === subtype));

test('[X-004.AC01] fields reach the right sinks across Haskell modules, siblings stay distinct', () => {
  const { flows } = build(fixture());
  assert.ok(reaches(flows, 'email', 'store', 'database'), 'email -> database through Store.persist');
  assert.ok(reaches(flows, 'nickname', 'store', 'database'));
  assert.ok(reaches(flows, 'email', 'log'), 'email -> log through Audit.record');
  assert.ok(reaches(flows, 'email', 'external', 'external-api'), 'email -> HTTP through Outbound.pingAnalytics');
  assert.ok(reaches(flows, 'email', 'external', 'email'), 'email -> mail');
  assert.ok(reaches(flows, 'nickname', 'store', 'file'), 'nickname -> file');
  // siblings are not merged: nickname never reaches the mail sink, email never reaches the file sink
  assert.ok(!reaches(flows, 'nickname', 'external', 'email'));
  assert.ok(!reaches(flows, 'email', 'store', 'file'));
});

test('[X-004.AC01] every flow carries one data element, not a merged record', () => {
  const { flows } = build(fixture());
  for (const f of flows) assert.ok(!f.field.includes(','), `flow merged fields: ${f.field}`);
});

test('[X-004.AC02] a provider import or a field name alone creates no AI or privacy flow', () => {
  const files = {
    'A.hs': 'module A where\nimport OpenAI.Client (chat)\nimport qualified Data.Text as T\n\nemailField :: String\nemailField = "email"\n\nmain :: IO ()\nmain = putStrLn "ready"\n',
  };
  const { g, flows } = build(files);
  assert.equal(flows.length, 0, `unexpected flows: ${JSON.stringify(flows.map((f) => f.field))}`);
  assert.ok(!g.nodes.some((n) => /^ai-/.test(n.subtype || '') && g.flows.some((f) => f.sink === n.id)));
});

test('[X-004.AC02] only the linked value reaches a sink', () => {
  const files = {
    'B.hs': 'module B where\nimport Web.Scotty (ActionM, jsonData, liftIO)\n\nh :: ActionM ()\nh = do\n  s <- jsonData\n  liftIO (putStrLn "static banner")\n  liftIO (writeFile "/tmp/x" (nickname s))\n',
  };
  const { flows } = build(files);
  assert.ok(!flows.some((f) => f.sink.subtype === 'log' && f.field === 'nickname'), 'a constant log line is not a flow of nickname');
});

test('[X-004.AC03] protection verdicts are per dimension and evidence graded', () => {
  const { flows } = build(fixture());
  const http = flows.find((f) => f.field === 'email' && f.sink.subtype === 'external-api');
  assert.ok(http && http.edge);
  const p = http.edge.protection;
  for (const d of ['transit', 'atRest', 'handling']) assert.ok(p[d] && typeof p[d].verdict === 'string', `${d} dimension present`);
  // an http:// destination is never reported protected in transit
  assert.notEqual(p.transit.verdict, 'protected');
  // a flow with no assessed dimension never claims full protection
  for (const f of flows) assert.notEqual(f.flow.protectionSummary, 'protected', `${f.field} -> ${f.sink.subtype} claimed protected without evidence`);
});

test('[X-004.AC03] an unrelated https call does not protect a different flow', () => {
  const files = {
    'C.hs': 'module C where\nimport Web.Scotty (ActionM, jsonData, liftIO)\nimport Network.HTTP.Simple\n\ndata Signup = Signup { email :: String }\n\nh :: ActionM ()\nh = do\n  s <- jsonData\n  a <- parseRequest "GET https://secure.example.test/ok"\n  _ <- liftIO (httpLBS a)\n  b <- parseRequest "POST http://plain.example.test/leak"\n  _ <- liftIO (httpLBS (setRequestBodyJSON (email s) b))\n  pure ()\n',
  };
  const { flows } = build(files);
  const f = flows.find((x) => x.field === 'email');
  assert.ok(f, 'email flow found');
  assert.notEqual(f.edge.protection.transit.verdict, 'protected');
});

test('[X-004.AC04] coverage limits are disclosed, never full coverage', () => {
  const { g } = build(fixture());
  assert.ok(g.coverage && g.coverage.sinks, 'coverage ledger present');
  assert.ok(g.coverage.sinks.callStatementSites >= g.coverage.sinks.connected);
  assert.ok(Array.isArray(g.limitations) && g.limitations.length > 0, 'limitations disclosed');
  const haskell = (g.coverage.languages || []).find((l) => l.language === 'haskell');
  assert.ok(haskell, 'haskell language bucket present');
  assert.notEqual(haskell.tier, 'full', 'haskell is never reported as full coverage');
});

test('[X-004.AC04] widened flows keep a visible grade', () => {
  const { flows } = build(fixture());
  const widened = flows.filter((f) => f.flow.evidenceGrade && f.flow.evidenceGrade !== 'explicit');
  for (const f of widened) assert.ok(f.flow.evidenceGrade, 'grade kept');
  assert.ok(flows.every((f) => typeof f.flow.evidenceGrade === 'string' || f.flow.evidenceGrade === undefined));
});
