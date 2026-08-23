#!/usr/bin/env node
// PRD F5.1 — materialise a PUBLISHED, third-party prompt-injection corpus.
//
// AI/LLM security is this product's most differentiated surface — 14 modules
// spanning prompt injection, RAG poisoning, MCP audit, agent-tool escalation,
// model loading — and before this it was scored on **two self-authored corpus
// entries**. It is also the area where the threat model is still moving, which
// is the argument for an external, versioned corpus rather than fixtures
// written here: fixtures written by the people who wrote the detectors test
// what those people already thought of.
//
// Source: `deepset/prompt-injections`, Apache-2.0, 546 rows in `train` and a
// separate `test` split, each row labelled 1 (injection) or 0 (legitimate) by
// its publishers. Both classes matter — a corpus of attacks alone measures
// recall and says nothing about how much ordinary text the detector would
// flag, which is the number that decides whether anyone leaves it switched on.
//
// Rows are fetched through the dataset host's row API rather than the parquet
// files, so this needs no parquet dependency. The cache is gitignored: this
// repository does not vendor other people's data.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CORPUS = path.join(HERE, 'cache', 'corpus.json');

const DATASET = 'deepset/prompt-injections';
const CONFIG = 'default';
const PAGE = 100;

async function fetchSplit(split) {
  const rows = [];
  for (let offset = 0; ; offset += PAGE) {
    const url = `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(DATASET)}`
      + `&config=${CONFIG}&split=${split}&offset=${offset}&length=${PAGE}`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`${split} offset ${offset}: HTTP ${resp.status}`);
    const body = await resp.json();
    const page = (body.rows || []).map((r) => r.row);
    rows.push(...page);
    process.stderr.write(`  ${split}: ${rows.length}/${body.num_rows_total}\n`);
    if (rows.length >= body.num_rows_total || page.length === 0) break;
  }
  return rows;
}

async function main() {
  fs.mkdirSync(path.dirname(CORPUS), { recursive: true });
  // The publishers' own train/test split is reused as the development /
  // held-out split. Reusing THEIR partition rather than inventing one means
  // nobody here chose which rows are hard.
  const train = await fetchSplit('train');
  const test = await fetchSplit('test');
  const out = {
    dataset: DATASET,
    license: 'apache-2.0',
    fetchedAt: new Date().toISOString().slice(0, 10),
    note: 'Labels are the publishers\'. 1 = injection, 0 = legitimate. The dataset\'s own train/test partition is used as development/held-out.',
    development: train,
    heldOut: test,
  };
  fs.writeFileSync(CORPUS, JSON.stringify(out, null, 2) + '\n');
  process.stderr.write(`\nwrote ${train.length} development + ${test.length} held-out rows\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { process.stderr.write(`fetch failed: ${e.message}\n`); process.exit(1); });
}
