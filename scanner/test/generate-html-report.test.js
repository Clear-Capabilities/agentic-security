// generate-html-report.test.js — Milestone 4, sub-project Self-contained
// HTML report, Task 3. Per the task-3 brief's own Step 1 starter code,
// verbatim (see .superpowers/sdd/2026-09-01-data-flow-explorer-m4-html-report-plan/task-3-brief.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateHtmlReport } from '../scripts/generate-html-report.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.resolve(__dirname, '../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

test('generateHtmlReport: produces one HTML document with no external references', () => {
  const html = generateHtmlReport(flagship);
  assert.match(html, /<!DOCTYPE html>/i);
  // §17.5's own "avoid any remote scripts or tracking" — no http(s):// src/href
  // anywhere except inside the embedded graph JSON's own data values (a
  // destination.literalValue string is not a resource reference).
  assert.doesNotMatch(html, /<script[^>]+src=["']https?:/i);
  assert.doesNotMatch(html, /<link[^>]+href=["']https?:/i);
});

test('generateHtmlReport: embeds the graph via exportGraphJSON (redacted by default)', () => {
  const html = generateHtmlReport(flagship);
  assert.match(html, /__AGENTIC_SECURITY_EXPORTED_GRAPH__/);
  // The exported envelope's own digest/scope/confidential fields must be
  // present in the embedded payload, not just the bare graph — confirming
  // this generator calls exportGraphJSON's full envelope, not graph alone.
  assert.match(html, /"confidential"\s*:\s*true/);
  assert.match(html, /"digest"\s*:/);
});

test('generateHtmlReport: inlines all 9 real CSS files', () => {
  const html = generateHtmlReport(flagship);
  const stylesDir = path.resolve(__dirname, '../../frontend/styles');
  const realCssFiles = fs.readdirSync(stylesDir).filter((f) => f.endsWith('.css'));
  assert.ok(realCssFiles.length > 0, 'sanity: frontend/styles must have real CSS files to inline');
  for (const f of realCssFiles) {
    const content = fs.readFileSync(path.join(stylesDir, f), 'utf8').trim();
    if (content) assert.ok(html.includes(content.slice(0, 50)), `expected ${f}'s own content to appear inlined`);
  }
});

test('generateHtmlReport: inlines tokens.css BEFORE the files that consume its custom properties', () => {
  // Real regression this session's own frontend/index.html read caught:
  // an alphabetical inline order would put tokens.css 8th, after 7 files
  // that reference its var(--...) custom properties on first paint.
  const html = generateHtmlReport(flagship);
  const stylesDir = path.resolve(__dirname, '../../frontend/styles');
  const tokensContent = fs.readFileSync(path.join(stylesDir, 'tokens.css'), 'utf8').trim().slice(0, 30);
  const shellContent = fs.readFileSync(path.join(stylesDir, 'shell.css'), 'utf8').trim().slice(0, 30);
  assert.ok(html.indexOf(tokensContent) < html.indexOf(shellContent), 'tokens.css must appear before shell.css in the inlined <style> block');
});

test('generateHtmlReport: AC-14 reproducibility — same graph in twice, byte-identical except a documented timestamp', () => {
  const a = generateHtmlReport(flagship);
  const b = generateHtmlReport(flagship);
  // The embedded exportGraphJSON envelope carries its own exportedAt
  // timestamp (real, expected difference) — strip ONLY that documented
  // field before comparing, matching export-json.test.js's own AC-14
  // proof pattern.
  const strip = (h) => h.replace(/"exportedAt"\s*:\s*"[^"]*"/, '"exportedAt":"STRIPPED"');
  assert.equal(strip(a), strip(b));
});

test('generateHtmlReport: redact:false is never the default — opts must be explicit to unredact', () => {
  const html = generateHtmlReport(flagship);
  assert.doesNotMatch(html, /"confidential"\s*:\s*false/);
});
