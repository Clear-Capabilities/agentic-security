// FR-907 (assurance-hardening PRD): "Add longitudinal production feedback
// measurement | Metrics separate user suppression, accepted risk, invalid
// finding, fixed finding, and verification outcome."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  collectFeedbackEvents, summarizeFeedbackTrend, productionFeedbackReport,
  renderProductionFeedbackSummary, CATEGORIES,
} from '../src/posture/production-feedback.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'scanner', 'bin', 'agentic-security.js');

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: cwd || path.join(REPO_ROOT, 'scanner'), encoding: 'utf8', timeout: 30_000 });
}

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'production-feedback-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function writeState(dir, name, content) {
  fs.writeFileSync(path.join(dir, '.agentic-security', name), content);
}

const DAY_MS = 86400000;

// ── collectFeedbackEvents: each of the 5 sources ─────────────────────────

test('collectFeedbackEvents: an empty/missing project degrades to zero events, never throws', async () => {
  const s = await mkSession();
  try { assert.deepEqual(collectFeedbackEvents(s.dir), []); } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: accepted.json (vibecoder soft-accept) -> user-suppression, dated', async () => {
  const s = await mkSession();
  try {
    writeState(s.dir, 'accepted.json', JSON.stringify({ accepted: [{ id: 'f1', file: 'a.js', line: 5, vuln: 'XSS', reason: 'later', accepted_at: '2026-08-01', expires_at: '2026-08-31' }] }));
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 1);
    assert.equal(events[0].category, 'user-suppression');
    assert.equal(events[0].at, '2026-08-01');
    assert.equal(events[0].outcome, 'soft-accepted');
  } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: suppressions.yml (pro exception) -> user-suppression, UNDATED (no creation timestamp in that schema)', async () => {
  const s = await mkSession();
  try {
    writeState(s.dir, 'suppressions.yml', '- finding_id: f1\n  file: a.js\n  reason: x\n  expires_at: "2027-01-01"\n');
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 1);
    assert.equal(events[0].category, 'user-suppression');
    assert.equal(events[0].at, null);
  } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: triage-memory.jsonl splits wont-fix -> user-suppression and false-positive -> invalid-finding', async () => {
  const s = await mkSession();
  try {
    const lines = [
      JSON.stringify({ at: '2026-08-01T00:00:00Z', decision: 'wont-fix', reason: 'x', bucket: 'b', family: 'xss', id: 'f1', file: 'a.js', line: 1 }),
      JSON.stringify({ at: '2026-08-02T00:00:00Z', decision: 'false-positive', reason: 'y', bucket: 'b', family: 'sqli', id: 'f2', file: 'b.js', line: 2 }),
    ];
    writeState(s.dir, 'triage-memory.jsonl', lines.join('\n') + '\n');
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 2);
    assert.ok(events.some(e => e.category === 'user-suppression' && e.outcome === 'wont-fix'));
    assert.ok(events.some(e => e.category === 'invalid-finding' && e.outcome === 'false-positive'));
  } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: sca-policy.yml accept-risk entries -> accepted-risk, UNDATED (schema has no creation date)', async () => {
  const s = await mkSession();
  try {
    writeState(s.dir, 'sca-policy.yml', 'accept-risk:\n  - cve: CVE-2024-1\n    reason: patched upstream\n    expires: 2027-01-01\n');
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 1);
    assert.equal(events[0].category, 'accepted-risk');
    assert.equal(events[0].at, null);
    assert.equal(events[0].findingId, 'CVE-2024-1');
  } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: fix-history/log.json -> fixed-finding, dated via appliedAt, outcome carries status', async () => {
  const s = await mkSession();
  try {
    fs.mkdirSync(path.join(s.dir, '.agentic-security', 'fix-history'), { recursive: true });
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'fix-history', 'log.json'), JSON.stringify([
      { findingId: 'f1', file: 'a.js', appliedAt: '2026-08-03T00:00:00Z', status: 'applied' },
    ]));
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 1);
    assert.equal(events[0].category, 'fixed-finding');
    assert.equal(events[0].at, '2026-08-03T00:00:00Z');
    assert.equal(events[0].outcome, 'applied');
  } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: fix-metrics.jsonl -> verification-outcome, dated via at, ok maps to verified/not-verified', async () => {
  const s = await mkSession();
  try {
    const lines = [
      JSON.stringify({ at: '2026-08-04T00:00:00Z', stableId: 'f1', ok: true, totalMs: 1200 }),
      JSON.stringify({ at: '2026-08-05T00:00:00Z', stableId: 'f2', ok: false, totalMs: 800 }),
    ];
    writeState(s.dir, 'fix-metrics.jsonl', lines.join('\n') + '\n');
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 2);
    assert.ok(events.every(e => e.category === 'verification-outcome'));
    assert.ok(events.some(e => e.outcome === 'verified'));
    assert.ok(events.some(e => e.outcome === 'not-verified'));
  } finally { await s.cleanup(); }
});

test('collectFeedbackEvents: a malformed source (bad JSON) degrades that ONE category to empty without blocking the other 4', async () => {
  const s = await mkSession();
  try {
    writeState(s.dir, 'accepted.json', '{ not valid json [[[');
    writeState(s.dir, 'sca-policy.yml', 'accept-risk:\n  - cve: CVE-2024-1\n    reason: x\n');
    const events = collectFeedbackEvents(s.dir);
    assert.equal(events.length, 1, 'the malformed accepted.json must yield zero events, not throw or block sca-policy');
    assert.equal(events[0].category, 'accepted-risk');
  } finally { await s.cleanup(); }
});

// ── summarizeFeedbackTrend ─────────────────────────────────────────────

test('summarizeFeedbackTrend: an undated event counts toward total and undated, never inWindow', () => {
  const events = [{ category: 'accepted-risk', at: null }];
  const s = summarizeFeedbackTrend(events, { sinceDays: 30 });
  assert.equal(s.byCategory['accepted-risk'].total, 1);
  assert.equal(s.byCategory['accepted-risk'].undated, 1);
  assert.equal(s.byCategory['accepted-risk'].inWindow, 0);
});

test('summarizeFeedbackTrend: an event outside the window counts toward total but not inWindow or undated', () => {
  const now = Date.now();
  const old = new Date(now - 60 * DAY_MS).toISOString();
  const events = [{ category: 'fixed-finding', at: old }];
  const s = summarizeFeedbackTrend(events, { sinceDays: 30, now });
  assert.equal(s.byCategory['fixed-finding'].total, 1);
  assert.equal(s.byCategory['fixed-finding'].inWindow, 0);
  assert.equal(s.byCategory['fixed-finding'].undated, 0);
});

test('summarizeFeedbackTrend: an event inside the window is bucketed by day in series', () => {
  const now = Date.now();
  const recent = new Date(now - 2 * DAY_MS).toISOString();
  const events = [{ category: 'invalid-finding', at: recent }];
  const s = summarizeFeedbackTrend(events, { sinceDays: 30, now });
  assert.equal(s.byCategory['invalid-finding'].inWindow, 1);
  assert.equal(s.series.length, 1);
  assert.equal(s.series[0].counts['invalid-finding'], 1);
});

test('summarizeFeedbackTrend: every one of the 5 named categories is always present in byCategory, even with zero events', () => {
  const s = summarizeFeedbackTrend([]);
  assert.deepEqual(Object.keys(s.byCategory).sort(), [...CATEGORIES].sort());
});

// ── productionFeedbackReport / renderProductionFeedbackSummary ──────────

test('renderProductionFeedbackSummary: null when nothing was measured at all', () => {
  assert.equal(renderProductionFeedbackSummary({ events: [], sinceDays: 30, byCategory: {} }), null);
  assert.equal(renderProductionFeedbackSummary(null), null);
});

test('productionFeedbackReport + renderProductionFeedbackSummary: a real project with data produces a populated summary naming categories and counts', async () => {
  const s = await mkSession();
  try {
    writeState(s.dir, 'accepted.json', JSON.stringify({ accepted: [{ id: 'f1', file: 'a.js', line: 1, vuln: 'x', reason: 'y', accepted_at: new Date().toISOString().slice(0, 10), expires_at: '2099-01-01' }] }));
    const report = productionFeedbackReport(s.dir, { sinceDays: 30 });
    assert.equal(report.events.length, 1);
    const summary = renderProductionFeedbackSummary(report);
    assert.match(summary, /Production feedback/);
    assert.match(summary, /user-suppression/);
  } finally { await s.cleanup(); }
});

// ── real CLI: triage trend surfaces production feedback ──────────────────

async function mkProProject() {
  const s = await mkSession();
  fs.writeFileSync(path.join(s.dir, '.agentic-security', 'profile.yml'), 'profile: pro\n');
  return s;
}

test('triage trend (real CLI, pro mode): includes a Production feedback section when suppression/fix data exists', async () => {
  const s = await mkProProject();
  try {
    writeState(s.dir, 'accepted.json', JSON.stringify({ accepted: [{ id: 'f1', file: 'a.js', line: 1, vuln: 'x', reason: 'y', accepted_at: new Date().toISOString().slice(0, 10), expires_at: '2099-01-01' }] }));
    const r = run(['triage', 'trend', '--root', s.dir], s.dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Trend over \d+ days/);
    assert.match(r.stdout, /Production feedback/);
    assert.match(r.stdout, /user-suppression/);
  } finally { await s.cleanup(); }
});

test('triage trend (real CLI, pro mode): omits the Production feedback section cleanly when nothing to report', async () => {
  const s = await mkProProject();
  try {
    const r = run(['triage', 'trend', '--root', s.dir], s.dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Trend over \d+ days/);
    assert.doesNotMatch(r.stdout, /Production feedback/);
  } finally { await s.cleanup(); }
});
