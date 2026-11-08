// Haskell parse budgets and the record of work left when one is hit (PRD FR 02 "budget behavior and proof of completion").
//
// The parser stops a file at a named bound (bytes, tokens, nesting, steps, wall clock) and reports `budget_exceeded`; the file is
// not analysed and the capability stays incomplete. This module does three things around that:
//
//   1. Operator budgets. AGENTIC_SECURITY_HASKELL_PARSE_BUDGETS raises (or lowers) named bounds: `deadlineMs=20000,maxTokens=800000`.
//      Only the parser's own budget names are accepted, as positive integers; anything else is rejected and reported, never guessed.
//   2. A persisted record. Each scan writes `.agentic-security/haskell-budget.json`: the effective budgets, the count of completed
//      files, and every remaining file with the reason and a digest of its content.
//   3. A comparison. The next scan reads that record and states, for each previously remaining file, whether it is now complete,
//      still remaining on the same inputs and budgets (a deterministic bound will be hit again: raise it), still remaining after
//      a change, or gone.
//
// What it does not do: resume. The Haskell pass parses every eligible file on every scan, so nothing is reused from a previous
// run, and nothing is skipped because it was analysed before. The record proves what was and was not finished; it does not
// shortcut the work. `deadlineMs` is wall-clock time, so a file can complete on one machine and exceed it on another.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { statePath, safeWriteState } from '../posture/state-dir.js';
import { DEFAULT_PARSE_BUDGETS } from './haskell-parser.js';

export const BUDGET_STATE_SCHEMA = 'haskell-budget-state/1';
export const HASKELL_PARSE_BUDGET_ENV = 'AGENTIC_SECURITY_HASKELL_PARSE_BUDGETS';
const STATE_FILE = 'haskell-budget.json';
const MAX_RECORDED = 5000;

/** Parse `name=value,...` into parser budget overrides. Returns { budgets, rejected }. */
export function parseBudgetOverrides(raw) {
  const budgets = {};
  const rejected = [];
  for (const part of String(raw || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const m = /^([A-Za-z]+)\s*=\s*(\d+)$/.exec(part);
    if (!m) { rejected.push({ entry: part, reason: 'expected name=positive-integer' }); continue; }
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_PARSE_BUDGETS, m[1])) { rejected.push({ entry: part, reason: `unknown budget "${m[1]}"` }); continue; }
    const v = Number(m[2]);
    if (!Number.isSafeInteger(v) || v <= 0) { rejected.push({ entry: part, reason: 'value must be a positive integer' }); continue; }
    budgets[m[1]] = v;
  }
  return { budgets, rejected };
}

export const contentDigest = (text) => crypto.createHash('sha256').update(String(text ?? '')).digest('hex');

export function loadBudgetState(scanRoot) {
  if (!scanRoot) return null;
  try {
    const doc = JSON.parse(fs.readFileSync(statePath(scanRoot, STATE_FILE), 'utf8'));
    if (!doc || doc.schema !== BUDGET_STATE_SCHEMA || !Array.isArray(doc.remaining)) return null;
    return doc;
  } catch { return null; }
}

const sameBudgets = (a, b) => JSON.stringify(Object.entries(a || {}).sort()) === JSON.stringify(Object.entries(b || {}).sort());

/**
 * Build this scan's record and compare it with the previous one.
 * @param {{remaining:{file:string,parse:string,flowAnalysis:string,budgetName?:string}[], completedFiles:number,
 *          budgets:object, files:Record<string,string>, previous:object|null}} i
 */
export function budgetRecord({ remaining, completedFiles, budgets, files, previous }) {
  const rows = remaining.slice(0, MAX_RECORDED).map((r) => ({ ...r, digest: contentDigest(files[r.file]) }));
  const record = { schema: BUDGET_STATE_SCHEMA, budgets, completedFiles, remainingFiles: remaining.length, remaining: rows, truncated: remaining.length > rows.length };
  if (!previous) return { record, sinceLast: null };
  const now = new Map(rows.map((r) => [r.file, r]));
  const budgetsChanged = !sameBudgets(previous.budgets, budgets);
  const sinceLast = { budgetsChanged, completed: [], stillRemainingSameInputs: [], stillRemainingChanged: [], gone: [], newlyRemaining: [] };
  for (const p of previous.remaining) {
    if (!(p.file in files)) { sinceLast.gone.push(p.file); continue; }
    const cur = now.get(p.file);
    if (!cur) { sinceLast.completed.push(p.file); continue; }
    // Both digests are hashes of source files the scan already read, not secrets: comparison time reveals nothing.
    if (cur.digest === p.digest && !budgetsChanged) sinceLast.stillRemainingSameInputs.push(p.file); // agentic-security-ignore: CWE-208
    else sinceLast.stillRemainingChanged.push(p.file);
  }
  const before = new Set(previous.remaining.map((p) => p.file));
  for (const r of rows) if (!before.has(r.file)) sinceLast.newlyRemaining.push(r.file);
  for (const k of Object.keys(sinceLast)) if (Array.isArray(sinceLast[k])) sinceLast[k].sort();
  return { record, sinceLast };
}

export function saveBudgetState(scanRoot, record) {
  if (!scanRoot) return false;
  return safeWriteState(statePath(scanRoot, STATE_FILE), JSON.stringify(record, null, 1) + '\n');
}
