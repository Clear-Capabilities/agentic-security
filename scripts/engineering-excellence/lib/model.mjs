// Shared constants and the schema check for the Engineering Excellence status tooling.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate } from '../../loop-engineering/lib/schema.mjs';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const EE_DIR = resolve(HERE, '..');
export const REPO_ROOT = resolve(EE_DIR, '..', '..');

// Implementation task states (PRD 14.2). These are NOT benchmark verdicts: a task can be `done` while a measurement it produced is
// `unmeasured`. `interrupted` is an audit event, never a stored state.
export const TASK_STATES = Object.freeze(['pending', 'in_progress', 'done', 'already_satisfied', 'blocked', 'failed']);
export const VERIFIED_STATES = Object.freeze(['done', 'already_satisfied']);

// Where a task may go from where it is. `done` only returns to in_progress through detected evidence invalidation.
export const TRANSITIONS = Object.freeze({
  pending: ['in_progress', 'blocked'],
  in_progress: ['done', 'already_satisfied', 'blocked', 'failed', 'pending'],
  blocked: ['in_progress'],
  failed: ['in_progress'],
  done: ['in_progress'],
  already_satisfied: ['in_progress'],
});

// The failure vocabulary used for MEASUREMENTS everywhere in the program (PRD 3.1). Only `passed` is a success.
export const VERDICT_STATES = Object.freeze(['passed', 'failed', 'blocked', 'skipped_by_policy', 'not_applicable', 'not_run', 'insufficient_population', 'unmeasured']);
export const SUCCESS_VERDICTS = Object.freeze(['passed']);

export const STALE_HEARTBEAT_MS = 90_000;
export const HEARTBEAT_MAX_GAP_MS = 30_000;
export const MAX_COMMAND_RECORDS = 40;

function inlineRefs(node, root) {
  if (Array.isArray(node)) return node.map((n) => inlineRefs(n, root));
  if (node && typeof node === 'object') {
    if (typeof node.$ref === 'string' && node.$ref.startsWith('#/definitions/')) {
      const def = root.definitions?.[node.$ref.slice('#/definitions/'.length)];
      if (!def) throw new Error(`unresolved $ref ${node.$ref}`);
      return inlineRefs(def, root);
    }
    const out = {};
    for (const [k, v] of Object.entries(node)) if (k !== 'definitions') out[k] = inlineRefs(v, root);
    return out;
  }
  return node;
}

let _schema = null;
export function statusSchema() {
  if (!_schema) {
    const raw = JSON.parse(readFileSync(join(EE_DIR, 'status.schema.json'), 'utf8'));
    _schema = inlineRefs(raw, raw);
  }
  return _schema;
}

/** Schema problems with a status document; an empty list means it conforms. */
export function validateStatus(doc) {
  return validate(statusSchema(), doc);
}
