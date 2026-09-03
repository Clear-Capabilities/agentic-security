// governance-edit.js — M5 deliverable #5 (PRD line 1324's 5-part write
// contract: preview, validation, backup/version guard, confirmation,
// audit event). A CLI-only workflow for proposing a validated,
// reviewable edit to recipient-profiles.json — the one governance
// config file this codebase already has real, tested per-entry
// validation for (isValidRecipientConfigEntry, recipient-registry.js).
//
// Deliberately narrower than the PRD's own richer "interactive review/
// approve UI" vision — the HTTP-server-side interactive write surface
// (new routes, CSRF protection, a write-authorization mechanism beyond
// the existing read-only session token) is real, separately-scoped
// future work, not attempted here. See this sub-project's own scoping
// doc for the full reasoning: no PRD acceptance criterion gates this
// deliverable at all, and every M4/M5 deliverable this session has
// shipped has been CLI-first with zero UI/HTTP-write work.
//
// This module is pure — no file I/O, no fs access. The CLI layer
// (bin/agentic-security.js's cmdGovernancePropose) owns reading the
// current file, writing the backup, writing the new content, and
// calling auditCall.

import { isValidRecipientConfigEntry } from './recipient-registry.js';

function _recipientsOf(config) {
  return config && typeof config === 'object' && config.recipients && typeof config.recipients === 'object'
    ? config.recipients
    : {};
}

function _validateEntries(recipients) {
  const errors = [];
  for (const [key, entry] of Object.entries(recipients)) {
    if (!isValidRecipientConfigEntry(entry)) {
      errors.push({ key, message: `recipient "${key}" is not a valid recipient-profile-shaped config entry` });
    }
  }
  return errors;
}

function _diffRecipients(currentRecipients, patchRecipients) {
  const added = [];
  const removed = [];
  const changed = [];
  const currentKeys = new Set(Object.keys(currentRecipients));
  const patchKeys = new Set(Object.keys(patchRecipients));
  for (const key of patchKeys) {
    if (!currentKeys.has(key)) { added.push(key); continue; }
    if (JSON.stringify(currentRecipients[key]) !== JSON.stringify(patchRecipients[key])) {
      changed.push({ key, before: currentRecipients[key], after: patchRecipients[key] });
    }
  }
  for (const key of currentKeys) {
    if (!patchKeys.has(key)) removed.push(key);
  }
  added.sort();
  removed.sort();
  changed.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { added, removed, changed };
}

/**
 * Propose a patch to a recipient-profiles.json-shaped config. Pure,
 * never throws, never touches the filesystem. `currentConfig`/`patch`
 * are both `{recipients: {...}}`-shaped; a malformed shape degrades to
 * an empty `recipients` object rather than throwing (mirrors
 * `loadRecipientConfig`'s own tolerant-degradation contract). Returns
 * `{valid, errors, diff}` — `diff` is always computed, even when
 * `valid` is false, so an operator can see what they attempted before
 * fixing a validation error.
 */
export function proposeGovernanceEdit(currentConfig, patch) {
  const currentRecipients = _recipientsOf(currentConfig);
  const patchRecipients = _recipientsOf(patch);
  const errors = _validateEntries(patchRecipients);
  const diff = _diffRecipients(currentRecipients, patchRecipients);
  return { valid: errors.length === 0, errors, diff };
}
