// FR-706 (assurance-hardening PRD): manifest-based export and deletion
// reports — "Operators can prove what was exported, deleted, retained, or
// failed."
//
// Two report kinds, one shared per-item shape ({name, status, ...}), each
// written by its one real caller in bin/agentic-security.js:
//   - `cmdReset` builds a deletion report from the SAME target/preserved
//     data it already computes for its console output (see FR-702/FR-703),
//     reshaped into a durable, structured artifact instead of only ever
//     printed and lost. Written on BOTH a dry run (items carry status
//     'planned') and a real run (status 'deleted'/'failed'), so an operator
//     can prove either "what would happen" or "what did happen" depending
//     on which they asked for — `dryRun` on the report says which.
//   - `cmdExport` (new) builds an export report after copying every
//     currently-present registered artifact to an operator-chosen
//     destination, naming what was copied (with a hash) and what failed.
//
// Each report is a SINGLE OVERWRITTEN file per kind — the same "last
// action" precedent as last-scan.json, not an ever-growing log. An
// operator who needs a persistent audit trail across many runs should
// retain these externally (commit them, forward to their own SIEM); this
// module's job is only to make the LAST action's outcome durable and
// provable, not to be the audit log itself.

import { statePath, safeWriteState } from './state-dir.js';

export const DELETION_REPORT_FILE = 'deletion-report.json';
export const EXPORT_REPORT_FILE = 'export-report.json';

export function buildDeletionReport({ mode, dryRun, root, items, preserved }) {
  const list = Array.isArray(items) ? items : [];
  const preservedList = Array.isArray(preserved) ? preserved : [];
  return {
    schema: 'agentic-security/deletion-report@1',
    generatedAt: new Date().toISOString(),
    mode: mode || 'reset',
    dryRun: !!dryRun,
    root: root || null,
    items: list,
    preserved: preservedList,
    summary: {
      planned: list.filter(i => i.status === 'planned').length,
      deleted: list.filter(i => i.status === 'deleted').length,
      failed: list.filter(i => i.status === 'failed').length,
      preserved: preservedList.length,
    },
  };
}

export function writeDeletionReport(scanRoot, report) {
  try {
    const fp = statePath(scanRoot, DELETION_REPORT_FILE);
    return safeWriteState(fp, JSON.stringify(report, null, 2) + '\n') ? fp : null;
  } catch { return null; }
}

export function buildExportReport({ root, outDir, items }) {
  const list = Array.isArray(items) ? items : [];
  return {
    schema: 'agentic-security/export-report@1',
    generatedAt: new Date().toISOString(),
    root: root || null,
    outDir: outDir || null,
    items: list,
    summary: {
      exported: list.filter(i => i.status === 'exported').length,
      failed: list.filter(i => i.status === 'failed').length,
    },
  };
}

export function writeExportReport(scanRoot, report) {
  try {
    const fp = statePath(scanRoot, EXPORT_REPORT_FILE);
    return safeWriteState(fp, JSON.stringify(report, null, 2) + '\n') ? fp : null;
  } catch { return null; }
}
