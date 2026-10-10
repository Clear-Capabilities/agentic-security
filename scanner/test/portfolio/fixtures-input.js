// Shared SYNTHETIC input for the flag-off pin (X-707): a fleet rollup input. Not a test file.
export const FLEET_RESULTS = [
  { ok: true, repo: 'svc-a', total: 3, proven: 1, bySeverity: { critical: 1, high: 1, medium: 1, low: 0, info: 0 }, ids: ['f1', 'f2', 'f3'] },
  { ok: true, repo: 'svc-b', total: 0, proven: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, ids: [] },
  { ok: false, repo: 'svc-c', error: 'synthetic failure' },
];
