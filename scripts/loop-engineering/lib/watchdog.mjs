// Per-attempt watchdog policy (LOOP-002.AC03). Three clocks are kept apart on
// purpose:
//   heartbeat  - the controller is alive            (never counts as progress)
//   activity   - the worker emitted bytes/events    (never counts as progress)
//   progress   - verified, substantive advancement  (the only thing that resets
//                the no-progress deadline)
// The clock is injected so the policy is testable without waiting minutes.
export const PROGRESS_KINDS = Object.freeze(['criterion-passed', 'failures-reduced', 'bounded-task-completed']);

export class AttemptWatchdog {
  constructor({ now = () => Date.now(), idleMs = 180_000, noProgressMs = 600_000, attemptMs = 1_200_000, maxTurns = 80 } = {}) {
    this.now = now;
    this.limits = { idleMs, noProgressMs, attemptMs, maxTurns };
    const t = now();
    this.startedAt = t;
    this.lastHeartbeatAt = t;
    this.lastActivityAt = t;
    this.lastProgressAt = t;
    this.turns = 0;
    this.leases = new Map(); // id -> deadlineAt (fixed; never renewable)
    this.externalLeases = 0; // registered operations observed on disk (each is deadline- and process-bound)
    this.progressLog = [];
  }
  heartbeat() { this.lastHeartbeatAt = this.now(); }
  activity() { this.lastActivityAt = this.now(); }
  turn() { this.turns += 1; this.activity(); }
  // A registered bounded operation (compile/test/VM). Its deadline is fixed at
  // registration: re-registering the same id cannot push it out.
  registerLease(id, deadlineMs) {
    if (this.leases.has(id)) return false;
    this.leases.set(id, this.now() + deadlineMs);
    return true;
  }
  setExternalLeases(n) { this.externalLeases = n; }
  releaseLease(id) { this.leases.delete(id); }
  activeLeases() {
    const t = this.now();
    for (const [id, d] of this.leases) if (d <= t) this.leases.delete(id);
    return this.leases.size;
  }
  // Only a recognised progress kind with evidence resets the clock.
  recordProgress(kind, evidence) {
    if (!PROGRESS_KINDS.includes(kind) || !evidence) return false;
    this.lastProgressAt = this.now();
    this.progressLog.push({ at: this.lastProgressAt, kind });
    return true;
  }
  // -> null, or { action: 'terminate', reason }
  check() {
    const t = this.now();
    if (this.turns > this.limits.maxTurns) return { action: 'terminate', reason: 'turn-limit', detail: `${this.turns} turns > ${this.limits.maxTurns}` };
    if (t - this.startedAt >= this.limits.attemptMs) return { action: 'terminate', reason: 'attempt-deadline' };
    if (t - this.lastProgressAt >= this.limits.noProgressMs) return { action: 'terminate', reason: 'no-substantive-progress' };
    if (t - this.lastActivityAt >= this.limits.idleMs && this.activeLeases() === 0 && this.externalLeases === 0) return { action: 'terminate', reason: 'idle' };
    return null;
  }
}
