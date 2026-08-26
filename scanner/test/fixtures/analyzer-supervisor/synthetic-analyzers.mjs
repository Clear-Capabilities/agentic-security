// Synthetic analyzer functions for test/analyzer-supervisor.test.js.
//
// A REAL hang (busy-wait), not a mocked one — the whole point of this
// fixture is to prove runWithDeadline's worker.terminate() actually
// preempts synchronous JavaScript that would otherwise never return.

export function quickWork(a, b) {
  return a + b;
}

export function throwsError(message) {
  throw new Error(message);
}

// A genuine infinite loop with no iteration-count/clock checks anywhere in
// it — exactly the class of hang neither _perFileTimeoutMs nor
// AGENTIC_SECURITY_DEEP_TIMEOUT_MS's cooperative deadlineMs check can stop.
export function hangForever() {
  // eslint-disable-next-line no-constant-condition
  while (true) {
    // busy-wait; deliberately does no I/O and checks no clock
  }
}
