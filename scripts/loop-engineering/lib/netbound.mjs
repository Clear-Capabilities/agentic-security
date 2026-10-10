// Bounded network calls for controller-owned code (LOOP-002): every request has a per-request timeout (networkRequestSeconds), a bounded
// retry count (networkRetries) and a backoff that is capped (retryBackoffMaxSeconds). The deadline is enforced HERE with a timer race,
// not by trusting the callee: a hung callee that ignores its abort signal is still cut at the boundary and the attempt is abandoned.
// Callers that start a process (gh, git) also pass the bound down so the process group dies with the request.
import { getBounds } from './bounds.mjs';

const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class NetTimeoutError extends Error {
  constructor(ms) { super(`network request exceeded its ${ms / 1000}s bound`); this.name = 'NetTimeoutError'; this.code = 'ENETTIMEOUT'; }
}

/** The policy in force, or null when the profile configured none (legacy behaviour). */
export function netPolicy(b = getBounds()) {
  if (b.networkRequestSeconds == null || b.networkRetries == null) return null;
  return { requestMs: b.networkRequestSeconds * 1000, retries: b.networkRetries, backoffMaxMs: b.retryBackoffMaxSeconds * 1000 };
}

/** Backoff before retry number `retry` (1-based): exponential from baseMs, never above the cap. */
export const backoffMs = (retry, baseMs, capMs) => Math.min(capMs, baseMs * 2 ** Math.max(0, retry - 1));

/**
 * attempt(signal) -> Promise. Resolves with the value of the first attempt that succeeds. A timeout or an error `isTransient` accepts is
 * retried up to policy.retries more times (so at most retries + 1 attempts); anything else is thrown at once. The final failure carries
 * `netAttempts` and `netTimedOut`.
 */
export async function boundedNetCall(attempt, { policy = netPolicy(), baseBackoffMs = 1000, isTransient = () => false, sleep = realSleep, onRetry = null } = {}) {
  if (!policy) return attempt(undefined);
  let last = null;
  for (let n = 1; n <= policy.retries + 1; n++) {
    const ac = new AbortController();
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => { ac.abort(); reject(new NetTimeoutError(policy.requestMs)); }, policy.requestMs); });
    try {
      return await Promise.race([attempt(ac.signal), timeout]);
    } catch (e) {
      last = e;
      const retriable = e instanceof NetTimeoutError || isTransient(e);
      if (!retriable) { e.netAttempts = n; throw e; }
      if (n <= policy.retries) {
        const wait = backoffMs(n, baseBackoffMs, policy.backoffMaxMs);
        if (onRetry) { try { onRetry({ attempt: n, waitMs: wait, error: e }); } catch { /* observer only */ } }
        await sleep(wait);
      }
    } finally { clearTimeout(timer); }
  }
  last.netAttempts = policy.retries + 1;
  last.netTimedOut = last instanceof NetTimeoutError;
  throw last;
}
