// Refund workflow: submitted -> approved -> refunded. Vulnerable: refund is accepted straight from "submitted",
// so the approval step can be skipped. No tainted data is involved.
export function createRefundFlow() {
  let state = 'draft';
  return {
    get state() { return state; },
    send(event) {
      if (event === 'submit' && state === 'draft') state = 'submitted';
      else if (event === 'approve' && state === 'submitted') state = 'approved';
      else if (event === 'refund' && (state === 'approved' || state === 'submitted')) state = 'refunded';
      else throw new Error(`illegal transition: ${event} from ${state}`);
    },
  };
}
