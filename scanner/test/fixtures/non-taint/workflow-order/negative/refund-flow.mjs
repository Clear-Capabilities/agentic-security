// Same workflow, refund only after approval.
export function createRefundFlow() {
  let state = 'draft';
  return {
    get state() { return state; },
    send(event) {
      if (event === 'submit' && state === 'draft') state = 'submitted';
      else if (event === 'approve' && state === 'submitted') state = 'approved';
      else if (event === 'refund' && state === 'approved') state = 'refunded';
      else throw new Error(`illegal transition: ${event} from ${state}`);
    },
  };
}
