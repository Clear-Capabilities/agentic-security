// Vulnerable: shipment is accepted without payment.
export function createMachine() {
  let state = 'created';
  return {
    get state() { return state; },
    send(event) {
      if (event === 'pay' && state === 'created') state = 'paid';
      else if (event === 'ship') state = 'shipped';
      else throw new Error('illegal transition');
    },
  };
}
