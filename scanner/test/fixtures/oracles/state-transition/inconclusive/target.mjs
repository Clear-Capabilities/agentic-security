// Payment is never implemented, so even the legal sequence cannot finish.
export function createMachine() {
  let state = 'created';
  return {
    get state() { return state; },
    send() { throw new Error('not implemented'); },
  };
}
