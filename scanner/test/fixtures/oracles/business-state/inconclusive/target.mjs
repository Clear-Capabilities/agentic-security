// Not implemented: every action throws, so even the legitimate flow changes nothing and the application is not shown to be working.
export function createApp() {
  return {
    updateOrder() { throw new Error('not implemented'); },
  };
}
