// Vulnerable: an order can be updated by any signed-in actor, whatever tenant owns it. The response is the same either way, so a
// status-code check alone would call the cross-tenant update a success of the legitimate flow.
export function createApp() {
  return {
    updateOrder(ctx, key, note) {
      const order = ctx.store.read(key);
      if (!order) return { status: 404 };
      ctx.store.write(key, { ...order, note });
      return { status: 200 };
    },
  };
}
