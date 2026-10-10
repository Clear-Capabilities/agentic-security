// Fixed: an order is changed only by an actor of the tenant that owns it.
export function createApp() {
  return {
    updateOrder(ctx, key, note) {
      const order = ctx.store.read(key);
      if (!order) return { status: 404 };
      if (order.tenant !== ctx.tenant) return { status: 403 };
      ctx.store.write(key, { ...order, note });
      return { status: 200 };
    },
  };
}
