export function createApp() { return { settle(ctx, key, p) {
      const seen = ctx.store.read('seen/' + p.requestId); const payer = ctx.store.read('ledger/payer'); const payee = ctx.store.read('ledger/payee');
      if (seen) { ctx.store.write('ledger/payee', { ...payee, amount: payee.amount + p.amount }); return { status: 200 }; }
      ctx.store.write('seen/' + p.requestId, { done: true });
      ctx.store.write('ledger/payer', { ...payer, amount: payer.amount - p.amount }); ctx.store.write('ledger/payee', { ...ctx.store.read('ledger/payee'), amount: ctx.store.read('ledger/payee').amount + p.amount });
      return { status: 200 }; } }; }
