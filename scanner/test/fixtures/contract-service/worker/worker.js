// Worker: applies the memo update a message describes.
import { queue } from './queue.js';

queue.consume('invoice-memo', async (msg, db) => {
  const tenant = msg.tenantId;
  await db.updateOne(`invoices/${msg.invoiceId}`, { memo: msg.note, tenant });
});
