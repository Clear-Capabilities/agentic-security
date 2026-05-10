import { prisma } from './db.js';
import express from 'express';
const app = express();

app.get('/api/orders/:id', async (req, res) => {
  const order = await prisma.order.findUnique({
    where: { id: req.params.id, tenantId: req.user.tenantId }
  });
  res.json(order);
});
