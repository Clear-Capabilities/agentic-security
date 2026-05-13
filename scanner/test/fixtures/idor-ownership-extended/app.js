// Extended IDOR ownership shapes — must NOT fire IDOR on the safe shapes
// and MUST fire on the genuinely vulnerable ones.
const express = require('express');
const app = express();

// SAFE: Prisma AND-nested ownership
app.get('/safe1/:id', async (req, res) => {
  const item = await prisma.item.findFirst({
    where: { id: req.params.id, AND: { userId: req.user.id } }
  });
  res.json(item);
});

// SAFE: Sequelize ownership via spread helper
function ownedBy(uid) { return { UserId: uid }; }
app.get('/safe2/:id', async (req, res) => {
  const item = await Item.findOne({
    where: { id: req.params.id, ...ownedBy(req.user.id) }
  });
  res.json(item);
});

// SAFE: separate const for userId then ownership clause
app.get('/safe3/:id', async (req, res) => {
  const userId = req.user.id;
  const item = await Item.findOne({ where: { id: req.params.id, ownerId: userId } });
  res.json(item);
});

// SAFE: ownership via post-lookup compare + 403 guard
app.get('/safe4/:id', async (req, res) => {
  const item = await Item.findById(req.params.id);
  if (!item || item.userId !== req.user.id) return res.status(403).send();
  res.json(item);
});

// VULNERABLE: no ownership clause at all
app.get('/vuln1/:id', async (req, res) => {
  const item = await Item.findById(req.params.id);
  res.json(item);
});

// VULNERABLE: ownership column bound to attacker-controlled value
app.get('/vuln2/:id', async (req, res) => {
  const item = await Item.findOne({ where: { id: req.params.id, userId: req.body.userId } });
  res.json(item);
});

app.listen(3000);
