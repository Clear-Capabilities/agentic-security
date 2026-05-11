const express = require('express');
const app = express();
const { PrismaClient } = require('@prisma/client');
const { Sequelize, sequelize } = require('sequelize');

const prisma = new PrismaClient();

// Prisma raw — tagged template with user input
app.get('/users/prisma/:id', async (req, res) => {
  const u = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${req.params.id}`;
  res.json(u);
});

// Prisma executeRaw with concat
app.delete('/users/prisma/:id', async (req, res) => {
  await prisma.$executeRaw('DELETE FROM users WHERE id = ' + req.params.id);
});

// Sequelize literal in where clause
app.get('/users/seq', async (req, res) => {
  const where = sequelize.literal(`name = '${req.query.name}'`);
  const users = await User.findAll({ where });
  res.json(users);
});

// TypeORM unsafe orderBy
app.get('/users/typeorm', async (req, res) => {
  const repo = getRepository(User).createQueryBuilder('u').where(`u.name = '${req.query.name}'`);
  const users = await repo.getMany();
  res.json(users);
});

app.listen(3000);
