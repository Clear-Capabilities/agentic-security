const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const INVOICE_DIR = path.join(__dirname, '..', 'data', 'invoices');

// VULNERABLE: path traversal. `filename` is joined onto the base directory
// with no validation — an attacker supplies `../../../../etc/passwd` (or an
// absolute path, which path.join happily accepts as an override on most
// platforms) to read any file the server process can access.
router.get('/invoice', (req, res) => {
  const filename = req.query.filename;
  const target = path.join(INVOICE_DIR, filename);
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.type('text/plain').send(data);
  });
});

// FIXED variant: the resolved path is required to still be INSIDE
// INVOICE_DIR after resolution — `..` segments or an absolute-path override
// that would escape the base directory are rejected before the file is
// ever opened.
router.get('/invoice-safe', (req, res) => {
  const filename = req.query.filename;
  const target = path.join(INVOICE_DIR, filename);
  const resolved = path.resolve(target);
  if (!resolved.startsWith(path.resolve(INVOICE_DIR) + path.sep)) {
    return res.status(400).send('invalid filename');
  }
  fs.readFile(resolved, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.type('text/plain').send(data);
  });
});

module.exports = router;
