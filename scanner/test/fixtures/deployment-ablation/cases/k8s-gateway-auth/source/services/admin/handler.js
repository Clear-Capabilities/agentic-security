function status(req, res) {
  res.json({ ok: true, uptime: process.uptime() });
}

module.exports = { status };
