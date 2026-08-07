// A second file so the digest depends on more than one path, which is what
// makes a path-ordering difference between machines visible.
module.exports = function redirect(req, res) {
  res.redirect(req.query.next);
};
