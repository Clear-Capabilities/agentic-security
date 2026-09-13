const express = require('express');
const router = express.Router();

const comments = [];

// VULNERABLE: reflected + stored XSS. The submitted comment `text` is
// stored verbatim and later rendered directly into an HTML response with
// no output encoding — a `<script>` payload executes in every future
// visitor's browser in the site's own origin.
router.post('/add', (req, res) => {
  comments.push({ text: req.body.text, author: req.body.author });
  res.redirect('/comments/list');
});

router.get('/list', (req, res) => {
  let html = '<html><body><h1>Comments</h1>';
  for (const c of comments) {
    html += '<div class="comment"><b>' + c.author + ':</b> ' + c.text + '</div>';
  }
  html += '</body></html>';
  res.type('html').send(html);
});

// FIXED variant: both fields are HTML-escaped before being placed into the
// response, so a `<script>` payload renders as inert literal text.
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

router.get('/list-safe', (req, res) => {
  let html = '<html><body><h1>Comments</h1>';
  for (const c of comments) {
    html += '<div class="comment"><b>' + escapeHtml(c.author) + ':</b> ' + escapeHtml(c.text) + '</div>';
  }
  html += '</body></html>';
  res.type('html').send(html);
});

module.exports = router;
