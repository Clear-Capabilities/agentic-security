const he = require('he');
function render(userUrl, el) {
  // WRONG: HTML-entity encoding does not stop javascript: scheme in a URL.
  el.href = he.encode(userUrl);
  el.src = escapeHtml(userUrl);
}
