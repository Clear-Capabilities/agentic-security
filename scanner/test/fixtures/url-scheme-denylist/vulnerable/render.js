function escapeHtml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }

export function renderLink(token) {
  const href = (token.href || '').trim();
  if (/^\s*(javascript|vbscript|data):/i.test(href)) {
    return escapeHtml(token.text);
  }
  return '<a href="' + escapeHtml(href) + '">' + escapeHtml(token.text) + '</a>';
}
