function escapeHtml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }

function safeUrl(value) {
  const href = String(value || '').trim().replace(/[\x00-\x1f\x7f]/g, '');
  const scheme = href.match(/^([A-Za-z][A-Za-z0-9+.-]*):/);
  if (scheme && !/^(https?|mailto|tel)$/i.test(scheme[1])) return null;
  return href;
}

export function renderLink(token) {
  const href = safeUrl(token.href);
  if (href === null) return escapeHtml(token.text);
  return '<a href="' + escapeHtml(href) + '">' + escapeHtml(token.text) + '</a>';
}
