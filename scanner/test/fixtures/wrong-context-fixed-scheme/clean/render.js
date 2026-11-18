function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

export function thumbnail(img) {
  return `<img src="data:${escapeHtml(img.mime)};base64,${escapeHtml(img.bytes)}" />`;
}

export function profileLink(user) {
  return `<a href="/users/${escapeHtml(user.id)}">profile</a>`;
}
