function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

export function avatar(user) {
  return `<a href="${escapeHtml(user.website)}">profile</a>`;
}
