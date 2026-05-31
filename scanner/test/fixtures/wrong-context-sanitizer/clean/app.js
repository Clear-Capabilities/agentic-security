function render(userUrl, el) {
  // Correct: validate the scheme before using as a URL.
  if (!userUrl.startsWith('https://')) return;
  el.href = escapeHtml(userUrl);
  // HTML-entity encoding for HTML body text is the right context.
  el.textContent = escapeHtml(userUrl);
}
