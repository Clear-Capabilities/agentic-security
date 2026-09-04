// Safe HTML-text escaping. Neither existing in-repo escaper is quote-complete
// (scanner/src/posture/fleet.js's `esc` skips `'`; scanner/src/badge.js's
// `_xmlEscape` skips `"` and `'`) — this one escapes all five HTML-significant
// characters so it is safe in both text content and quoted attribute values.

const ENTITIES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
});

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ENTITIES[c]);
}
