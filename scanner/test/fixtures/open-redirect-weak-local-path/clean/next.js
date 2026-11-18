export function safeRedirectTarget(next) {
  if (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\')) return next;
  return '/';
}

export function withLeadingSlash(path) {
  return path.startsWith('/') ? path : `/${path}`;
}
