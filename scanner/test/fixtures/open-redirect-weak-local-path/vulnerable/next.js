export function safeRedirectTarget(next) {
  if (typeof next === 'string' && next.startsWith('/')) return next;
  return '/';
}
