// Synthetic fixture: cached responses are looked up by the full canonical request string.
const cache = new Map<string, unknown>();

export function cacheKeyFor(request: { method: string; url: string; body: string }): string {
  const cacheKey = [request.method, request.url, request.body].join('|');
  return cacheKey;
}

export function lookup(request: { method: string; url: string; body: string }): unknown {
  return cache.get(cacheKeyFor(request));
}
