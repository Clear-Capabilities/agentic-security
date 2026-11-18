// Synthetic fixture: cached responses are looked up by a 32-bit hash of the request.
const cache = new Map<string, unknown>();

function shortHash(text: string): string {
  let h = 0;
  for (const ch of text) {
    h = (Math.imul(31, h) + ch.charCodeAt(0)) | 0;
  }
  return String(h >>> 0);
}

export function cacheKeyFor(request: { method: string; url: string; body: string }): string {
  const cacheKey = shortHash([request.method, request.url, request.body].join('|'));
  return cacheKey;
}

export function lookup(request: { method: string; url: string; body: string }): unknown {
  return cache.get(cacheKeyFor(request));
}
