// Fixed: only the API host is allowed.
export async function fetchPreview(url, deps) {
  if (!url.startsWith('https://api.example/')) throw new Error('destination not allowed');
  return deps.fetch(url);
}
