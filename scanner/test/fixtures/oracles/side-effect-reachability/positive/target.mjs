// Vulnerable: the caller's URL goes straight to the fetch operation.
export async function fetchPreview(url, deps) {
  return deps.fetch(url);
}
