# Synthetic fixture: the same loop, narrowing the headers whenever a hop changes origin.
def fetch_document(client, url, headers=None):
    current = url
    hop_headers = headers
    for _ in range(5):
        response = client.get(
            current,
            headers=hop_headers,
            follow_redirects=False,
        )
        next_hop = response.headers.get("location")
        if not next_hop:
            return response.text
        target = resolve_redirect(current, next_hop)
        hop_headers = headers_for_hop(hop_headers, current, target)
        current = target
    raise RuntimeError("too many redirects")
