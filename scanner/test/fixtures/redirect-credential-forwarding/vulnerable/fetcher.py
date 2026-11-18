# Synthetic fixture: a manual redirect loop that sends the same headers to every hop.
def fetch_document(client, url, headers=None):
    current = url
    for _ in range(5):
        response = client.get(
            current,
            headers=headers,
            follow_redirects=False,
        )
        next_hop = response.headers.get("location")
        if not next_hop:
            return response.text
        current = resolve_redirect(current, next_hop)
    raise RuntimeError("too many redirects")
