import ipaddress
import socket
from urllib.parse import urlparse

import requests


def ensure_public(url):
    host = urlparse(url).hostname
    if not host:
        raise ValueError("no host")
    addr = ipaddress.ip_address(socket.gethostbyname(host))
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError("internal address")
    return str(addr)


def fetch_feed(feed_url):
    checked_ip = ensure_public(feed_url)
    parsed = urlparse(feed_url)
    pinned = parsed._replace(netloc=checked_ip).geturl()
    resp = requests.get(pinned, timeout=5, allow_redirects=False, headers={"Host": parsed.hostname})
    return resp.text
