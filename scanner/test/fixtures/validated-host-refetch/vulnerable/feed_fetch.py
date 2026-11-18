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


def fetch_feed(feed_url):
    ensure_public(feed_url)
    resp = requests.get(feed_url, timeout=5)
    return resp.text
