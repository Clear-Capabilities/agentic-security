import re

LINK_TEMPLATES = {
    'tracker': (
        r'''
        (?P<tracker>(?P<base>{}/
        (?P<project>[^/]+))/
            (?:tickets/(?P<ticket>\d+)(?:/[^/]+)?/?|
                reviews/(?P<review>\d+)(?:/[^/]+(?:/changes)?)?/?))''',
        r'tracker\.example'
    ),
}


def ratio(total, parts):
    return total / parts / 2
