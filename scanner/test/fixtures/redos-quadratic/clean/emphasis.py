# The same pattern with each star run forced to be maximal by a negative lookahead.
import re

STRONG = r'(\*)((?:[^\*]|\*{2,}(?!\*))+?)(\*)'


def compile_patterns():
    return [re.compile(STRONG)]
