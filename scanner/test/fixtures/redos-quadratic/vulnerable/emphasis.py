# Independently authored: an emphasis pattern whose star runs can split between iterations.
import re

STRONG = r'(\*)((?:[^\*]|\*{2,})+?)(\*)'


def compile_patterns():
    return [re.compile(STRONG)]
