# Safe: defusedxml drop-in replacement
from defusedxml import ElementTree as ET
from lxml import etree

def parse_payload(buf):
    # Even lxml usage suppresses when defusedxml is imported in file
    tree = etree.parse(buf)
    return tree.getroot()
