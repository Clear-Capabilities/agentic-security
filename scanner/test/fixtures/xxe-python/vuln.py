# Vulnerable: lxml.etree.parse without safe parser
from lxml import etree

def parse_payload(buf):
    tree = etree.parse(buf)
    return tree.getroot()

import xml.etree.ElementTree as ET
def parse_with_stdlib(buf):
    return ET.parse(buf).getroot()

import xml.sax
def parse_sax(buf):
    return xml.sax.parseString(buf, ContentHandlerStub())

class ContentHandlerStub:
    pass
