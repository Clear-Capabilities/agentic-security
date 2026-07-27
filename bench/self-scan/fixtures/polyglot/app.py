import sys


def emit(payload):
    sys.stderr.write(payload)
    fh = open("/tmp/out.log", "w")
    fh.write(payload)
    fh.close()
