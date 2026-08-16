def identity(payload):
    return payload


def emit():
    path = identity("/tmp/out.log")
    fh = open(path, "w")
    fh.close()
