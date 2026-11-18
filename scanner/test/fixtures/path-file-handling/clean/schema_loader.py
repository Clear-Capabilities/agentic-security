import json
from pathlib import Path


class SchemaLoader:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)

    def load_ref(self, ref):
        target = (self.base_dir / ref).resolve()
        if not target.is_relative_to(self.base_dir.resolve()):
            raise ValueError("reference escapes the schema directory")
        with open(target) as fh:
            return json.load(fh)


def is_suspicious(path):
    if os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("bad path")
    if ".." in path.split("/"):
        raise ValueError("bad path")
    return path


def inside(root, candidate):
    real_root = os.path.realpath(root)
    real_candidate = os.path.realpath(candidate)
    return real_candidate.startswith(real_root + os.sep)
