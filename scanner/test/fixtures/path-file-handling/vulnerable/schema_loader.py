import json
from pathlib import Path


class SchemaLoader:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)

    def load_ref(self, ref):
        target = self.base_dir / ref
        with open(target) as fh:
            return json.load(fh)


def is_suspicious(path):
    if os.path.normpath(path) != path:
        raise ValueError("bad path")
    return path


def inside(root, candidate):
    real_root = os.path.realpath(root)
    real_candidate = os.path.realpath(candidate)
    return real_candidate.startswith(real_root)
