# Synthetic fixture: the third method has no named guard, but it checks the
# name by hand and exits, and the fourth hands the name to a same-file helper
# that applies the guard. Neither is a deviation.
import os

from .paths import ensure_inside_root


class ArchiveStore:
    def __init__(self, fs, root):
        self.fs = fs
        self.root = root

    def _confined(self, name):
        ensure_inside_root(self.root, name)
        return name

    def put_a(self, name, body):
        ensure_inside_root(self.root, name)
        self.fs.write(os.path.join(self.root, name), body)

    def put_b(self, name, body):
        ensure_inside_root(self.root, name)
        self.fs.write(os.path.join(self.root, name), body)

    def put_c(self, name, body):
        if ".." in name or name.startswith("/"):
            raise ValueError("bad name")
        self.fs.write(os.path.join(self.root, name), body)

    def put_d(self, name, body):
        self._confined(name)
        self.fs.write(os.path.join(self.root, name), body)
