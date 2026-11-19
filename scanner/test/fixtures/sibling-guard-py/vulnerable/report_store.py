# Synthetic fixture: two methods confine the name under the root before
# writing, save_draft() writes the caller's name unchecked.
import os

from .paths import ensure_inside_root


class ReportStore:
    def __init__(self, fs, root):
        self.fs = fs
        self.root = root

    def save_report(self, name, body):
        """Write a finished report."""
        ensure_inside_root(self.root, name)
        self.fs.write(os.path.join(self.root, name), body)

    def save_attachment(self, name, data):
        ensure_inside_root(self.root, name)
        self.fs.write(os.path.join(self.root, name), data)

    def save_draft(self, name, body):
        self.fs.write(os.path.join(self.root, name), body)
