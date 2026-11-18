import os
import subprocess
import tempfile


def run_snippet(source, stdin_text=""):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as handle:
        handle.write(source)
        path = handle.name
    result = subprocess.run(["python3", path], input=stdin_text, text=True, capture_output=True, timeout=5)
    return result.stdout


def build_c(source):
    work = tempfile.mkdtemp()
    c_path = os.path.join(work, "prog.c")
    with open(c_path, "w") as out:
        out.write(source)
    cmd = ["gcc", "-o", os.path.join(work, "prog"), c_path]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)
