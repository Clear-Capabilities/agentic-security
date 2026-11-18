import subprocess
import tempfile

TEMPLATE = "print('ready')\n"


def run_template():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as handle:
        handle.write(TEMPLATE)
        path = handle.name
    return subprocess.run(["python3", path], capture_output=True, text=True, timeout=5).stdout


def save_note(note):
    with open("/var/tmp/notes.txt", "w") as out:
        out.write(note)
    return subprocess.run(["python3", "summarize.py"], capture_output=True, text=True, timeout=5).stdout
