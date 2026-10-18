# Mitigated: an argument vector, no shell, so the input is data and never a command.
import subprocess
import sys

name = sys.argv[1] if len(sys.argv) > 1 else ""
subprocess.run(["echo", "hello", name])
