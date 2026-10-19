# Deliberately vulnerable: untrusted input is concatenated into a shell command (CWE-78).
import os
import sys

name = sys.argv[1] if len(sys.argv) > 1 else ""
os.system("echo hello " + name)
