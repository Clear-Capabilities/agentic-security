# Mitigated: a data-only format. The result is a value, never code.
import json
import sys

data = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    json.loads(data)
except ValueError:
    pass
