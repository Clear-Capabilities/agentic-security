# Deliberately vulnerable: pickle.loads on untrusted data runs whatever the data says (CWE-502).
import pickle
import sys

data = (sys.argv[1] if len(sys.argv) > 1 else "").encode("latin-1")
try:
    pickle.loads(data)
except Exception:
    pass
