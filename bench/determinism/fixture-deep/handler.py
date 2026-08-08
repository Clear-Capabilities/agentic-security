# Exercises the Python parser path. When python3 is present this goes through
# the stdlib `ast` subprocess; without it, the regex fallback. Those two produce
# DIFFERENT parser attribution, which is precisely why the attestation excludes
# `parser` from canonicalisation — so this fixture tests whether the FINDINGS
# agree across machines even when the parser underneath them may not.
import subprocess


def read_target(request):
    return request.args.get('host')


def ping(request):
    host = read_target(request)
    subprocess.call('ping -c 1 ' + host, shell=True)
