// Deliberately vulnerable: fetches an attacker-controlled URL with no allowlist, from a confined sandbox with
// no outbound network — only the test runner's loopback callback listener is reachable.
const url = process.argv[2];
try { await fetch(url); } catch { /* ignore network errors — the proof is in whether the listener saw the request */ }
