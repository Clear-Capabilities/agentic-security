# assurance-demo

A small project owned by this repository, built to be scanned, triaged, validated, patched, verified, correlated with runtime metadata, signed and checked offline by `scripts/engineering-excellence/e2e-demo.mjs`.

It is deliberately flawed, so **do not "improve" it**: the captured output in `docs/engineering-excellence/E2E_DEMO.md` quotes its findings.

| Where | What it holds |
|---|---|
| `services/api/app.js` | Express service: a SQL injection (`/search`), two safe lookalikes (`/lookup` is bound, `/report` is a constant), an IDOR (`PUT /notes/:id`), a cross-tenant read (`GET /invoices/:id/lines`) with an enforcing sibling for each |
| `services/worker/convert.py` | Flask worker: a command injection (`/convert`) and a safe lookalike (`/probe` passes an argument list) |
| `services/api/importer.js` | Calls one advisory function of `acme-xml-lite` (reachable) and never calls the advisory function of `acme-img-tools` (imported, not reachable) |
| `package.json` | Two dependencies with a LOCAL advisory (`spec/advisories.json`): one whose vulnerable function the API calls, one it never calls |
| `spec/behavior.json` | The project's behaviour checks: requests with the outcome each must still have after a patch (the owner can still update their own note) |
| `spec/patches.json` | Candidate patches: a correct fix, and a "false fix" that makes the detector go quiet by denying every request |
| `spec/runtime-records.json` | Runtime metadata to ingest, only when runtime collection is switched on (it is off by default) |

No network is used. The advisories are local data written for this demo, not a feed.
