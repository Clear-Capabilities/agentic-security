# Contract-driven hunting and verified remediation

What this directory holds: the Phase 0 gap audit (`GAP-AUDIT.md`, with the four subsystem audit notes under `audit/`), the requirement
and acceptance ledger (`ledger.json`: implementation and evidence are separate columns), and this guide. The programme connects the
operator's statement of what a service must guarantee (a service security contract) to the context build, the hunt, the qualification
and refutation of candidates, the executable scenario, the repair verification and the regression artifact, under one identity.

## Status, honestly

- Implemented and pinned by tests on a synthetic fixture: the contract schema and its readable companion, approval through the one
  signed ledger (with revoke and expiry), the context supplier, the hunt's contract-aware mode, the structured qualification record,
  evidence-grounded refutation with full retention, the per-candidate stage history, contract identity in the regression artifact, and
  the `contracts` command. `npm run example:contract-slice` runs the connected slice on this host.
- Not measured: the effectiveness of any model under this mode. Every model in the tests and in the slice is a scripted function of the
  prompt. No real-code population has been run through the contract-aware hunt. Those are Phase 2 (Epic C) and are `unmeasured` in the
  ledger until then.
- Unsupported in this build: runtime-predicate and preservation bindings of a contract (no producer yet), a real framework or database
  profile for the oracle (the fixture is plain Node over an in-memory store), and the Linux trust boundary for the business-state
  oracle (not advertised; the slice executes where the host boundary runs and says `unsupported` elsewhere).

## Phases 2 to 5 (implemented on synthetic data)

- **Evaluation:** per-defect stability over scheduled repetitions with failed and cancelled trials kept in the denominators, stage
  attrition, the evaluator-only `eval semantic` view, the contract arm (`adapter.contract` on the hunt arm), a population label on every
  run, and a router that refuses synthetic scores. No real model has been run through it: the four-arm comparison is unmeasured.
- **Service scope:** `contracts/service-scope.js` resolves the contract's repositories from an operator root map at exact revisions,
  with distinct gaps, and reads identity propagation between components (spoofable forwarded headers, tenants taken from messages).
- **Real profiles:** Express and FastAPI with PostgreSQL are declared with one lifecycle and typed setup blockers. On this host both are
  `setup-blocked` (framework not installed, no PostgreSQL, image pulls not authorised); no confined runner for a real database exists.
- **Faults and verifier strength:** fault plans on the business-state harness (duplicate delivery, explicit reorder, revocation between
  steps), harness fault tests for the ledger, and a semantic mutation population over the slice.
- **Runtime feedback:** imported traces become discrepancies, proposed contract revisions and gated regression records; an isolated
  shadow comparison fails a patch that breaks the authorized workflow.

The acceptance matrix with every criterion's status is `ACCEPTANCE.md`.

## Commands

```
agentic-security contracts validate <contract.json>
agentic-security contracts inspect <contract.json> [--ledger <ledger.json>] [--root <dir>] [--json]
agentic-security contracts draft --root <dir> [--out <contract.json>] [--id <service-id>]
agentic-security context build --root <dir>
agentic-security hunt --root <dir> --contract <contract.json> [--ledger <ledger.json>] [--no-memory]
npm run example:contract-slice            # from scanner/: the slice end to end, exit 0 ok, 1 failed, 3 host cannot run the boundary
```

`draft` writes a PROPOSED contract from the context build (no model, no network); a reviewer records approval in the ledger with the
existing invariant tooling (`posture/invariants/lifecycle.js` through `contracts/approval.js`), named by the project's
`.agentic-security/reviewer-policy.json`. A contract file that says `approved` is not approved. `hunt --contract` enables no paid call,
no live access and no new execution authority; it adds the verified context bundles to the hunter and the panel and qualifies every
candidate. A partial or unavailable context is printed as such and is never a clean pass.

## The slice

`scanner/test/fixtures/contract-slice/`: a two-tenant invoice service whose PUT memo route lacks the tenant scope. The script runs, in
order, contract validation and pack reconciliation; approval in a local ledger by a fixture reviewer (synthetic); the context build (3
bundles, complete); the deterministic context rule `INVOICES-TENANT-SCOPE` (GET and POST satisfied, PUT violated); the hunt in
contract-aware mode with the scripted model (the candidate is `qualified` under `TENANT-ISOLATION-001`, with a five-stage history);
the executable invariant through the business-state oracle (vulnerable: `confirmed`, approved violation; patched: `refuted`); the
repair verification (`verified-fix`, artifact carrying the contract ref) and a patch that blocks everyone (`not-verified-fix`,
`authorized-workflow-broken`). Measured on this host on 2026-11-22; the host's timing is in the script's `--json` output when needed.

## Where the code is

`scanner/src/contracts/` (guide in its `CLAUDE.md`), `scanner/src/discovery/context-supplier.js`, the contract-mode paths in
`scanner/src/discovery/{index,lenses,hunter,disprove}.js`, the `contract` field of `scanner/src/posture/invariants/repair.js`, and the
`service-contract` subject in `scanner/src/posture/invariants/lifecycle.js`. Tests: `scanner/test/contracts-driven/`.
