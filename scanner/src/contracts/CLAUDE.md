# scanner/src/contracts/

The service security contract and what follows from it (the contract-driven verification programme, Epics A and B). Additive and
opt-in: nothing in the default scan, the default `hunt` or the default `context` command imports this directory.

## What a contract is

`schema.js`: `agentic-security/service-contract` 1.0.0. The operator's statement of what a service must guarantee: invariants in plain
language with the attacker each assumes, the repositories at exact commits and the environment it speaks about, declared compensating
controls, and the bindings that connect each invariant to the producers that can check it (`dciInvariantRefs` for the deterministic
context-intelligence rules, `scenarioInvariantRefs` for executable scenario invariants, `runtimePredicateRefs`, `preservationRefs`). It is
closed-world data. A placeholder revision, an absolute or home path, a string shaped like a command or a credential, an unknown field,
a dangling control reference, or an `observed`/`executed` control with no evidence reference is refused. `contractDigest` covers the
semantic content; `contractRef` is `<id>@<version>#<digest16>` and `invariantRef` adds `/<INVARIANT-ID>`. The review claim in the
document is not content and is not authority.

`pack.js`: the readable companion `threat-pack.md`, bound into the contract by digest and reconciled, never interpreted: a pack that names
an invariant the contract lacks, or omits one it declares, is a diagnostic with both sources (`reconcilePack`).

`bindingView`: per invariant, which binding kinds are declared, missing or unsupported by this build. A missing binding is a gap, never a
satisfied check (A-AC06).

## Approval

`approval.js` is an adapter over the ONE approval ledger, `posture/invariants/lifecycle.js`: a contract is proposed and approved there as
a `service-contract` subject (the ledger gained the subject kind and a `revoke` action; transition ids and signatures are unchanged, so
every earlier ledger still verifies). `approvalState(contract, ledger, { policy, registry, signer, now })` returns `proposed`,
`approved`, `rejected`, `superseded`, `revoked`, `expired` (by the contract's review policy or hard date, with `now` always supplied by
the caller), `wrong-scope` (the ledger approves the same id and version with another digest: the contract changed after review),
`not-recorded` or `approval-unverifiable` (the ledger does not verify, including a recorded reviewer the current policy no longer
authorises). Only `approved` with `current: true` is authority. A model may propose; it cannot approve (A-AC02).

## Qualification and refutation

`qualification.js` builds the additive `candidate.qualification` record (B-02): `contractRef`, the matched `invariantId` (named by the
hunter only when the contract declares it; otherwise by the entry points that reach the cited line; otherwise `contract-gap`), the
attacker assumptions (marked `model-proposed`, never established), the citation with its status against the bundle the model was shown,
the controls the context layer recorded with their effectiveness on the path, what is unresolved, and a decision: `qualified`,
`needs-context` (partial, stale or unavailable context, or a citation that does not resolve: never safe), `contract-gap` (kept with its
evidence; A-AC05), `disqualified` (only `discovery/disprove.js` sets it, with a grounded blocker).

The refutation panel (`discovery/disprove.js`) returns a cited blocker (`refutation-vote/2`); grounding is in that module's header.

## Where the pieces meet

`discovery/context-supplier.js` reads the context-intelligence store for a scanned root and serves verified package texts, per-candidate
spans and controls, and the citation check. `discovery/index.js` `runDiscovery(ctx, { contractMode: { contract, approval, supplier? } })`
threads it through the hunter prompt (a VERIFIED CONTEXT block, fenced as data, a third of the budget), the panel, the qualification of
every candidate, the per-candidate `history[]` and the `attrition` tally in the report (B-04); memory learns only from grounded
refutations. The regression artifact of `posture/invariants/repair.js` carries `contract: { ref, invariantId }` when the repair was
requested for one (A-03, F-04).

## The slice fixture

`test/fixtures/contract-slice/`: a two-tenant invoice service (`server.js` routes over `service.mjs`, which also exports the oracle factory
`createApp()`), its contract and threat pack under `security/contracts/invoices-service/`, the executable invariant and the DCI
invariants. `test/fixtures/contract-slice-patch/service.mjs` is the repair. The PUT memo route lacks the tenant scope; GET and POST
carry it. Tests: `test/contracts-driven/` (`npm run test:contracts-driven`). The model in those tests is a scripted function of the
prompt: it proves plumbing and says nothing about any model's effectiveness.

## Invariants (break one and a test fails)

- A document's `review.state` never decides anything; only the signed ledger does, re-verified against the current policy.
- An invariant id the hunter names that the contract does not declare is a contract gap, never accepted.
- A missing or unverifiable context store is `unavailable` in every record it touches; it is never "nothing to see".
- `now` is an input: no module here reads the clock.
