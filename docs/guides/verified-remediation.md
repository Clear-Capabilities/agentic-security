# Contract-driven repair

`agentic-security repair` repairs one finding against an executable contract. The contract states what the repair must establish: the attacks that must stop working, the legitimate requests that must keep working, and the project checks that must still pass. A candidate patch is accepted only when every required obligation passes on exactly that patch, in the trust boundary. A verified result holds for that contract only.

This is a Labs capability. The shapes, outcomes and exit codes are in the [repair contract reference](../reference/repair-contract.md).

## What it covers in this release

| Family | What is executed |
| --- | --- |
| `sql-injection` | The application's own request handler over a real SQLite file. Attack probes go into each declared untrusted value; a planted secret belonging to another user must not appear in any response. Declared legitimate values must still return their data, including values the original gets wrong, such as a title with a quote. |
| `object-authorization` | Every declared actor (owner, another member, an admin, another tenant, anonymous) against every declared object and operation. A denied read must not disclose the object's planted secret. A denied update must leave the stored value unchanged, whatever status code the application returns. Allowed actors must keep working. |

Node applications over SQLite only. Requests run one at a time in one process.

## The workflow

1. **Scan**, so the finding is in the signed scan state:

   ```bash
   agentic-security scan .
   ```

2. **Write an application profile** (see the reference for every field). It names the entry module and its factory, the database schema and seed, the actors and how each one authenticates, and per family the inputs or objects to exercise. Keep it outside the repository if its facts should count as approved: a profile inside the repository is recorded as declared.

3. **Plan.** This builds the contract and executes nothing:

   ```bash
   agentic-security repair plan --profile ../notes-profile.json --finding <finding-id>
   ```

   The output lists every required obligation, the edit scope and what the contract does not observe. If the scanner did not report the finding, name it yourself with `--family sql-injection --file src/app.mjs`. Its custody is then `unresolved`.

4. **Run.** Running executes the application and the candidates, so the operator enables it explicitly:

   ```bash
   agentic-security repair run --plan <plan.json> --allow-execution
   ```

   For a SQL finding the deterministic recipe proposes a parameterized query. Supply your own candidates with `--candidates candidates.json` (`{"candidates":[{"files":{"src/app.mjs":"..."}}]}`); they are judged in order, one per round, and each failed candidate's counterexample is recorded.

5. **Apply**, if you want the verified patch written:

   ```bash
   agentic-security repair run --plan <plan.json> --allow-execution --apply
   ```

   The write goes through the same apply service as `fix --apply`: signed scan state, path confinement, material-change approval and the concurrent-modification check. Source that changed after planning is refused.

6. **Inspect, export, resume.** `repair show <run-id>`, `repair export <run-id> --out <dir>`, `repair verify <dir> --root .`, `repair cancel <run-id>`, `repair resume <run-id>`.

## Reading the result

The disposition is the answer. `verified-for-contract` means a candidate passed every required obligation, including a sealed set of held-out attack variants that is never shown to candidate generation. `rejected` means every candidate failed one, and `counterexamples` names the request, the actor and the property each one broke. A `blocked` or `needs-review` run says what is missing in `nextPrerequisite`.

Checks generated from the profile that cannot mean anything on the original are quarantined, each with its reason, rather than silently counted. An attack that discloses nothing on the original cannot show that a patch fixed it.

## What a verified result does not mean

- It does not mean the application is free of the weakness outside the declared requests, actors and objects.
- It does not mean the patch was built, staged or deployed: every record says `source-only`.
- It does not mean concurrency is safe: no concurrent execution is exercised.
- On Linux the trust boundary does not run yet, so repair execution there is reported as `blocked`.

The adversarial corpus that keeps the verifier honest is `bench/repair/`: deliberately ineffective patches (indirection, wrong escaping, one route of two fixed, a check after the write, deny-all, a filter fitted to the visible probes, edits to tests and runner configuration) next to legitimate repairs of the same applications. `npm run bench:repair:challenge:check` in `scanner/` fails if any of them is accepted or if any outcome moves from its reviewed baseline. It is synthetic regression evidence, not an accuracy figure.
