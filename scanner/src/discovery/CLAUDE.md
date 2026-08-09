# scanner/src/discovery/

LLM-driven candidate discovery, gated by the deterministic engine.

User entry point: `agentic-security hunt --root <dir>` (`cmdHunt` in `bin/agentic-security.js`),
documented in `commands/scan.md`. Advisory only — it never gates a build and its
output does not enter `last-scan.json`.

`partition.js` splits the call graph into disjoint focus areas · `lenses.js`
holds the seven hunting lenses and the prompt builder · `hunter.js` runs one
bounded (area × lens) pass · `confirm.js` routes each candidate back through
the taint engine · `disprove.js` runs the three-angle majority-vote refutation
panel · `judge.js` shapes findings and dedupes against the prior scan ·
`llm-invoke.js` is the single injected LLM endpoint caller shared by
`hunter.js` and `disprove.js` (no other module may talk to an LLM directly) ·
`index.js` composes them.

## Rules

- **A hunter proposes; it never decides.** `confirm.js` sets a confirmation
  tier and never filters — an `unconfirmed` candidate still proceeds, because
  the taint engine models only a subset of the program and the absence of
  corroboration must never be laundered into a false-positive verdict.
  `disprove.js` is the only stage that removes a candidate: nothing reaches a
  report without surviving refutation there.
- **Every LLM call is an injected `llmInvoke`.** No module may import an SDK or
  hard-code an endpoint. Absence of an LLM degrades to an empty, well-formed
  result — it never throws and never blocks a scan.
- **Silence never refutes.** A probe that says nothing lowers a candidate to
  `unconfirmed`; only an argued majority refutes. A voter that errors is
  excluded from the denominator, not counted as agreement.
- **Severity comes from evidence, not from the model.** The confirmation tier
  sets it: taint-confirmed → high, sink-adjacent → medium, unconfirmed → low.
  This layer never emits `critical`.
- **Ids are content digests.** No clock, no randomness, anywhere in an id, a
  digest, or a sort key.
- **Bounded by default.** The pipeline is multiplicative — areas × lenses
  hunter calls, then three refutation votes per surviving candidate. Six
  files produced 168 LLM calls before C3. `makeBudget` in `index.js` wraps
  `llmInvoke` so every call is counted against a ceiling, and `maxCandidates`
  caps what reaches the panel. Never remove a bound without replacing it:
  an unbounded run's cost is a function of repository size.
- **An exhausted budget means INCOMPLETE, not clean.** Exhaustion arrives
  through the same degradation path as a dead endpoint and lands in
  `coverage.reasons`. A capped candidate is neither a finding nor cleared —
  it was not examined, and the report says so.
- **Coverage is reported.** Degraded runs and their reasons appear in every
  report. A half-failed pass must never read as a clean one.
