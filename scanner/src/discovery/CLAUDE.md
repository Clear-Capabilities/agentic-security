# scanner/src/discovery/

LLM-driven candidate discovery, gated by the deterministic engine.

`partition.js` splits the call graph into disjoint focus areas · `lenses.js`
holds the seven hunting lenses and the prompt builder · `hunter.js` runs one
bounded (area × lens) pass · `confirm.js` routes each candidate back through
the taint engine · `disprove.js` runs the three-angle majority-vote refutation
panel · `judge.js` shapes findings and dedupes against the prior scan ·
`llm-invoke.js` is the single injected LLM endpoint caller shared by
`hunter.js` and `disprove.js` (no other module may talk to an LLM directly) ·
`index.js` composes them.

## Rules

- **A hunter proposes; it never decides.** Nothing reaches a report without
  passing `confirm.js` and surviving `disprove.js`.
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
- **Coverage is reported.** Degraded runs and their reasons appear in every
  report. A half-failed pass must never read as a clean one.
