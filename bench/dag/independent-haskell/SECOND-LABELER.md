# A second labeler, without touching the sealed record

`labels.json` has eight fields per label and one verdict, from one LLM labeler, and its `labelsDigest` is computed over exactly those eight fields.
That cannot say how far the verdicts depend on the labeler, and it folds "the labeler was unsure" and "two readers would disagree" into one
`ambiguous`. This adds a second, blind labeler of a different model, and a recorded third pass for what they do not agree on, **beside** the single
record. `labels.json` and its digest are not modified by anything below; `scanner/test/bench-independent-haskell-panel.test.js` pins the digest of a
fixed label list against an independent re-implementation of the canonical form, so extending the schema cannot invalidate the sealed set.

This capability has been exercised on a synthetic fixture only. No second labeler has labelled the sealed set, and nothing here has been run against it.

## The panel record: `labels-panel.json` (panelVersion 2)

    { panelVersion: 2, baseLabelsDigest, panelDigest,
      labelers: [{ labelerId, model, blind: true }, ...],        the labeler behind labels.json is the first
      adjudicator: { labelerId, model } | null,
      sites: [{ id, project, language, file, line, vuln,
                votes: [{ labelerId, verdict: tp | fp | unsure, evidence }],
                status: agreed | disagreed | one-unsure | all-unsure,
                adjudication: { verdict: tp | fp | ambiguous, evidence } | null,
                final: tp | fp | ambiguous }] }

- `status` is derived from the votes. **disagreed** (two labelers decided differently) and **one-unsure** / **all-unsure** (a labeler declined to
  decide) are different findings about a label; the single record's `ambiguous` cannot tell them apart, so its `ambiguous` becomes `unsure` in the
  panel.
- `final` is the shared verdict when the labelers agreed; otherwise the adjudication, else `ambiguous`. An adjudication on an agreed site is refused.
- Rules, borrowed from `scanner/src/posture/evaluation/labels.js` (not its schema): labelers have distinct ids and **distinct models**, each is
  declared blind, every labeler votes once on every site with evidence, and the adjudicator is none of the labelers and uses none of their models.
  `validatePanel` enforces them and re-derives `status`, `final` and `panelDigest`. A declaration of blindness is a claim; nothing here can verify it.

## Agreement: `agreement.json`, `agreement.md`

For every pair of labelers: percent agreement and Cohen's kappa over `tp / fp / unsure`, kappa again over the sites both decided, the confusion
matrix, and the four-way status counts. Kappa is `null` (with the reason) when every verdict of both labelers is in one category, and is unstable when
one category dominates; the percent and the matrix are reported beside it (`bench/_lib/agreement.mjs`).

## Using it

1. Each additional labeler writes `draft-haskell-<labelerId>.txt` (lines `index|tp|fp|unsure|evidence`, indexed into `sample-haskell.json`), blind to the
   other verdicts.
2. The adjudicator writes `adjudication-haskell.txt` (lines `index|tp|fp|ambiguous|evidence`) for the sites that were not agreed.
3. `labelers.json` names them: `{ "base": {"labelerId", "model"}, "labelers": [{"labelerId", "model", "blind": true}], "adjudicator": {...} | null }`.
4. `node build-labels.mjs --panel` writes `labels-panel.json`, `agreement.json` and `agreement.md`, and refuses (writing nothing) when the base record
   does not match its digest or the panel is not independent.
5. `run.mjs --check`, when `labels-panel.json` exists, validates it against the labels and adds the agreement and the precision under the adjudicated
   verdicts to `results.json` and `results.md`, beside the unchanged single-labeler figures. With no panel file the output is what it always was.

Reading the sealed labels to do step 4 is a use of the sealed set and belongs in `USE-LOG.md`.
