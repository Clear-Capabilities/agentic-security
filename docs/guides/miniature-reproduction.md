# Miniature public reproduction

An offline run that anyone with a checkout can repeat in about a minute. It needs no network, no sealed labels and no credentials.

```
cd scanner
npm run reproduce:mini
```

(Equivalent: `node scripts/public-reproduction.mjs` from the repository root; add `--json` for machine-readable output.)

## What it does

It exercises the real measuring path end to end over a few small, public, synthetic projects in
`scanner/test/fixtures/evaluation-synthetic/`: freeze a protocol, stage each project through the leakage audit, run the engine in
a child process, score end to end, build the accuracy report with its intervals, account costs, and judge the real-code gates.

Then it runs negative controls, each of which must behave as expected for the measuring path to be trusted:

| Control | What must happen |
| --- | --- |
| `null-engine` | an engine that reports nothing scores recall 0, and the real engine scores higher |
| `flag-everything` | an engine that reports every line raises more false positives on the patched trees than the real engine |
| `shuffled-labels` | the real engine's findings scored against labels moved to the wrong lines score recall 0 |
| `planted-leak` | a workspace carrying an answer-key file is quarantined, counted as a miss, and fails the leak gate |
| `gates-need-data` | the real-code gates read `insufficient-population` however good the figures look |

Exit 0 means every control behaved. Exit 1 names the control that did not, which would mean the measuring path cannot be trusted.
To see the script can fail, break one control on purpose: `node scripts/public-reproduction.mjs --fault null-engine` (also
`flag-everything`, `shuffled-labels`, `planted-leak`) must exit 1 and name that control.

## What it is not

The projects are three authored files and the labels were written by the tooling's developers, so every number it prints is
labelled synthetic. It measures nothing about the engine's accuracy on real code, and it contains no sealed labels because none
exist in this repository. No result from it may be quoted as an accuracy figure.

## Related commands

- `npm run evaluation:synthetic` runs the three-layer ablation on the same projects.
- `node scripts/evaluation.mjs verify-protocol <file>` checks a protocol against its hash.
- `node scripts/dev-recovery.mjs` runs the development case suite against any engine checkout (see `docs/guides/engine-mechanism-evidence.md`).
- `node scripts/evaluation.mjs bakeoff-validate <manifest>` checks a bake-off recipe (see `docs/guides/bakeoff-recipe.md`).
