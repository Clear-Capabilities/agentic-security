# Implementation status: Eval Lab and Intelligent Model Router (PRD 6)

## Status summary (2026-10-18)

* **Percent complete:** 6 of 8 P0 requirements fully evidenced; 1 partial, 1 not done. Not done: requirement 2 (integrating the existing SARD evaluation: the SARD harness reads answer keys, which the lab's custody rules keep out of a scored run). Partial: requirement 5 (the end-to-end comparison has no separate `deterministic + hunt` arm; hunts are model arms behind the command adapter).
* **Current phase:** G (completion): built, documented, released; ongoing work is hardening.
* **Completed requirements:** Dataset manifest with mandatory leakage enforcement, hard negatives, real advisory pairs imported from the independent population (dev and validation only), neutralized and audited workspaces, deterministic and model arms (a local Ollama arm built in), mechanical scoring of detection, exploit and patch tasks, repeats with variance and provider variance, reports in five formats, intelligence per dollar, the policy router and `models route explain`.
* **Current work:** None in flight.
* **Remaining requirements:** SARD integration; a curated licensed corpus beyond the mined advisory population; a remote-model client (remote models go through the command adapter and the egress policy); a measured multi-model comparison on real models (the only real-code run so far is the deterministic baseline).
* **Failing tests:** None at the last run.
* **Blockers:** No model server or API access on the build host, so model arms are tested against stand-ins.
* **Last verified command:** `node --test test/eval-lab/*.test.js test/cli/eval-lab-cli.test.js` (scanner/): 63 pass, 0 fail.

---

**Percent complete:** requirements 1, 3 (the loader and the licence gate), 4, 5, 6, 7 and 8 are implemented and tested, and the
CLI surface and reports are done. Requirement 2 (integrate the existing SARD evaluation) is NOT done beyond reusing its neutralization
ideas and the custody audit. No curated real-vulnerability corpus ships. The only built-in model adapter is a local Ollama server (tested against a protocol stand-in, never a real model).

**Current phase:** G (completion): unit, integration, adversarial and end-to-end tests pass.

**Branch:** `feature/moat-prd6-eval-lab`.

## Requirement to evidence

| Requirement | Where | Evidence |
|---|---|---|
| 1. Common dataset manifest (id, version, language, source, split, license, cwe, expectedSpan, build, test, leakagePolicy) | `lab/dataset.js` | `test/eval-lab/dataset-neutralize.test.js` (18 refusals: leakage mode off, missing licence, no negatives, duplicate ids, paths that leave the folder, moving refs, ...) |
| 2. Integrate the existing SARD evaluation | not done | the `sard` source kind was removed from the manifest schema rather than left accepted-but-unloadable; see limits |
| 3. Real vulnerability corpus: vulnerable commit -> fixing commit | `lab/materialize.js` (`git archive` of a pinned commit through the hardened tar reader) | test builds a two-commit repository and materializes both revisions; a bad revision and a path escape are typed failures |
| 4. Hard negatives (sanitization, authorization, parameterization, bounds checks, correct crypto, safe wrappers) | manifest `kind: hard-negative` with a required `category`, `resemblesCwe` and `lookalikeSpan`; scored in `score.js` per category | dataset tests; run tests; the fixture set has two |
| 5. End-to-end benchmark: deterministic, deterministic + hunt, different models, local model, proof, remediation | `lab/run.js`, `lab/arms.js` | `test/cli/eval-lab-cli.test.js` compares a baseline, a local model and two external configurations across detect, falsify, exploit and patch |
| 6. Repeat probabilistic runs and report variance | `lab/stats.js`, `lab/report.js` | model arms repeat (3 by default), spread printed beside every mean, fewer than three runs is "not representative" |
| 7. Intelligent model router with four policies, tasks routed independently | `routing/policy-router.js` | `test/eval-lab/router.test.js` (10 tests), CLI test |
| 8. Explain routing | `models route explain <task>` | output matches the PRD's shape; captured in the guide |
| Benchmark integrity: labels unavailable to scanner, models, remediation agent; leakage audit recorded per run | `lab/neutralize.js`, custody audit, request guard | six kinds of leak each quarantine an entry; a spy test shows no request carries an id, kind, category, span or dataset name; `leakageAudit` is on every run |
| Reports: JSON, CSV, Markdown, HTML, chart data; commit, dataset hash, model id, config, machine profile, timestamp | `lab/report.js` | report tests; HTML escapes a hostile model id |
| Intelligence per dollar: confirmed vulnerabilities / $100, verified fixes / $100, recall at a fixed budget | `lab/report.js` | formulas asserted against measured spend in the exploit/patch test |

## Honest limits

* **The SARD corpus is not integrated.** The existing harness downloads its corpus from the network and keeps its own neutralizer;
  the lab does not call it. The lab's neutralizer is line-preserving and best effort (a regular-expression literal containing `//`
  can be mis-read) and the audit is a pattern audit.
* **The independent advisory population can be imported** (`scripts/eval-lab/import-independent.mjs`; dev and validation splits only,
  permitted licences only; first measured result: 1 of 12 real JavaScript advisories detected by the deterministic baseline, one run, not
  representative). It is mined, not hand-curated, and its spans come from fix diffs.
* **No curated corpus.** The loader supports commit pairs from a local repository and requires a permissive licence; assembling the
  corpus is data work. The shipped fixtures are small and synthetic, so no quality number in this repository describes any real model.
* **Only a local Ollama adapter is built in.** Other models attach through a command the operator supplies, which keeps the lab from
  becoming a second path around the guarded model call. The Ollama adapter (`arm-ollama.js`) is loopback-only, leak-guarded, and tested
  against a stand-in server. The consequence is that costs are whatever the arm reports (labelled `reported` or
  `computed-from-reported-tokens`); a wrapper that under-reports makes a model look cheaper.
* **The lab cannot see an arm's internal prompts.** The leakage guard covers workspace contents and every request the lab sends.
* **`threat-model` has no evaluation task**, so the router blocks it instead of recommending a model.
* **Remediation tests are optional.** A patch whose dataset has no test command is `exploitBlocked` but never "valid", and the
  report says test preservation is unmeasured for it.
* **Exploit and patch tasks need an execution environment.** Without one, reproducers are reported as not executed (not failed).
* **"Deterministic + hunt" as a distinct configuration** is not built: the baseline arm is the deterministic scanner, and a model arm
  stands in for a hunt; the repository's discovery pipeline is not an arm adapter.
* Not folded into `scanHealth`: a benchmark run is not a scan; its incompleteness is in the run record, the report and the exit code.

## Blockers

None.

## Last verified commands

* `cd scanner && node --test test/eval-lab/*.test.js test/cli/eval-lab-cli.test.js`
