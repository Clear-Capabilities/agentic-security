# Implementation status: Vulnerability-to-Detection-and-Response Loop (PRD 7)

## Status summary (2026-10-18)

* **Percent complete:** All 8 P0 requirements are implemented with executable evidence (8 of 8), plus the P1 text renderers for Splunk SPL, Microsoft Sentinel KQL, CloudWatch Logs Insights, Elastic, Google SecOps (YARA-L) and Datadog. The last three translate exactly or decline and were never run against the live products.
* **Current phase:** G (completion): built, documented, released; ongoing work is hardening.
* **Completed requirements:** Detection IR, grounded outputs (Sigma, generic HTTP, detect-only WAF, structured log query, YARA, six SIEM renderers), evidence grounding, historical hunting with four honest verdicts, the exposure window, detection validation with synthetic telemetry, remediation closure, the unified Find-Prove-Hunt-Fix-Verify-Detect view, redaction, and the ten-step end-to-end test.
* **Current work:** None in flight.
* **Remaining requirements:** Remote, opt-in, read-only SIEM integrations (every renderer is text only); an MCP tool; telemetry captured from real traffic (the synthetic telemetry is built from the proof's own facts).
* **Failing tests:** None at the last run.
* **Blockers:** No SIEM product or captured production telemetry on the build host.
* **Last verified command:** `node --test test/dnr/*.test.js test/cli/dnr-cli.test.js` (scanner/): 52 pass, 0 fail.

---

**Percent complete:** all eight P0 requirements and the required end-to-end scenario are implemented and tested. The P1 SIEM
adapters are partly done (Splunk SPL, Microsoft Sentinel KQL and CloudWatch Logs Insights as text renderers; Elastic, Google
SecOps YARA-L and Datadog are built as text renderers that translate exactly or decline, never run against a live product), and no remote integration exists. No MCP tool.

**Current phase:** G (completion): unit, integration, adversarial and end-to-end tests pass; full `npm test` and the release
gates are run by the ship flow, not by this document.

**Branch:** `feature/moat-prd7-dnr`.

## Requirement to evidence

| Requirement | Where | Evidence |
|---|---|---|
| 1. Detection IR (finding id, CWE/family, behavior, endpoint, payload class, operation, process/network/DB effect, confidence, evidence refs) | `dnr/detection-ir.js`, `dnr/attack-facts.js`, `dnr/payload-classes.js` | `test/dnr/ir-and-outputs.test.js` |
| 2. Outputs: Sigma, generic HTTP, WAF suggestion, structured log query, YARA where appropriate | `dnr/outputs.js` | same file; YARA declines request-shaped classes with a stated reason |
| 3. Evidence grounding (no invented IP, domain, hash, user agent) | closed-world IR and attack facts; `facts` records each field's source | "closed-world" and "nothing is invented" tests; hostile attack facts refused at the reproducer boundary |
| 4. Historical hunting, four verdicts, `NOT_OBSERVED` is not `NOT_EXPLOITED` | `dnr/hunt.js`, `dnr/log-reader.js`, `dnr/matchers.js` | `test/dnr/logs-and-hunt.test.js`, `test/cli/dnr-cli.test.js` (distinct exit codes) |
| 5. Exposure window from provenance, deployment history, fix commit and telemetry window | `dnr/exposure-window.js` | `test/dnr/window-store-view.test.js` (real git repository, the PRD's example dates) |
| 6. Detection validation (positive fires, lookalike does not) | `dnr/validate.js` | all eight classes at every parameter location; a rule that fires on everything is caught |
| 7. Remediation closure (detection kept, finding and proof link to it) | `dnr/store.js`, `dnr/view.js`, `proof show` | end-to-end test: the rule still detects after the fix |
| 8. Unified finding view | `dnr status` | end-to-end test |
| Privacy (local by default, redaction) | `dnr/redact.js`; a test pins that no module imports a network or model layer | `logs-and-hunt.test.js` |
| Required E2E (10 steps) | `test/cli/dnr-cli.test.js` | Find, Prove, Hunt, Fix, Verify, Detect through the real spawned CLI, stdin closed |

## Honest limits

* **Synthetic telemetry is not captured traffic.** Validation builds events from the proof's own facts (endpoint, parameter,
  class) and the class's exemplar payloads. It does not run the exploit in the proof lab and record what the application logged.
  It shows the rule matches the shape the proof established and ignores lookalikes; it does not show what a real application logs.
* **Payload classes are generic shapes.** Eight classes. A finding of another class gets no detection rather than a guess.
* **Artifact history is a plain file.** The exposure window reads a deployment-history JSON file. It is not yet joined to the
  source-to-artifact provenance graph (PRD 5), so "artifact history" means what the operator supplies.
* **Not folded into `scanHealth`.** A hunt is not a scan, and its degraded states (inconclusive, unavailable) are reported in the
  hunt result and the finding view and carry their own exit codes. They do not feed the scan's assurance rollup.
* **Not built:** every remote, read-only SIEM integration; an MCP tool;
  hunting compressed logs (reported as skipped, which makes the verdict INCONCLUSIVE).
* **Finding ids.** Records are keyed by the id you pass. Use the stable id consistently; `fix --require-proof` records under the
  finding's stable id.

## Also fixed along the way

* `triage exploit --prove` never passed a source root, so a reproducer that imports repository sources (`sources`) could not be
  proven from the CLI; every attempt was incomplete. It now passes the project root. Found by the end-to-end test.

## Blockers

None.

## Last verified commands

* `cd scanner && node --test test/dnr/*.test.js test/cli/dnr-cli.test.js`
