# Independent Haskell precision results

Date: 2026-10-26
Scanner version: 0.186.2
Labels digest: c2f17b33a43176a28799a6cd6b47f773d99c6ea273275c41a83bee1f926beb9b

MEASUREMENT ONLY. See README.md and USE-LOG.md.

## Overall

| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson | range if ambiguous all fp / all tp |
|---|---|---|---|---|---|---|---|---|---|
| all haskell projects | 84 | 1 | 42 | 11 | 30 | 43 | 2.3% | 0.4% to 12.1% | 1.8% to 22.2% |

## Per project

| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson | range if ambiguous all fp / all tp |
|---|---|---|---|---|---|---|---|---|---|
| hakyll | 8 | 0 | 8 | 0 | 0 | 8 | 0.0% | 0.0% to 32.4% | 0.0% to 0.0% |
| hledger | 46 | 1 | 27 | 1 | 17 | 28 | 3.6% | 0.6% to 17.7% | 3.5% to 6.9% |
| postgrest | 12 | 0 | 5 | 0 | 7 | 5 | 0.0% | 0.0% to 43.5% | 0.0% to 0.0% |
| shellcheck | 18 | 0 | 2 | 10 | 6 | 2 | 0.0% | 0.0% to 65.8% | 0.0% to 83.3% |

## Per source kind

| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson | range if ambiguous all fp / all tp |
|---|---|---|---|---|---|---|---|---|---|
| haskell source (.hs) | 66 | 1 | 40 | 1 | 24 | 41 | 2.4% | 0.4% to 12.6% | 2.4% to 4.8% |
| non-Haskell file in a Haskell project | 18 | 0 | 2 | 10 | 6 | 2 | 0.0% | 0.0% to 65.8% | 0.0% to 83.3% |

## Per vulnerability class (classes with at least one label)

| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson | range if ambiguous all fp / all tp |
|---|---|---|---|---|---|---|---|---|---|
| Data Exposure | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 0.0% |
| Dockerfile USER root (container runs with root privileges) | 7 | 0 | 0 | 6 | 1 | 0 | n/a | n/a | 0.0% to 100.0% |
| Dockerfile: USER root — container runs as root | 7 | 0 | 0 | 4 | 3 | 0 | n/a | n/a | 0.0% to 100.0% |
| Known-Broken Code Marker Near Security-Sensitive Logic | 8 | 0 | 8 | 0 | 0 | 8 | 0.0% | 0.0% to 32.4% | 0.0% to 0.0% |
| Missing Timeout on Outbound HTTP Request (DoS) | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 0.0% |
| OS Command Injection (shell string) | 3 | 1 | 0 | 0 | 2 | 1 | 100.0% | 20.6% to 100.0% | 100.0% to 100.0% |
| Open Redirect | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 0.0% |
| Partial function applied to caller-supplied text | 4 | 0 | 1 | 1 | 2 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 50.0% |
| Path Traversal (copy/rename) | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 0.0% |
| Path Traversal (filesystem operation) | 5 | 0 | 3 | 0 | 2 | 3 | 0.0% | 0.0% to 56.1% | 0.0% to 0.0% |
| Path Traversal | 9 | 0 | 4 | 0 | 5 | 4 | 0.0% | 0.0% to 49.0% | 0.0% to 0.0% |
| PostgreSQL Connection URI | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 0.0% |
| Server-Side Request Forgery | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% | 0.0% to 0.0% |
| Session cookie without HttpOnly or Secure | 2 | 0 | 2 | 0 | 0 | 2 | 0.0% | 0.0% to 65.8% | 0.0% to 0.0% |
| Unsafe boundary: unsafePerformIO | 13 | 0 | 12 | 0 | 1 | 12 | 0.0% | 0.0% to 24.3% | 0.0% to 0.0% |
| Whole input read into memory without a size limit | 6 | 0 | 6 | 0 | 0 | 6 | 0.0% | 0.0% to 39.0% | 0.0% to 0.0% |

## Reading these numbers

- precision = tp / (tp + fp). Ambiguous sites are excluded from the denominator and counted separately; the last column shows the range if they were all fp or all tp.
- Only 84 sites are flagged in total across 4 projects, so the labeled sample is most of the flagged population (a near census of flags, not a draw from a large population). Unlabeled sites are never counted.
- Recall cannot be measured here: there is no ground-truth list of the vulnerabilities in these projects, and a flag list says nothing about what was missed.
- Intervals treat the sample as simple random. Sites cluster by file and rule (for example ten sampled sites are one Dockerfile rule across sibling build images, and twelve are unsafePerformIO global-state idioms), so the true uncertainty is wider.
- Stale labels (labeled sites no longer flagged): 6.

## Limitations

- One LLM labeler reading source; not a human audit, no second labeler, so labeler disagreement is unmeasured.
- Projects and scan roots were chosen by the labeler, not drawn at random; four projects cover web service, CLI, library and CLI plus web UI.
- A "tp" requires the named weakness to be present and security-meaningful for someone other than the operator invoking the tool; a CLI user's own paths and arguments are not a privilege boundary. Another labeler could draw that line differently, which is why the ambiguous range is shown.
- Labels reflect each project at its pinned commit.
- Dependency and file-level findings (line 0) and test directories are out of scope. The flagged set includes non-Haskell files in the projects (Dockerfiles, one JavaScript file); they are reported as a separate source kind.
