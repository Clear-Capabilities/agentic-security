# Adversarial input and model boundaries (E6-07)

The scanner reads repositories it does not control, sends excerpts of them to models, and exposes tools to agents. Every one of those inputs can be written by an attacker. This document lists each boundary, the control that holds it, and the test that fails if the control is removed. Every test named here runs in `npm test`, which is the CI gate.

## The claim, and how it is measured

> Hostile repository text cannot cause an arbitrary shell command, network connection or file write.

`scanner/test/engineering-excellence/e6-07-adversarial-boundaries.test.js` measures it directly. It builds a repository in which every attacker-controlled surface tries to act (`fixtures/hostile-repo.mjs`), runs the real CLI on it in a child process under an observation preload (`fixtures/containment-preload.mjs`) that records every process start, network call, write and out-of-tree read, and then checks what the scan DID against what the text asked for. A negative-control test runs a program that does make a shell call, a connection and an outside write, and checks the observer sees all three, so a pass is not an observer that sees nothing.

| Attacker-controlled surface | What it tries | What is observed |
|---|---|---|
| File names `a;touch X.js`, `$(touch X).js`, `` `touch X`.js ``, `-rf.js`, quotes, spaces | run a command when the name reaches git or a shell | git runs with the name only after `--`, never through a shell; no sentinel file is created |
| `.git/config` (`core.fsmonitor`, `core.pager`, `core.sshCommand`, aliases for `blame` and `show`, a diff `textconv` driver) and `.git/hooks/*` | run a command when the scanner invokes git | every git call carries `-c core.fsmonitor= -c core.hooksPath=/dev/null` and `--no-textconv`; no sentinel |
| `package.json` scripts, `.npmrc` | run on "install" | the scanner never runs a package manager; no sentinel |
| `.claude/settings.json` hook command | be executed when read | read as data; no sentinel |
| Symlinks to `/etc/hosts`, `/etc`, and a loop | read outside the tree, or recurse | no read of `/etc`; scan terminates |
| Prompt-injection text in comments and strings | make the scanner or a model follow instructions | no process other than git, no network, no write outside state |
| 3 MB single line, 5000-deep JSON, invalid UTF-8 | exhaust or crash a parser | scan completes in bounded time |
| Unsigned custom rule pack with a catastrophic regex | run an attacker pattern | the pack is refused (`REFUSED rule pack ... unsigned`) and the scan finishes in seconds |
| The scan path itself containing shell syntax | be interpreted by a shell | handled as a path; no sentinel in the working directory |
| A model's reply containing instructions, a path to `/etc/passwd` and extra fields | be acted on | only the loopback model is contacted; nothing is executed; no write to the named path; invented fields are not copied onto the finding; no environment secret is in the request |

## Boundaries covered by existing tests

| Boundary | Control | Test |
|---|---|---|
| Writes by fix and agent tools | path confinement with a reserved-write list; traversal, absolute, symlink, case and encoding escapes refused | `confinement-adversarial.test.js` |
| Outbound model calls | deny-by-default egress policy evaluated before a prompt is built; offline mode refuses non-loopback hosts | `egress-policy*.test.js`, `egress-audit.test.js`, `ollama-offline-egress.test.js` |
| MCP tool poisoning and server swaps | tool description pinning, rug-pull detection | `mcp-rug-pull.test.js`, `mcp-audit.test.js`, `agent-mcp-tools.test.js` |
| Detectors fed hostile source | timeouts, isolation of a failing detector, comment-borne "ignore" text | `adversarial-robustness.test.js`, `detector-fault-injection.test.js` |
| Untrusted text in DCI prompts | comments blanked before control inference; commands stripped from model output; egress fail-closed | `e4-04`, `e4-05` tests in `test/engineering-excellence/` |

## What this does not establish

- The observation preload watches the Node APIs a scan uses (`child_process`, `net`, `dns`, `http`, `https`, `fetch`, `fs`). A native addon or a program started by one of those calls is outside it. The only program the scan starts is git; git itself is not instrumented.
- The hostile repository is a fixed set of vectors, not a fuzzer. It shows these vectors are held, not that none exists. New vectors are added to `hostile-repo.mjs` and its sentinel list together; a test fails if they diverge.
- The model-boundary test uses a fake loopback model and one hostile reply. It does not measure how a real model behaves under injection, only that nothing the scanner does depends on the model obeying.
- Run on macOS. The git hardening and write confinement are platform-neutral code; the process observation was not run on Linux or Windows.
- Parsers are bounded by size and time in the scan loop, but no coverage-guided fuzzing was run in this task.
