# Local AI with Ollama

Run `agentic-security`'s AI-assisted stages — validation, adversarial
verification, explanation, patch synthesis, PoC synthesis, and `hunt` — against
a model running entirely on your own machine, so source code, findings, and
generated patches never leave it for those stages. The deterministic scanner
(SAST, SCA, secrets, IaC) never needed an LLM and still doesn't; Ollama makes
the *optional* reasoning layer local too.

## 1. Why local models

- Source code, credentials, or regulated data cannot leave the workstation.
- Development happens in a disconnected or restricted network.
- Cloud-model approval is slow, expensive, or simply not available.
- You want predictable inference with no token/API cost.

## 2. Install Ollama

Follow [ollama.com](https://ollama.com) for your platform, then confirm it's
running:

```bash
ollama --version
```

Ollama listens on `http://127.0.0.1:11434` by default — that's also
`agentic-security`'s default, so no extra configuration is needed to stay
loopback-only.

## 3. Pull a model

Pick a profile based on your machine's RAM. Pulling requires network access —
do it before you need to work offline.

**8 GB RAM — the required, tested baseline:**

```bash
ollama pull qwen3.5:4b
```

If memory is genuinely tight (`qwen3.5:4b` doesn't admit with safe headroom),
`agentic-security` will recommend the smaller fallback:

```bash
ollama pull qwen3.5:2b
```

**16 GB RAM — recommended Qwen 3.5 profile:**

```bash
ollama pull qwen3.5:9b
```

**16 GB+ RAM — Gemma 4:**

```bash
ollama pull gemma4:e2b
```

A 16 GB machine with more headroom may also use `gemma4:12b`. Gemma 4 is **not**
the 8 GB default — even its smallest current artifact leaves too little memory
for the OS, the Ollama runtime, and the scanner itself on an 8 GB machine.

Other supported families (installed and used the same way): `qwen3`,
`qwen3-coder`, `qwen3-coder-next`, `qwen2.5-coder`, `gemma3`, `functiongemma`.
Family names are read from what Ollama reports installed — nothing here is a
hardcoded allowlist, so a newer model in these families works without an
update to `agentic-security`.

## 4. Configure `agentic-security`

```bash
export AGENTIC_SECURITY_LLM_PRESET=ollama
export AGENTIC_SECURITY_LLM_MODEL=qwen3.5:4b
```

That's the whole minimum. Or let the setup command discover and confirm this
for you — it reaches your Ollama server, lists installed models, and either
uses the one you name or picks a sane default for your detected RAM tier
(never prompts interactively; this CLI is flag-driven throughout):

```bash
agentic-security setup --llm ollama                     # auto-picks a default model
agentic-security setup --llm ollama --model qwen3-coder:30b   # or name one explicitly
```

It prints the exact `export` lines above rather than writing them anywhere —
put them in your shell profile or CI env yourself.

Everything below is optional tuning.

```bash
# Base URL — must be loopback unless you explicitly opt into a remote server
export AGENTIC_SECURITY_OLLAMA_HOST=http://127.0.0.1:11434

# Generation timeout (default 300000ms — generous, because a cold local
# model load can legitimately take minutes; a dead port still fails in ~3s)
export AGENTIC_SECURITY_LLM_TIMEOUT_MS=180000

# How long Ollama keeps the model resident after a call (default 5m; 0 to
# unload immediately, useful on memory-constrained machines)
export AGENTIC_SECURITY_OLLAMA_KEEP_ALIVE=5m

# Per-role overrides — same mechanism every other provider already uses
export AGENTIC_SECURITY_LLM_MODEL_VALIDATE=qwen3.5:4b
export AGENTIC_SECURITY_LLM_MODEL_FIX=qwen3-coder:30b
```

## 5. Verify with `models doctor`

```bash
agentic-security models doctor
```

```text
agentic-security local AI doctor

✓ Ollama server reachable
✓ Endpoint is loopback-only
✓ 2 model(s) installed

System RAM: 8.0 GB (free: 5.2 GB)
Memory tier: 8gb
Default model: qwen3.5:4b
  ✓ memory admission passed — context 4096 tokens
  chat=yes structuredJson=true tools=true (Ollama metadata)
  ↗ run with --probe to runtime-verify structured output / tool calling (consumes inference time)

Cloud fallback: disabled
Deterministic scanner: enabled
```

When `AGENTIC_SECURITY_LLM_PRESET=ollama` is configured, a real `agentic-security
scan` prints its own per-run summary — provider, model, egress, and how many
validate calls succeeded/were refused/failed:

```text
  AI Assistance
    Provider: ollama   Model: qwen3.5:4b
    LLM egress: loopback-only   Cloud fallback: disabled
    validate   14 calls   success 12   failed 2
    LLM inference was loopback-only.
```

It never says "this entire scan was fully offline" — OSV/KEV/EPSS lookups
are a separate, deterministic network path this line does not describe.

Other read-only subcommands:

```bash
agentic-security models list              # installed models, family + size
agentic-security models inspect qwen3.5:4b
agentic-security models status --json     # machine-readable, for CI/scripts
```

None of these make a chat call by default — `chat`/`structuredJson`/`tools`
above come from Ollama's own `/api/show` metadata when it reports a
`capabilities` array (Layer A), falling back to the non-authoritative family
hint (Layer B) on older Ollama versions that don't. Pass `--probe` to add a
real, inference-consuming runtime check (Layer C: a tiny structured-output
request and a one-tool-call request) — the result is cached on disk, keyed by
Ollama version + model digest + model name, so a repeat `--probe` run is
free until the model is re-pulled or Ollama is upgraded. None of the three
layers ever downloads a model.

## 6. Role-based model selection

The same per-role environment variables every provider already respects work
for Ollama:

| Role | Env var | Notes |
|---|---|---|
| `validate` | `AGENTIC_SECURITY_LLM_MODEL_VALIDATE` | FP-suppression checks; runs per finding |
| `verify` | `AGENTIC_SECURITY_LLM_MODEL_VERIFY` | adversarial re-check |
| `explain` | `AGENTIC_SECURITY_LLM_MODEL_EXPLAIN` | human-facing narrative |
| `fix` | `AGENTIC_SECURITY_LLM_MODEL_FIX` | patch synthesis — prefer a coder model when memory allows |
| `poc` | `AGENTIC_SECURITY_LLM_MODEL_POC` | proof-of-concept synthesis |
| `logic` | `AGENTIC_SECURITY_LLM_MODEL_LOGIC` | cross-file business-logic reasoning |

On an 8 GB machine, prefer routing everything through one small resident model
(`qwen3.5:4b`) rather than pinning different roles to different models — Ollama
can only keep one large model loaded comfortably at that memory tier, and
swapping models between roles costs a reload each time.

> **Current implementation status.** All six roles now have a real call site:
> `validate` (FP-suppression), `hunt` (candidate discovery, `runHunter`),
> `verify` (adversarial re-check, `disproveCandidate`), `fix`
> (`agentic-security fix`, falls back to an Ollama-proposed patch — still
> re-scanned/linted/tested through the same gate a deterministic patch goes
> through), `explain` (`agentic-security triage --explain <id>`, a read-only
> narrative kept visually separate from deterministic evidence), and `poc`
> (`agentic-security triage --poc <id>`, a narrative-only, unexecuted exploit
> sketch — not a replacement for the `security-poc-generator` agent's
> data-flow-traced regression test, which remains the deeper option when
> Claude Code is available). `logic` is wired through `hunt`'s
> business-logic lens; it has no separate standalone CLI entry point.

## 6a. Tool-calling agent loop (`ask`)

```bash
agentic-security ask "What does this project do with passwords?" .
```

For free-form questions that don't map to a single finding (`triage
--explain`/`--poc`) or a structured discovery run (`hunt`), `ask` gives the
model bounded, READ-ONLY tool access to the scanned project: `read_file`,
`list_files`, `search_code`, `read_finding`. It cannot write files, run
commands, or make network calls — there is no write- or execute-capable tool
registered at all. Every tool call passes an eight-point safety gate (name
allowlist, JSON-schema argument validation, path normalization, repo-root
confinement with symlink rejection, a destructive-action policy trivially
satisfied by having no destructive tool, a per-call timeout, an output-size
cap, and prompt-injection framing — every tool result is wrapped as
untrusted data before it re-enters the model's context, the same isolation
`fix`/`explain`/`poc` already use for file content).

The loop terminates on the first of: the model stops requesting tools, 12
tool-call iterations (hard ceiling, not configurable upward), a five-minute
wall-clock budget, or the model requesting a tool it was never offered
(treated as a policy violation, not a retryable error). It refuses outright,
before any request, if the resolved model's capability (Layer A/B/C) reports
`tools: false` — check with:

```bash
agentic-security models test qwen3.5:4b
```

`models test` runs BOTH Layer C probes (a structured-output request, a
one-tool-call request) unconditionally and caches the result — unlike
`models doctor`/`models inspect`, where `--probe` is opt-in — since the
whole point of `test` is to spend the inference time once and get a
definitive answer.

The cache is keyed by Ollama version + model digest + model name, and also
carries a 30-day safety-net expiry — but neither is a substitute for a real
re-check if you suspect a cached answer is wrong (a same-tag `ollama pull`
doesn't always change the digest an older Ollama version reports, and a
single-trial probe can occasionally land on an unlucky answer). Force a
fresh probe with:

```bash
agentic-security models test qwen3.5:4b --force
```

`models doctor --probe --force` and `models inspect <model> --probe --force`
support the same flag.

## 7. Hardware and context guidance

`agentic-security` detects total/available RAM (`os.totalmem()`/`os.freemem()`)
and picks a conservative starting context, growing it only after a memory
admission check — the model's advertised maximum context (e.g. `qwen3.5:4b`'s
256K) is a ceiling, never a safe default allocation.

| Profile | Model | Initial context | Concurrency |
|---|---|---|---|
| 8 GB | `qwen3.5:4b` (fallback `qwen3.5:2b`) | 4K, target 8K after admission | 1 |
| 16 GB (Qwen) | `qwen3.5:9b` | 16K, target 32K+ after admission | 1 |
| 16 GB (Gemma) | `gemma4:e2b` (or `gemma4:12b`) | 8K, target 16K after admission | 1 |

Concurrency defaults to **1**: running more than one generation at once on
shared/unified memory tends to cause model-reload thrashing rather than real
throughput gains. Raise `AGENTIC_SECURITY_OLLAMA_MAX_CONCURRENCY` deliberately,
not by default.

Timeouts are split so a dead Ollama port fails in ~3 seconds while a
cold-loading model still gets its full generation budget — see
`AGENTIC_SECURITY_OLLAMA_CONNECT_TIMEOUT_MS` / `AGENTIC_SECURITY_LLM_TIMEOUT_MS`.

## 8. Offline behavior — read this carefully

**"Offline" here means one specific thing:** LLM inference requests are
constrained to this machine's loopback interface. It does **not** mean the
whole scanner makes zero network requests (OSV/KEV data, dependency-currency
checks, etc. are separate, unrelated network paths this feature doesn't touch).
A future, separate full-airgap mode would cover that; don't conflate the two.

By default, `PRESET=ollama` refuses any non-loopback host **before** building
a prompt or making a network call:

```text
✗ Ollama offline mode refused http://192.168.1.50:11434.

Offline LLM mode guarantees model prompts remain on this machine.
A LAN or remote Ollama server is a remote endpoint for that guarantee.

Use --allow-remote-ollama (or AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE=1) to opt into
remote inference, or use http://127.0.0.1:11434 for local inference.
```

A self-hosted remote Ollama server is a legitimate thing to want, but it must
be an explicit opt-in — `AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE=1` — and every
report from that configuration says `egress: remote`, never "loopback-only".

## 9. No-cloud-fallback guarantee

If Ollama is unreachable, the model is missing, the request times out, or the
response is malformed, the outcome is always one of:

- the deterministic finding stays exactly as detected, with the AI stage
  marked `unavailable`/`malformed`/`disabled` (never silently dropped),
- an explicit error, or
- another **explicitly configured** local model.

It is never a silent fallback to Anthropic, OpenAI, or Gemini. This is
enforced in code (`discovery/llm-invoke.js`, `llm-validator/index.js` both
route Ollama failures back to their existing degrade paths, never to a
different provider) and covered by an automated test
(`test/ollama-offline-egress.test.js`) that patches `fetch` and asserts zero
network calls occur for a refused endpoint.

## 10. `ollama` vs. legacy `local` vs. BYO

| Preset | Wire shape | Loopback enforced? | Use when |
|---|---|---|---|
| `ollama` | native `/api/chat` (`messages`, `format`, `tools`) | yes, by default | you're running Ollama |
| `local` | legacy generic `{prompt, model}` | yes, always, no opt-out | an existing local server built against the older shape |
| BYO endpoint | same legacy generic shape | no | any other self-hosted or third-party endpoint |

`local` is unchanged by this feature and keeps its existing wire contract
forever — an Ollama server happens to also understand OpenAI-compatible
`/v1/chat/completions`, but `local` was never sending that shape, so switching
to `ollama` is what actually gets you the richer native protocol (structured
output, tool calls, real token/timing metrics).

## 11. Troubleshooting

**"Ollama server is not reachable"** — `ollama` isn't running, or is listening
on a different port. Start it, or pass `--host`.

**"Ollama offline mode refused ..."** — you pointed `AGENTIC_SECURITY_OLLAMA_HOST`
at something that isn't a literal loopback address. See §8.

**A finding stays `unvalidated` with `reason: ollama-model-not-installed`** —
pull the model while you have network access; strict offline mode never runs
`ollama pull` for you (`models pull` is refused outright when offline mode is
active — see the PRD's §24 for why: a silent download is not "offline").

**Out of memory / model won't load** — `models doctor` reports whether the
requested model/context combination passed the memory admission check. If it
didn't, use the recommended smaller model or context, or free memory.

**Everything seems to work but nothing feels "smarter"** — check
`models inspect <model> --probe` for whether `structuredJson`/`tools` are
actually detected for that model at runtime; without `--probe` you're only
seeing Ollama's own `/api/show` metadata or (failing that) a non-authoritative
family-hint default, and an unusual model tag may report `unknown` rather
than a confirmed yes/no either way.

**I need to stop `agentic-security` from calling Ollama at all, right now** —
set `AGENTIC_SECURITY_OLLAMA_DISABLED=1`. This is the one setting that
overrides everything else, including a per-role
`AGENTIC_SECURITY_LLM_PRESET_<ROLE>=ollama` override (`fix`/`explain`/`poc`/
`verify`/`validate`/`logic` each support one independently of the global
`AGENTIC_SECURITY_LLM_PRESET`) — unsetting only the global preset during an
incident does NOT stop a role that has its own override configured, which is
exactly the gap this flag exists to close. Unset it to re-enable.

## 12. Security/trust model

**Models propose. Deterministic controls decide.** A local model:

- can suggest a finding is a false positive — the harness still checks the
  actual evidence (`validateResponse`'s challenge/nonce cross-check, which
  applies identically whether the model is Ollama or a cloud vendor);
- can synthesize a patch — it never writes directly to disk; the existing
  rescan/lint/test verification pipeline still gates every patch, local or not;
- never directly sets final severity, exploitability, or compliance status.

Prompt-injection defenses (untrusted-content boundaries, the same redaction
pipeline every provider goes through) apply identically to local models — a
model running on your own machine is still an untrusted output source, just a
private one.

**Supply-chain trust boundary — read this before pulling a model from an
unfamiliar source.** This project verifies its OWN npm dependencies with
Sigstore-backed provenance (`src/sca/sigstore-verify.js`) — no equivalent
exists, or can currently be added, for the Ollama binary or the model
weights `ollama pull` downloads. Ollama's model registry does not publish
Sigstore or comparable provenance attestations for models today, so this
project has nothing to verify against even in principle. Concretely, this
means:

- `agentic-security` trusts whatever `ollama` binary is on `PATH` and
  whatever model weights are already pulled — it never inspects, hashes, or
  attests either.
- A compromised `ollama` binary, or a maliciously-crafted model pulled from
  a non-official registry/mirror, is outside every guarantee described in
  this guide. The offline/loopback guarantees above are about NETWORK
  egress from THIS tool once a model is running — they say nothing about
  whether that model or the runtime executing it can be trusted in the
  first place.
- Practical mitigation, until upstream provenance exists: pull models only
  from Ollama's own official library (`ollama pull <name>`, no custom
  registry flags) and keep the `ollama` binary updated through your
  platform's normal package manager, the same way you'd trust any other
  locally-installed interpreter or runtime.

## 13. Model-quality benchmark

A dedicated `agentic-security models benchmark <model>` command (scoring
finding-classification accuracy, patch-verifier pass rate, schema reliability,
and similar task-specific dimensions against this project's own corpus) is
planned but not implemented in this release — see the PRD's Phase 3 scope.
Until then, treat model choice as a tuning decision informed by the profiles
above, not a benchmarked ranking.

This is a different thing from **live contract testing**, which IS
implemented: `AGENTIC_SECURITY_OLLAMA_E2E=1 npm run test:ollama-e2e`
(scanner/test/ollama-e2e.test.js) runs against whatever Qwen/Gemma model you
have installed and checks that the WIRE CONTRACT holds against a real
server — valid structured output, a real tool-call round trip, prompt-
injection resistance, graceful context-overflow handling — never whether the
model's answers are any GOOD (that's the benchmark suite above, not yet
built). Every other test in this codebase exercises the same logic against
a fake in-process server standing in for Ollama, which is fast and hermetic
but cannot catch a real model doing something a scripted reply never would.
This tier is opt-in and slow by design (a cold local model can legitimately
take minutes per call) — it is never run as part of normal CI.
