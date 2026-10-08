# Nix and NixOS

Scanning Nix works with no `nix` binary, no network and no NixOS host: the scanner parses the `.nix` source itself and
never evaluates, builds, fetches or runs anything unless you opt in to the isolated evaluation described below. This
guide separates five different things people mean by "Nix security", because a finding means something different at each:

| Scope | What it is | Where it comes from | Can the scanner claim it? |
|---|---|---|---|
| **static** | the text of a `.nix` file as written | the parser | yes, always |
| **declared** | what the files say a project depends on or sets | `flake.nix`, `flake.lock`, `fetch*` calls, module options | yes |
| **effective** | the value a NixOS option really takes after module priorities, `mkMerge`, `mkIf` and imports are applied | the module resolver, over literal local imports only | yes, with stated conditions; `conditional` or `unknown` when it cannot decide |
| **evaluated** | what `nix eval` returns for a target | an opt-in, sandboxed evaluation | only when you select it and a sandbox proves its isolation |
| **runtime** | what a running host actually does: services up, ports reachable, files on disk | a NixOS host | **no**: reachability is always `unknown`, and the scanner makes no runtime claim |

Scanning a NixOS configuration (a Nix source file) is therefore a different thing from running the scanner **on** a NixOS
host; the second is covered in [Installing on NixOS](nixos-install.md), and its host-level verification is separate from every
claim here.

**Prerequisites:** Node.js >= 24.

---

## Scan a flake or a configuration

```bash
npx @clear-capabilities/agentic-security-scanner scan .
```

Found by file type: every `.nix` source and `flake.lock`. Both flakes and legacy layouts (`default.nix`, `shell.nix`,
`configuration.nix`) are read. Paths the walk never enters: `result`, `.direnv/`, `nix/store/` and the other build outputs;
a `nix-export.json` is read by exact path only (see the closure section). All the usual scan modes, report formats,
baselines and the `# agentic-security-ignore: <rule>` pragma (`#` and `/* */` forms, line-scoped, rule-id exact) work
unchanged, and the exit code is the usual `0 / 1 / 2 / 3 / 4`.

To try it, scan the shipped examples:

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/nixos-host/vulnerable
```

### A NixOS host with several problems

<!-- generated:ex-nix-vuln:start -->
Captured from the built bundle on `examples/nixos-host/vulnerable`: exit code **2**, scan health **partial**.

| Severity | Family | CWE | Location |
| --- | --- | --- | --- |
| medium | `vulnerable-dep` | CWE-494 | configuration.nix:0 |
| high | `firewall-exposure` | CWE-284 | configuration.nix:4 |
| high | `ssh-access` | CWE-250 | configuration.nix:8 |
| medium | `ssh-access` | CWE-307 | configuration.nix:9 |
| high | `hardcoded-secret` | CWE-798 | configuration.nix:14 |
| high | `firewall-exposure` | CWE-668 | configuration.nix:19 |
| high | `firewall-exposure` | CWE-306 | configuration.nix:20 |
| low | `service-identity` | CWE-250 | configuration.nix:26 |
| high | `secret-in-store` | CWE-312 | configuration.nix:29 |
| high | `secret-in-store` | CWE-312 | configuration.nix:31 |
| medium | `vulnerable-dep` | CWE-829 | flake.nix:0 |

Scan-health conditions:
- 1 Nix build-trust finding(s) rest on an unresolved branch or partial module graph
<!-- generated:ex-nix-vuln:end -->

Every one of those is a statement about the **effective** configuration, not a text match: a `PermitRootLogin = "yes"` that
a later `lib.mkForce "no"` overrides produces no finding, and a value the resolver cannot decide is capped at `medium`
and labelled conditional. The same host with the problems fixed:

<!-- generated:ex-nix-fixed:start -->
Captured from the built bundle on `examples/nixos-host/fixed`: exit code **0**, scan health **complete**.

_No findings._

Disclosed limits: `license-data-unavailable`.
<!-- generated:ex-nix-fixed:end -->

It is `complete`: both files parsed, the flake input is locked, and there is nothing partial to disclose.

## How the effective configuration is decided

The resolver starts from an entry (`configuration.nix`, or each NixOS module nothing imports) and follows **literal local
imports only**. Each option is decided by module-system priority (`mkForce` 50, a plain assignment 100, `mkDefault` 1000,
`mkOverride N`), `mkMerge` and `mkIf` conditions it can judge (booleans, `!`, `&&`, `||`, `==`, `config.<option>`,
`pkgs.stdenv.isLinux` from the target system). Then:

- a list or attribute set is evaluated only when **every element is statically known** (`[ { from = 1; to = 65535; } ]` is; a
  list holding a `config.<option>` reference, an interpolated string or a `rec` set is not, and stays `unknown` as a whole);
  **any unknown part makes the whole value unknown**, nothing is ever guessed (see "What the evaluator runs" below);
- an undecidable condition keeps the value `conditional`; equal-priority disagreement is `conflict`; nothing is guessed;
- a missing setting gets a default only when the option catalog proves it for the release in force, else `unknown`;
- the release comes from the target or the flake's `nixpkgs` input, never from `system.stateVersion`;
- dynamic attributes, overlays, an opaque parent, a partial module graph or a cycle end as stated caveats that clear
  `definite` and become scan-health conditions;
- Home Manager is a separate namespace, scoped per user.

### What the evaluator runs

A value is computed statically from exactly these forms, and from nothing else. Anything outside the list is `unknown`, and
the option is reported as such rather than guessed.

- **Literals and operators:** booleans, `null`, integers (safe-integer range only), floats, strings, lists, attribute sets;
  `!`, `&&`, `||`, `->`, `==`/`!=` (structural, attribute order ignored, functions never compared), `++`, `//`, `+` (integers
  or strings), `-`, `*`, unary `-`, and `<` `>` `<=` `>=` on integers. There is no division and no path arithmetic.
- **Binding forms:** `let ... in` (lazy, with `inherit x;` and `inherit (lib) x;`), `with` over a known attribute set or over
  `lib` / `builtins`, `if/then/else` on a known condition (only the chosen branch is evaluated), `assert` on a known `true`,
  lambdas (`x: ...`, `{ a, b ? 1, ... }: ...`, `args@{ ... }: ...`) applied to known arguments, partial application, and
  selection `x.a.b` / `x.a or d` on a known attribute set. A binding of a dotted name (`let a.b = 1;`), a duplicate binding or an
  `inherit` from anything but `lib` / `builtins` makes the whole `let` unknown.
- **Scoping follows Nix:** an inner binding shadows an outer one, a lambda parameter shadows a `let`, a lexical binding wins
  over every `with`, and the innermost `with` wins over an outer one. A file-level `let` name is used only when that `let`
  encloses the expression, no other binding or function parameter of the file shares the name, and the expression is not
  inside a `rec` set. A local binding named `config` or `pkgs` is not the module argument.
- **Library functions (a closed allow-list, over fully known arguments):** `lib.optionals`, `lib.optional`,
  `lib.optionalAttrs`, `lib.optionalString`, `lib.concatStringsSep`, `lib.concatMapStringsSep`, `lib.hasPrefix`,
  `lib.hasSuffix`, `lib.boolToString`, `lib.mkMerge` (over plain lists only), `map`, `filter`, `elem`, `length`, `concatLists`,
  `concatMap` (as `lib.<f>` or `builtins.<f>`, `lib.strings.<f>`, `lib.lists.<f>`, or through `with lib;` / `inherit (lib)`),
  `builtins.hasAttr`, `toString` (strings, integers, booleans, null). `lib` must be the module's own `lib` argument and not
  rebound in the file.
- **String interpolation** when every interpolated part is a known string (an integer or a derivation is not).
- **`config.<option>`** reads, `cfg.x` through a `let cfg = config.a.b;` alias, `pkgs.stdenv.isLinux`-style flags from the target
  system, and `target.args`, as before.
- **Priority wrappers.** `lib.mkDefault`, `mkForce`, `mkOverride N`, `mkBefore`, `mkAfter` around a definition are read by the
  module resolver, so `lib.mkDefault (base ++ lib.optionals cond [ 80 ])` is a priority-1000 definition of the computed list.
  A wrapper **inside** an evaluated value (`let p = lib.mkDefault [ 22 ]; in p`) is `unknown`: a priority cannot be recovered
  from a value. A `let`, `with` or `assert` that wraps a definition is evaluated as a whole, so its bindings apply to the value.

Never evaluated: `import`, `fetch*`, `readFile`, `toFile`, `getEnv`, `currentSystem`, `trace`, `throw`, path values, `rec`
sets, dynamic attribute names, derivations, and any library function not listed above. Evaluation is bounded: the step budget
(`maxEvaluations`), expression nesting (`maxExprDepth`, so runaway recursion stops) and result size (`maxValueSize`) each end as
`unknown` plus a `truncated` entry, never as a partial answer.

## Hardening rules

Judged against the effective configuration, never raw text. Enabled, listening and reachable are separate: a service that
is merely declared is not a finding, and reachability is always `unknown` (only the host firewall is modelled).

<!-- generated:nix-hardening:start -->
22 rules, judged against the effective configuration:

| Rule | Family | CWE | Severity | Finding |
| --- | --- | --- | --- | --- |
| `ssh-root-login` | ssh-access | CWE-250 | high | SSH permits direct root login with a password |
| `ssh-password-auth` | ssh-access | CWE-307 | medium | SSH accepts password authentication |
| `ssh-empty-passwords` | ssh-access | CWE-258 | high | SSH permits empty passwords |
| `firewall-disabled` | firewall-exposure | CWE-284 | high | Host firewall is disabled |
| `firewall-sensitive-port` | firewall-exposure | CWE-668 | high | Firewall opens a database or administration port on every interface |
| `firewall-wide-port-range` | firewall-exposure | CWE-668 | high | Firewall opens a very wide port range on every interface |
| `listener-all-interfaces` | firewall-exposure | CWE-668 | medium | Service is configured to listen on every interface |
| `listener-trust-auth` | firewall-exposure | CWE-306 | high | Database authentication is "trust" for a network-wide address range |
| `service-runs-as-root` | service-identity | CWE-250 | medium | systemd service runs as root |
| `service-exec-elevated` | service-identity | CWE-250 | medium | ExecStart uses a privilege-preserving prefix |
| `systemd-dangerous-capability` | systemd-privilege | CWE-250 | high | systemd service holds a dangerous Linux capability |
| `systemd-device-access` | systemd-privilege | CWE-250 | high | systemd service may access raw memory or all devices |
| `systemd-filesystem-relaxed` | systemd-privilege | CWE-732 | medium | systemd service filesystem protection is disabled or the root is writable |
| `systemd-no-new-privileges-off` | systemd-privilege | CWE-269 | low | NoNewPrivileges is explicitly disabled |
| `sudo-passwordless-wheel` | privilege-escalation | CWE-250 | high | Members of wheel get passwordless root through sudo |
| `sudo-nopasswd-all` | privilege-escalation | CWE-250 | high | sudoers grants NOPASSWD for ALL commands |
| `doas-nopass` | privilege-escalation | CWE-250 | high | doas permits passwordless privilege escalation |
| `tls-verification-disabled` | tls-runtime | CWE-295 | medium | Service environment disables TLS certificate verification |
| `tls-key-in-store` | tls-runtime | CWE-312 | high | TLS private key is copied into the world-readable Nix store |
| `tls-not-enforced` | tls-runtime | CWE-319 | medium | Virtual host explicitly serves cleartext HTTP (forceSSL = false) |
| `container-privileged` | container-declaration | CWE-250 | high | OCI container is declared privileged or with a dangerous mount |
| `container-host-network` | container-declaration | CWE-668 | medium | OCI container shares the host network namespace |
<!-- generated:nix-hardening:end -->

**Firewall port ranges.** `networking.firewall.allowedTCPPortRanges` and `allowedUDPPortRanges` open ports exactly as the
single-port lists do, and are judged the same way:

| Range opened on every interface | Result |
|---|---|
| every port (`from <= 1` and `to >= 65535`) | `firewall-wide-port-range`, **high**: a firewall that is off in everything but name |
| ten thousand ports or more | `firewall-wide-port-range`, **medium** |
| a smaller range that contains a database or administration port (PostgreSQL 5432, Redis 6379, ...) | `firewall-sensitive-port` for each such port, with the range recorded |
| a smaller range with no such port (a peer-to-peer client's 6881-6999, say) | nothing |
| a range under `networking.firewall.interfaces.<name>.` | nothing: interface-scoped ingress is restrictive |

A service port that falls inside a global range is reported `open-in-firewall`, not `firewall-closed`. A range option that
cannot be read as `{ from, to }` integers (a `config.` reference inside, say) is **not** read as closed: every firewall
conclusion becomes `unknown` and a `firewall-port-ranges-unevaluated` gap is recorded, so the absence of a finding is never
presented as a clean result.

Container findings are about **declarations** only; a Nix-built or declared OCI image is not scanned
(`container-image-scan` is listed as a limitation).

## Build, fetch and cache trust

<!-- generated:nix-build-trust:start -->
24 rules (ruleset `nix-build-trust/1`):

| Rule | Family | CWE | Severity | Finding |
| --- | --- | --- | --- | --- |
| `nix-fetch-missing-hash` | nix-fetch-integrity | CWE-494 | high | Fetcher has no content hash |
| `nix-fetch-fake-hash` | nix-fetch-integrity | CWE-494 | medium | Fetcher or fixed-output derivation carries a placeholder hash |
| `nix-fetch-floating-rev` | nix-fetch-pin | CWE-829 | high | Source revision is a moving reference |
| `nix-fetch-insecure-transport` | nix-fetch-integrity | CWE-319 | medium | Fetch uses an unencrypted transport |
| `nix-flake-input-unlocked` | nix-flake-lock | CWE-829 | medium | Flake input is not locked to a revision |
| `nix-flake-nixconfig-cache` | nix-cache-trust | CWE-494 | low | Flake proposes its own binary cache or signing key |
| `nix-script-pipe-to-shell` | nix-script-download | CWE-494 | high | Script pipes a download straight into a shell |
| `nix-script-tls-verification-off` | nix-script-download | CWE-295 | medium | Script downloads with TLS verification disabled |
| `nix-script-unverified-download` | nix-script-download | CWE-494 | medium | Script downloads a file with no integrity check |
| `nix-ifd-boundary` | nix-eval-boundary | CWE-829 | low | Import from derivation crosses an evaluation boundary |
| `nix-ifd-policy-enabled` | nix-eval-boundary | CWE-829 | low | Import from derivation is explicitly enabled |
| `nix-unsafe-native-eval` | nix-eval-native | CWE-94 | high | Unsafe native code is allowed during evaluation |
| `nix-eval-native-plugin` | nix-eval-native | CWE-94 | high | Evaluator loads native plugins |
| `nix-extra-builtins-file` | nix-eval-native | CWE-94 | medium | Evaluator loads extra builtins from a file |
| `nix-trusted-users-widened` | nix-privilege | CWE-269 | medium | trusted-users grants daemon privileges beyond root |
| `nix-require-sigs-disabled` | nix-cache-trust | CWE-347 | high | Binary-cache signature checking is disabled |
| `nix-substituter-insecure-transport` | nix-cache-trust | CWE-319 | low | Binary cache is reached over plain http |
| `nix-accept-flake-config` | nix-cache-trust | CWE-494 | medium | Flake-supplied configuration is accepted automatically |
| `nix-sandbox-disabled` | nix-sandbox | CWE-693 | high | Build sandbox is disabled or relaxed |
| `nix-sandbox-sensitive-path` | nix-sandbox | CWE-732 | high | Sandbox exposes a sensitive host path to builds |
| `nix-build-users-group-empty` | nix-sandbox | CWE-250 | high | Builds run as the invoking user |
| `nix-overlay-hardening-disabled` | nix-overlay | CWE-693 | medium | Overlay disables compiler hardening |
| `nix-overlay-clears-vuln-marker` | nix-overlay | CWE-1395 | medium | Overlay clears a package's knownVulnerabilities |
| `nix-insecure-packages-permitted` | nix-overlay | CWE-1395 | low | Insecure packages are permitted |
<!-- generated:nix-build-trust:end -->

## Secrets in Nix

Anything rendered into the Nix store is readable by every local user, so a credential that reaches a store path is a leak
even if the file looks private. The scanner reports the credential itself (redacted in every output), the store path it
reaches, build-time and log exposure, and decrypt-then-copy patterns:

<!-- generated:nix-secrets:start -->
| Rule | Family | CWE | Finding |
| --- | --- | --- | --- |
| `nix-secret-plaintext` | hardcoded-secret | CWE-798 | Credential written as a literal in Nix source |
| `nix-secret-store` | secret-in-store | CWE-312 | Secret value reaches the world-readable Nix store |
| `nix-secret-build` | secret-in-build | CWE-312 | Secret is a derivation input or environment variable |
| `nix-secret-log` | secret-in-log | CWE-532 | Secret value is printed to a log or trace |
| `nix-secret-decrypt-copy` | secret-in-store | CWE-312 | Decrypted secret copied into a store value at evaluation time |
| `nix-secret-plaintext-file` | hardcoded-secret | CWE-312 | Plaintext credentials file used where an encrypted file is expected |
<!-- generated:nix-secrets:end -->

Prefer a runtime secret mechanism (a path outside the store such as `config.age.secrets.<name>.path` or `sops.secrets`,
a systemd `LoadCredential=`, or an environment file) and rotate any value that was ever in a store path or a repository.
Moving a secret changes where the credential lives and who can read it, so these findings are **guidance only**: the
scanner never rewrites them.

## Personal data

A `config.<module>.<field>` option whose name classifies as personal data (an email, a health or payment field) that is
interpolated into another option's value ends up in the store. Each such reference is a field-to-store flow in the Data
Flow Explorer, labelled with where it lands (an `/etc` file, a unit script, an environment). A reference hashed with
`builtins.hashString`, measured with `stringLength` or only compared is recorded as protected and produces no flow. The
journey is shown in the [Data Flow Explorer guide](data-flow-explorer.md); credential-shaped names belong to the secret
rules above, not here.

## Dependencies: flake inputs, the closure and advisories

- **Declared inputs.** `flake.nix` and `flake.lock` give the flake inputs: locked revision, fetch type, `narHash`, follows
  edges. An unlocked input is a finding; a lock that cannot be read is a stated gap. Inputs are source dependencies, not
  the build closure, so the SBOM marks them `incomplete`.
- **The closure.** To get the real build or runtime closure you export it yourself, with the tool you trust, and save it in
  the project:

  ```bash
  nix path-info --json --recursive .#app        > pathinfo.json
  nix derivation show --recursive .#app         > drvshow.json
  ```

  The scanner reads one file by exact path, `nix-export.json` (or `.direnv/nix-export.json`), holding the exports and what
  you expect them to describe:

  ```json
  { "exports": [
      { "schema": "nix-path-info-json",        "data": { "...": "..." }, "provenance": { "tool": "nix", "command": "nix path-info --json --recursive .#app", "target": { "system": "x86_64-linux", "installable": ".#app" }, "flakeLockSha256": "<sha256 of flake.lock>", "generatedAt": "<ISO time>" } },
      { "schema": "nix-derivation-show-json", "data": { "...": "..." }, "provenance": { "...": "..." } } ],
    "expected": { "system": "x86_64-linux", "installable": ".#app", "flakeLockSha256": "<sha256 of flake.lock>" } }
  ```

  An export without provenance, for another target, from another lock, or too old is **refused with a stated reason** and
  never half-used. Output-only `nix-store --query --requisites` text is accepted as a path list with no edges and is
  labelled so. A malformed or oversized export is a scan-health condition. Nothing is run to produce or refresh it. Trust: the freshness of a Nix export is derived by the scanner from the project's `flake.lock`, never read from the export; an export or plan that the project itself supplies is disclosed as project-supplied, and an operator-supplied one (environment variable) is the trusted path.
- **Advisories.** Provide an OSV-style snapshot, either `AGENTIC_SECURITY_NIX_ADVISORIES=/path/to/advisories.json` or
  `nix-advisories.json` in the operator configuration directory (`$XDG_CONFIG_HOME/agentic-security/`). A copy inside the scanned project is ignored and reported: a project cannot vouch for its own advisories. A
  component is matched by its **upstream identity** (the source URL host and repository, an explicit purl or CPE), never by
  its Nix attribute name alone: a name-only or ambiguous identity yields a `candidate`, not a verdict. A backported patch
  counts only when its content hash is one the advisory lists as a fix; a patch merely named after a CVE is an unverified
  claim and the finding stays `possibly-affected`. Wrapped Haskell packages reuse the Hackage matcher and the same Hackage advisory data, including the opt-in live feed described in the [Haskell guide](haskell.md#dependencies-advisories-and-the-software-bill-of-materials); a Hackage package that feed did not cover is reported unknown, not clean. With no snapshot the
  scan is `partial` and says the closure was **not checked**, which is not a clean result.
- **License data** is not present in these records, so no license policy is applied and the scan says so.

## Fixes

```bash
agentic-security fix --finding <id> --preview
agentic-security fix --finding <id> --apply
agentic-security undo
```

A fix edits the definition that wins by priority, and carries a tier: **full-source-edit**, **source-edit-requires-relock**
(a `flake.lock` change you must regenerate with `nix flake lock`), **guidance-only** or **blocked**. The gates are the same
as for Haskell: path inside the project, syntax, and a rescan that must show the finding gone and nothing new at medium or
above. No evaluation is run to verify a fix unless you opt in.

<!-- generated:fix-nix-ssh:start -->
```text
$ agentic-security fix --finding <id> --preview     # exit 0
FULL (full-source-edit): services.openssh.settings.PermitRootLogin = "yes" -> "no" at configuration.nix:8, the definition that wins by priority.
--- a/configuration.nix
+++ b/configuration.nix
@@ -8,1 +8,1 @@
-    settings.PermitRootLogin = "yes";
+    settings.PermitRootLogin = "no";
  note: Root can no longer log in over SSH. Make sure a non-root account with an authorized key and sudo access exists BEFORE deploying, or you can lock yourself out.
```
<!-- generated:fix-nix-ssh:end -->

A finding that needs a human decision is reported as guidance and exits non-zero, rather than being patched:

<!-- generated:fix-nix-secret:start -->
```text
$ agentic-security fix --finding <id> --preview     # exit 4
No verified fix for this finding (manual, guidance-only): moving a secret out of the store changes where the credential lives and who can read it: it needs a human migration, never an automatic rewrite
```
<!-- generated:fix-nix-secret:end -->

## Haskell on Nix

A project that builds a Haskell package with Nix is scanned as both: the Haskell sources get the Haskell analysis and the
flake gets the Nix analysis, and a service module that runs the built program as `root` is a Nix finding about the same
code.

<!-- generated:ex-hn-vuln:start -->
Captured from the built bundle on `examples/haskell-on-nix/vulnerable`: exit code **3**, scan health **partial**.

| Severity | Family | CWE | Location |
| --- | --- | --- | --- |
| medium | `vulnerable-dep` | CWE-829 | flake.nix:0 |
| low | `vulnerable-dep` | CWE-829 | flake.nix:0 |
| high | `path-traversal` | CWE-22 | src/Main.hs:14 |
| critical | `command-injection` | CWE-78 | src/Main.hs:15 |
| critical | `multi-sink-taint-chain` | CWE-20 | src/Main.hs:15 |

Scan-health conditions:
- no Hackage advisory snapshot is loaded: Haskell dependency vulnerabilities were not assessed. no advisory snapshot configured (set AGENTIC_SECURITY_HACKAGE_ADVISORIES, or place hackage-advisories.json in the operator configuration directory, agentic-security under XDG_CONFIG_HOME) To fetch advisories from the OSV Hackage feed instead, set AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1 (network, opt-in).
- 1 Nix build-trust finding(s) rest on an unresolved branch or partial module graph

Disclosed limits: `license-data-unavailable`.
<!-- generated:ex-hn-vuln:end -->

## Optional evaluation

Evaluation is **off by default** and a default scan never starts a Nix evaluator. To select it:

```bash
export AGENTIC_SECURITY_NIX_EVAL=1
export AGENTIC_SECURITY_NIX_TARGET=nixosConfigurations.<host>.config.system.build.toplevel.drvPath
agentic-security scan .
```

It runs only when a sandbox (macOS `sandbox-exec`, Linux namespaces) **proves its isolation** with a probe, with the pure,
offline, no-lock-update flags, a deadline, an output cap and a memory cap. Whatever happens is a scan-health field:
`not_selected`, `ok`, `unsupported` (no `nix` binary, no sandbox, no suitable evaluator), `blocked` (no target, probe
failed), `failed` or `timed_out`. Static findings are kept in every case, and `ci --assurance strict` fails a scan that
selected the evaluation and did not get it. On a host without Nix the evaluation reports `unsupported` and the project's code
is **not** evaluated; that is the case on the machine this guide's captured outputs were produced on.

## Scan-health, limits and what is not claimed

- Conditional options, dynamic attributes, import cycles, parse errors and budget hits are stated, not dropped; a binding
  with a syntax error withholds only that binding.
- Unevaluated: overlays that compute values, `builtins.getFlake`, import-from-derivation and anything behind `nix eval`.
- No runtime claim: whether a service is reachable, whether a path exists on a host, or what a deployed system does.
- NixOS **host** execution of the scanner itself, and the VM-based checks, are covered by the separate NixOS jobs and are
  not part of what scanning a configuration claims; see [Installing on NixOS](nixos-install.md) and the support table in
  [Haskell and Nix support](../language-support.md), where `nix-eval` and `nixos-host` are `blocked` wherever no Nix or NixOS
  was available to measure on.
