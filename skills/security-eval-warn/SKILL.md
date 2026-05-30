---
name: agentic-security:security-eval-warn
description: Refuse runtime code-eval on user input. Activate before writing eval(), Function(), or string→exec patterns.
---

# Skill — refuse runtime code-eval

Activates **before** you write code that converts a string to executable
code at runtime, when that string can come from any input source (HTTP
body, query, header, file, third-party API, message queue).

## When to fire

You're about to call `Edit` / `Write` with a body that contains any of:

- **JS/TS**: `eval(x)`, `new Function(x)`, `setTimeout(stringArg, …)`,
  `setInterval(stringArg, …)`, `vm.runInNewContext(x)`, `vm.compileFunction(x)`,
  `vm.Script(x).runInThisContext()`.
- **Python**: `eval(x)`, `exec(x)`, `compile(x, …)`, `__import__(x)`,
  `getattr(obj, user_string)`, `globals()[user_string]`.
- **Ruby**: `eval(x)`, `class_eval(x)`, `instance_eval(x)`, `send(x, …)`,
  `public_send(x, …)`.
- **PHP**: `eval($x)`, `assert($x)`, `create_function($x, $y)`,
  `call_user_func($x, …)`.
- **Shell-from-JS**: `exec(userString)`, `execSync(userString)`,
  `child_process.exec(userString)` — the user-controlled-shell variant
  is covered by `security-weak-crypto` separately; this skill covers
  the literal code-eval families.
- **Templating-engine eval**: `Mustache.render(x, { __proto__: … })`,
  `Handlebars.compile(userInput)` (template injection).

## What to do

**Stop. Refuse the edit. Propose the structured alternative.**

1. **Name the vuln class.** "CWE-94 / Code Injection. Anything that
   reaches `eval()` at runtime is the same as letting the input source
   write your code directly."

2. **Diagnose what the user actually wants**:
   - Parse JSON? → `JSON.parse(x)` / `json.loads(x)`.
   - Dispatch on a string key? → a `dict`/`object` lookup table with
     an explicit allow-list of keys; throw on unknown.
   - Run user-supplied formulae? → A real expression language with a
     sandboxed evaluator (`mathjs.evaluate` in a worker, `simpleeval`
     in Python, `jsep` for AST-only). Or refuse — formulae from
     untrusted users is the same shape as eval.
   - Lazy-load a module? → Static `import` + a switch statement.
     Never `import(userString)`.
   - Run a deserialization? → A safe deserializer (`json`, not `pickle`).

3. **Show the literal replacement** as a 3-line code block.

4. **If the user insists eval is necessary** (a documented LISP/Lua-style
   feature, a build-time scripting hook), confirm the input source is
   trusted (developer-only file in the repo) AND the input goes through
   a separate validator BEFORE `eval`. Document the assumption in a
   `// agentic-security-ignore: code-injection` pragma with a one-line
   reason.

## Don't

- Don't write the eval call and *then* recommend the safer pattern.
  This skill exists to prevent the write, not to comment on it after.
- Don't accept "the input is from MY frontend, so it's trusted." User-
  controlled clients are NEVER trusted.
- Don't suggest "validate the string first" as the only defense.
  Validation regexes for "is this valid JS" are themselves the bug
  class. Use the structured alternative.

## Canonical commands

- `/setup --bodyguard` — make this skill mandatory on every Edit
- `/scan --uncommitted` — scan just-edited files for code-eval shapes
- `/triage --explain CWE-94` — full explanation of code-injection family
