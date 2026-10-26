// Deterministic security oracles. A model may SELECT an oracle and propose its parameters; it may never decide that the
// oracle succeeded. Each oracle is a pure function of an Observation gathered by the TRUSTED runner (never by the model):
//
//   Observation = {
//     exitCode, signal, timedOut, stdout, stderr,
//     canaries: { <name>: { exists, digestBefore, digestAfter } }      // checked by the runner on disk, after the run
//     callbacks: [{ nonce }]                                            // hits recorded by the runner's loopback listener
//     nonce                                                             // per-run random token the target cannot predict
//   }
//
// An oracle returns { fired, reason }. `fired:false` with `inconclusive:true` means the observation could not decide
// (for example a timeout); it is never treated as "not exploitable".
export const ORACLE_TYPES = Object.freeze([
  'crash_sanitizer', 'command_execution', 'unauthorized_http_access', 'unauthorized_db_read', 'database_mutation',
  'filesystem_mutation', 'outbound_callback', 'authentication_bypass', 'arbitrary_assertion',
  'file_disclosure', 'argument_injection',
]);

const SANITIZER_RE = /(AddressSanitizer|UndefinedBehaviorSanitizer|stack-buffer-overflow|heap-buffer-overflow|SEGV on unknown address|stack smashing detected|buffer overflow detected)/i;
const CRASH_SIGNALS = new Set(['SIGSEGV', 'SIGABRT', 'SIGBUS', 'SIGILL', 'SIGFPE']);

const out = (fired, reason, extra = {}) => ({ fired, reason, ...extra });
const inconclusive = (reason) => ({ fired: false, inconclusive: true, reason });
const has = (obs, text) => typeof text === 'string' && text.length > 0 && `${obs.stdout || ''}${obs.stderr || ''}`.includes(text);

const IMPL = {
  crash_sanitizer(obs) {
    if (SANITIZER_RE.test(obs.stderr || '')) return out(true, 'sanitizer or runtime memory-safety report on stderr');
    if (obs.signal && CRASH_SIGNALS.has(obs.signal)) return out(true, `process terminated by ${obs.signal}`);
    if (obs.timedOut) return inconclusive('run timed out before a crash could be judged');
    return out(false, 'no crash signal and no sanitizer report');
  },
  // The injected payload asks the shell/interpreter to create a file named after the per-run nonce inside the
  // watched canary directory. The target cannot create it unless attacker data reached a command.
  command_execution(obs, p) {
    const c = obs.canaries?.[p.canary || 'command'];
    if (!c) return inconclusive('command canary was not armed by the runner');
    if (c.exists && !c.existedBefore) return out(true, 'nonce-named canary file created by an injected command');
    if (obs.timedOut) return inconclusive('run timed out before the canary could be judged');
    return out(false, 'canary file not created');
  },
  // A secret planted behind authorization (never shown to the exploit client). Seeing the nonce-bearing secret in the
  // client's output while the actor held no credential is the violation.
  unauthorized_http_access(obs, p) {
    const secret = obs.secrets?.[p.secret || 'http'];
    if (!secret) return inconclusive('protected secret was not armed by the runner');
    if (has(obs, secret)) return out(true, 'protected resource content returned to an unauthenticated actor');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'protected content not observed');
  },
  unauthorized_db_read(obs, p) {
    const secret = obs.secrets?.[p.secret || 'db'];
    if (!secret) return inconclusive('database canary row was not armed by the runner');
    if (has(obs, secret)) return out(true, 'row the actor may not read was returned');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'canary row value not observed');
  },
  database_mutation(obs, p) {
    const c = obs.canaries?.[p.canary || 'db'];
    if (!c) return inconclusive('database canary was not armed by the runner');
    if (c.digestBefore && c.digestAfter && c.digestBefore !== c.digestAfter) return out(true, 'protected database state changed');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'protected database state unchanged');
  },
  filesystem_mutation(obs, p) {
    const c = obs.canaries?.[p.canary || 'fs'];
    if (!c) return inconclusive('filesystem canary was not armed by the runner');
    if ((c.exists && !c.existedBefore) || (c.digestBefore && c.digestAfter && c.digestBefore !== c.digestAfter)) return out(true, 'file outside the permitted area was created or modified');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'protected path unchanged');
  },
  // A file the runner planted OUTSIDE the directory the program is meant to read from holds a per-run secret. Seeing that secret in the
  // program's output means attacker data steered a read onto it. The target cannot know the secret in advance, so it can print it
  // only by reading the file. A read that leaves nothing in stdout/stderr is invisible to this oracle (it stays unproven, not refuted).
  file_disclosure(obs, p) {
    const secret = obs.secrets?.[p.secret || 'file'];
    if (!secret) return inconclusive('disclosure canary was not armed by the runner');
    if (has(obs, secret)) return out(true, 'content of a planted file outside the permitted directory appeared in the output');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'planted file content not observed');
  },
  // A stand-in for the called program (planted by the runner, never the target) acts on exactly one option, given as its FIRST argument,
  // by creating a nonce-named file. The file exists only if attacker data reached the first argument of the call unseparated and
  // unvalidated. It shows the option position is attacker-controlled; it does not show the real program has a dangerous option.
  argument_injection(obs, p) {
    const c = obs.canaries?.[p.canary || 'arg'];
    if (!c) return inconclusive('argument canary was not armed by the runner');
    if (c.exists && !c.existedBefore) return out(true, 'a harness-planted option supplied as attacker data reached the first argument of the called program');
    if (obs.timedOut) return inconclusive('run timed out before the canary could be judged');
    return out(false, 'canary file not created');
  },
  outbound_callback(obs) {
    if (obs.callbackUnavailable) return { fired: false, unsupported: true, reason: 'loopback callback listener is not available on this backend' };
    const hit = (obs.callbacks || []).some((c) => c && c.nonce && c.nonce === obs.nonce);
    if (hit) return out(true, 'nonce-bearing request reached the runner-controlled listener');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'no nonce-bearing callback received');
  },
  authentication_bypass(obs, p) {
    const secret = obs.secrets?.[p.secret || 'auth'];
    if (!secret) return inconclusive('protected secret was not armed by the runner');
    if (has(obs, secret)) return out(true, 'privileged content returned without valid credentials');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'privileged content not observed without credentials');
  },
  // Declarative only: no code, no regex supplied by a model. Operators are a closed set.
  arbitrary_assertion(obs, p) {
    const a = p.assert;
    if (!a || typeof a !== 'object') return inconclusive('assertion missing');
    if (obs.timedOut) return inconclusive('run timed out');
    if ('exitCode' in a) return a.exitCode === obs.exitCode ? out(true, `exit code was ${obs.exitCode}`) : out(false, `exit code was ${obs.exitCode}`);
    if ('stdoutIncludes' in a) return has({ stdout: obs.stdout }, String(a.stdoutIncludes)) ? out(true, 'stdout contained the asserted text') : out(false, 'stdout did not contain the asserted text');
    if ('stderrIncludes' in a) return has({ stderr: obs.stderr }, String(a.stderrIncludes)) ? out(true, 'stderr contained the asserted text') : out(false, 'stderr did not contain the asserted text');
    return inconclusive('unsupported assertion operator');
  },
};

export function evaluateOracle(spec, observation) {
  if (!spec || !ORACLE_TYPES.includes(spec.type)) return { fired: false, unsupported: true, reason: `unknown oracle type: ${String(spec?.type)}` };
  if (!observation || typeof observation !== 'object') return inconclusive('no observation');
  try { return IMPL[spec.type](observation, spec.params || {}); } catch (e) { return inconclusive(`oracle error: ${e.message}`); }
}
