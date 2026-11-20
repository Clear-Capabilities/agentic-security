// Models that answer on the loopback port but run somewhere else.
//
// The `ollama` and `local` presets promise that no prompt leaves this machine, and the promise used to rest on the HOST alone:
// a loopback address passed. Ollama can also serve a "cloud" model, which is listed beside the local ones, answers on the same
// loopback port, and forwards every prompt to a remote service. Measured on Ollama 0.24: `GET /api/tags` lists such a model
// with `remote_host` and `remote_model`, and the pulled name ends in `cloud` (`<name>:cloud`, `<name>-cloud`, `<size>-cloud`).
//
// Two checks, because they need different information:
//   - the NAME check is synchronous and needs nothing but configuration, so it runs wherever a provider is resolved
//     (`providers.js` refuses such a model under either preset before any caller exists);
//   - the LISTING check needs the server's own model list, so it runs before the request in `ollama-provider.js`, and catches a
//     model whose name does not say what it is (one created from a cloud base under a local-looking name).
// Both fail closed. No module imports anything here, so every layer may use it without an import cycle.

const CLOUD_TAG = /(?:^|[:-])cloud$/i;

/** True when an Ollama model name carries the cloud tag (`gpt-oss:120b-cloud`, `minimax-m3.1-flash:cloud`). */
export function isCloudModelName(model) {
  return typeof model === 'string' && CLOUD_TAG.test(model.trim());
}

/** The refusal message for a model that would forward prompts off the machine. `via` says how it was recognised. */
export function remoteModelRefusal(preset, model, via) {
  return `the '${preset}' preset keeps every prompt on this machine, and model '${model}' is served from a remote host `
    + `(${via}): Ollama would forward the prompt off this machine. Choose a locally installed model (ollama list shows a size `
    + 'for local models and none for remote ones), or use an explicitly remote provider.';
}
