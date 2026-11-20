// The model listing a fake Ollama server answers with.
//
// Since the local-model guard (ollama-provider.js `verifyLocalOllamaModel`), every chat to a loopback Ollama host first reads
// `GET /api/tags` and refuses a model the listing does not contain or marks remote. A fake server written before the guard
// only answered `/api/chat`; it now answers the listing too, naming the models its tests use as LOCAL models (a size, no
// `remote_host`). A test that is about the listing itself keeps its own handler, which takes precedence.
import { DEFAULT_OLLAMA_MODEL } from '../../src/llm-validator/ollama-provider.js';

const LOCAL = new Set([DEFAULT_OLLAMA_MODEL, 'm', 'some-model', 'qwen3.5:4b', 'qwen3:4b', 'qwen3:14b', 'gemma3:4b', 'gemma4:12b',
  'gemma4:26b', 'qwen3-coder:30b', 'local-model:1b']);

/** Add a model name the fake should list as local (a test that builds a unique name at run time); returns the name. */
export function registerLocalTestModel(name) { LOCAL.add(name); return name; }

/** Answer `GET /api/tags` with the local test models. Returns true when it answered. */
export function answerLocalTags(req, res) {
  if (req.method !== 'GET' || req.url !== '/api/tags') return false;
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ models: [...LOCAL].map((name) => ({ name, model: name, size: 1, digest: `sha256:${name}` })) }));
  return true;
}
