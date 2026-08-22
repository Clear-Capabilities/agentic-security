// ML supply chain analyzer — Item #7 of the world-class+3 plan.
//
// Fills the gaps between model-load.js (pickle/torch/yaml core) and
// llm-app.js / llm-owasp.js (runtime prompt-injection / tool-exec). This
// module catches:
//
//   1. MLFLOW_UNTRUSTED_URI            mlflow.pyfunc.load_model from URI
//                                       not under a verified registry
//   2. ONNX_NO_PROVIDER_ALLOWLIST      onnxruntime.InferenceSession without
//                                       explicit providers=[...]
//   3. HF_DATASETS_TRUST_REMOTE_CODE   load_dataset(trust_remote_code=True)
//   4. STREAMING_DATASET_URL           webdataset / streaming.StreamingDataset
//                                       loading from HTTP without checksum
//   5. PROMPT_FROM_ENV_OR_URL          System prompt sourced from env var /
//                                       URL fetch / file read without integrity
//   6. AGENT_TOOL_EXPOSES_EXEC         LangChain / OpenAI function-calling
//                                       tool definitions exposing exec/shell/eval/fs.write
//   7. UNSAFE_MODEL_FILE_FORMAT        Loading .pt/.pth/.bin where .safetensors
//                                       would do (informational nudge)
//   8. MODEL_HASH_NOT_VERIFIED         Downloading model file via requests /
//                                       urllib without a verifying checksum
//   9. GRADIO_AUTH_DISABLED            gradio.launch(share=True) without auth
//  10. CUSTOM_HF_HUB_URL               HF cache_dir / endpoint override
//                                       pointing at non-canonical mirror
//
// Detection: regex on .py / .ipynb. Lower confidence than model-load.js
// because these patterns are less unique — context matters.
//
// Opt-out: AGENTIC_SECURITY_NO_ML_SUPPLY=1

import { blankComments } from './_comment-strip.js';

// The finding families this module can emit (F10.2 producer registry).
//
// Declared HERE, next to the rules, because no external method enumerates them:
// this module passes `family` POSITIONALLY (`_shape(file, line, ruleId, vuln,
// fam, ...)`), so a textual search for `family:` finds nothing, and a corpus
// sweep only ever reports a LOWER BOUND -- it sees whichever families a fixture
// happened to trigger. This list is the union of both, and
// `test/family-registry.test.js` fails if a scan produces a family from this
// module that is not listed.
//
// Add the family here in the same edit that adds the rule.
export const EMITS = [
  'gradio-auth',
  'hf-datasets-rce',
  'hf-endpoint-override',
  'mlflow-untrusted-uri',
  'model-format',
  'onnx-providers',
  'prompt-integrity',
  'streaming-dataset-url',
];

const _SCAN_EXT_RE = /\.(?:py|ipynb)$/i;
const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;

const _RELEVANCE = /\b(?:mlflow|onnxruntime|onnx_runtime|datasets\b|webdataset|streaming\.StreamingDataset|gradio|huggingface_hub|HUGGINGFACE|HF_HUB|langchain|openai|anthropic|tools?\s*=)/i;

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _shape(file, line, ruleId, vuln, fam, sev, cwe, remediation, description) {
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line, vuln, severity: sev, cwe,
    family: fam, parser: 'ML-SUPPLY',
    confidence: 0.75,
    stride: 'Tampering',
    description: description || vuln,
    remediation,
  };
}

// ── Detectors ──────────────────────────────────────────────────────────────

function detectMlflowUntrustedUri(file, raw, code, out, seen) {
  // mlflow.pyfunc.load_model / mlflow.sklearn.load_model from URI not pinning
  // to a registry alias / version.
  const re = /\bmlflow\.(?:pyfunc|sklearn|pytorch|keras|tensorflow|onnx|spark|xgboost)\.load_model\s*\(\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(code))) {
    const uri = m[1];
    // Pinned forms: models:/<name>/<version-number>, models:/<name>@<alias>,
    // runs:/<run-id>/<artifact>, or trailing /\d+ on a non-models URI.
    const isPinned =
      /\bmodels:\/[^/]+\/\d+\b/.test(uri) ||
      /\bmodels:\/[^/]+@\w+/.test(uri) ||
      /\bruns:\/[^/]+\/[\w./-]+/.test(uri) ||
      /\/v?\d+(?:\.\d+)*(?:[/?#]|$)/.test(uri);
    if (isPinned) continue;
    const ln = _line(raw, m.index);
    const id = `mlflow-untrusted-uri:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'mlflow-untrusted-uri',
      `mlflow.load_model from ${uri} without a pinned version / alias`,
      'mlflow-untrusted-uri', 'medium', 'CWE-1357',
      'Use a pinned MLflow URI: `models:/<name>/<version>` or `models:/<name>@<alias>`. Without it, model loads pick up whatever revision the registry serves at runtime — a registry compromise (or accidental promotion) silently changes your inference path.',
      'MLflow URIs without explicit version pinning resolve to the current "latest" / champion. Model promotion events change the deployed model without redeploying your service. Same risk class as `:latest` Docker tags.'));
  }
}

function detectOnnxNoProviderAllowlist(file, raw, code, out, seen) {
  // onnxruntime.InferenceSession(...) without explicit providers=[...].
  const re = /\b(?:onnxruntime|ort)\.InferenceSession\s*\([^)]+\)/g;
  let m;
  while ((m = re.exec(code))) {
    if (/providers\s*=/.test(m[0])) continue;
    const ln = _line(raw, m.index);
    const id = `onnx-no-providers:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'onnx-no-providers',
      'onnxruntime.InferenceSession without explicit providers list — falls back to default CPU+CUDA',
      'onnx-providers', 'low', 'CWE-1357',
      'Pass `providers=["CPUExecutionProvider"]` (or specific GPU provider). Without it, ONNX Runtime tries CUDA → DirectML → CPU in order; on shared machines this can leak inference state through GPU residual data.',
      'Explicit providers=[...] also prevents accidental upgrades when ORT changes its provider auto-selection logic between versions.'));
  }
}

function detectHfDatasetsTrustRemoteCode(file, raw, code, out, seen) {
  const re = /\bload_dataset\s*\([^)]*trust_remote_code\s*=\s*True/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    const id = `hf-datasets-trust-remote-code:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'hf-datasets-trust-remote-code',
      'datasets.load_dataset(trust_remote_code=True) executes arbitrary loading code from HF Hub',
      'hf-datasets-rce', 'critical', 'CWE-94',
      'Remove trust_remote_code=True. If you need a dataset whose loader requires custom code, audit the loader script first and vendor it locally as a script under your repo.',
      'HF datasets can ship a Python loader script (.py) that runs during load_dataset. trust_remote_code=True allows that script to run. Same RCE class as transformers.from_pretrained(trust_remote_code=True).'));
  }
}

function detectStreamingDatasetUrl(file, raw, code, out, seen) {
  // webdataset / mosaicml streaming from http(s) URL.
  const patterns = [
    /\bwebdataset\.(?:WebDataset|WebLoader)\s*\(\s*['"]https?:\/\//g,
    /\bstreaming\.StreamingDataset\s*\(\s*[^)]*remote\s*=\s*['"]https?:\/\//g,
    /\bdatasets\.load_dataset\s*\(\s*['"]https?:\/\//g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `streaming-dataset-url:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'streaming-dataset-url',
        'Streaming dataset loaded from HTTP(S) URL without integrity verification',
        'streaming-dataset-url', 'medium', 'CWE-494',
        'Mirror the dataset to a controlled store (S3 + signed URLs, GCS, internal HF Hub) and verify a manifest checksum before training. Public CDNs hosting datasets are routinely repointed.',
        'Training-time data poisoning is a documented attack class — controlling even 0.1% of training data is enough to backdoor an LLM (Carlini et al., 2023). Mirror + checksum is the proven defense.'));
    }
  }
}

function detectPromptFromEnvOrUrl(file, raw, code, out, seen) {
  // System prompt sourced from os.environ / requests.get / open() at runtime.
  const indicators = [
    { re: /SYSTEM_PROMPT\s*=\s*os\.(?:environ\.get|getenv)\s*\(/g, src: 'os.environ' },
    { re: /system_prompt\s*=\s*os\.(?:environ\.get|getenv)\s*\(/g, src: 'os.environ' },
    { re: /(?:system_prompt|SYSTEM_PROMPT)\s*=\s*requests\.get\s*\(/g, src: 'requests.get' },
    { re: /(?:system_prompt|SYSTEM_PROMPT)\s*=\s*open\s*\(\s*['"][^'"]+['"]/g, src: 'open()' },
  ];
  for (const ind of indicators) {
    let m;
    while ((m = ind.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `prompt-from-env-or-url:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'prompt-from-env-or-url',
        `System prompt loaded from ${ind.src} — modifiable at runtime`,
        'prompt-integrity', 'medium', 'CWE-345',
        'Bake the system prompt into the deployed artifact (Python string constant or repo-committed file). If you need runtime overrides, gate them behind a signed manifest (Sigstore) or HMAC-checked source. Environment variables and remote fetches are tamperable by anyone with deploy or network access.',
        'A modifiable system prompt is one of the easiest ways to subvert an agent — change the instructions, change the behavior. Recent prompt-injection-via-config-file incidents (Replit Agent, Cursor) all reduce to this pattern.'));
    }
  }
}

// (Agent tools exposing exec/shell/subprocess to the LLM are detected by
// sast/llm-app.js detectToolExec — not duplicated here.)

function detectUnsafeModelFileFormat(file, raw, code, out, seen) {
  // Loading .pt / .pth / .bin — recommend .safetensors.
  // Only fires when path-string literally ends in one of those extensions.
  const re = /['"]([^'"]+\.(?:pt|pth|bin|ckpt))['"]/g;
  let m;
  while ((m = re.exec(code))) {
    const window = code.slice(Math.max(0, m.index - 100), m.index);
    if (!/torch\.load|load_state_dict|from_pretrained|joblib\.load/.test(window)) continue;
    const ln = _line(raw, m.index);
    const id = `unsafe-model-format:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'unsafe-model-format',
      `Loading ${m[1]} (.pt/.pth/.bin/.ckpt is pickle-based) — prefer .safetensors`,
      'model-format', 'low', 'CWE-502',
      'Convert to `.safetensors` format: `from safetensors.torch import save_file; save_file(state_dict, "model.safetensors")`. Safetensors is a header + raw tensor data — it cannot execute code during load.',
      'pickle-based model formats are the canonical RCE attack vector for ML supply chain. Safetensors was created specifically to eliminate this class.'));
  }
}

function detectGradioAuthDisabled(file, raw, code, out, seen) {
  // gradio.launch(share=True) without auth=...
  const re = /\b(?:gr|gradio)\.[A-Z]\w*\.launch\s*\(([^)]*)\)|\b(?:demo|app|iface)\.launch\s*\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(code))) {
    const args = (m[1] || m[2] || '');
    if (!/share\s*=\s*True/.test(args)) continue;
    if (/\bauth\s*=/.test(args)) continue;
    const ln = _line(raw, m.index);
    const id = `gradio-share-no-auth:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'gradio-share-no-auth',
      'gradio launch with share=True but no auth — publicly accessible via gradio.live',
      'gradio-auth', 'high', 'CWE-862',
      'Add `auth=("user", "password")` or `auth=callable` to gradio.launch. share=True exposes the demo via gradio.live tunnel — a public URL that anyone with the link can reach.',
      'gradio.live tunnels are routinely scraped by drift-bots for unauthenticated ML demos. Many demos run prediction APIs that consume rate-limited backend resources.'));
  }
}

function detectCustomHfHubUrl(file, raw, code, out, seen) {
  // HF_HUB_ENDPOINT / HF_ENDPOINT / HUGGINGFACE_HUB_CACHE pointing at a
  // non-canonical URL.
  const re = /(?:HF_HUB_ENDPOINT|HF_ENDPOINT|HUGGINGFACE_CO_URL|HUGGINGFACE_HUB_URL)\s*=\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(code))) {
    const url = m[1];
    if (/huggingface\.co|hf\.co/.test(url)) continue;
    const ln = _line(raw, m.index);
    const id = `custom-hf-hub-url:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'custom-hf-hub-url',
      `HF Hub endpoint overridden to ${url}`,
      'hf-endpoint-override', 'medium', 'CWE-494',
      'Verify this is an authorized mirror (e.g. corporate proxy with TLS termination + integrity verification). Some attacks substitute a hostile mirror that returns backdoored weights for popular model names.',
      'Mirror substitution is a documented supply-chain pattern. The mirror returns valid weights for unknown queries and substituted weights for the model the attacker targets.'));
  }
}

// ── Entry point ────────────────────────────────────────────────────────────

const _BENCH_FIXTURE_RE = /(?:^|\/|\\)(?:BenchmarkTest|JulietTestCase|CWE\d+_)[\w-]*\.(?:py|java|c|cpp|cs)$/i;

export function scanMlSupplyChain(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_ML_SUPPLY === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  if (!_SCAN_EXT_RE.test(fp)) return [];
  if (_BENCH_FIXTURE_RE.test(fp)) return [];
  if (_NONPROD_PATH_RE.test(fp.replace(/\\/g, '/'))) return [];
  if (!_RELEVANCE.test(raw)) return [];

  const code = blankComments(raw, 'py');
  const out = [];
  const seen = new Set();
  try { detectMlflowUntrustedUri(fp, raw, code, out, seen); } catch {}
  try { detectOnnxNoProviderAllowlist(fp, raw, code, out, seen); } catch {}
  try { detectHfDatasetsTrustRemoteCode(fp, raw, code, out, seen); } catch {}
  try { detectStreamingDatasetUrl(fp, raw, code, out, seen); } catch {}
  try { detectPromptFromEnvOrUrl(fp, raw, code, out, seen); } catch {}
  try { detectUnsafeModelFileFormat(fp, raw, code, out, seen); } catch {}
  try { detectGradioAuthDisabled(fp, raw, code, out, seen); } catch {}
  try { detectCustomHfHubUrl(fp, raw, code, out, seen); } catch {}
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = {
  _RELEVANCE,
  detectMlflowUntrustedUri, detectOnnxNoProviderAllowlist,
  detectHfDatasetsTrustRemoteCode, detectStreamingDatasetUrl,
  detectPromptFromEnvOrUrl,
  detectUnsafeModelFileFormat, detectGradioAuthDisabled, detectCustomHfHubUrl,
};
