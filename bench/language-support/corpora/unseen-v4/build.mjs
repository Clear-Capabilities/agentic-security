// Builds sources/, labels.json and manifest.json of the unseen-v4 split from authoring/*.txt, over the shared ../frozen-split.mjs
// (the body this file used to carry; `--verify` reproduces the digests frozen on 2026-10-26 exactly).
// Usage: node build.mjs          (writes; refuses if a manifest already exists)
//        node build.mjs --verify (recomputes and compares against manifest.json)
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCli } from '../frozen-split.mjs';

buildCli({ dir: path.dirname(fileURLToPath(import.meta.url)), split: 'unseen-v4', idPrefix: 'hs-v4-' });
