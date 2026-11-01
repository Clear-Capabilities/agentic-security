// Builds sources/, labels.json and manifest.json of the unseen-nix-v1 split from authoring/*.txt, over the shared ../frozen-split.mjs.
// MEASUREMENT ONLY. See README.md. Usage: node build.mjs          (writes; refuses if a manifest already exists)
//                                          node build.mjs --verify (recomputes and compares against manifest.json)
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCli } from '../frozen-split.mjs';

buildCli({ dir: path.dirname(fileURLToPath(import.meta.url)), split: 'unseen-nix-v1', idPrefix: 'nx-v1-', eco: 'nix' });
