// Turns a measure.mjs result for the unseen-nix-v1 split into the baseline markdown, over the shared ../frozen-split.mjs.
// Usage: node summarize.mjs <result.json> <out.md>
import { summarizeCli } from '../frozen-split.mjs';

await summarizeCli({ split: 'unseen-nix-v1', eco: 'nix' });
