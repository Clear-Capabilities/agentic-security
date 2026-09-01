import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { contrastRatio, meetsAA } from '../src/lib/contrast.js';

const TOKENS_PATH = fileURLToPath(new URL('../styles/tokens.css', import.meta.url));
const CSS = readFileSync(TOKENS_PATH, 'utf8');

// Extracts every `--name: #HEXVALUE;` declaration inside ONE named CSS
// block (`:root { ... }` or `:root[data-theme="light"] { ... }`), keyed
// by the bare token name (no leading `--`). Regex-based, not a real CSS
// parser — sufficient because tokens.css is a hand-authored, single-file,
// flat custom-property list with no nesting beyond the two theme blocks
// this test explicitly targets.
function extractTokens(css, blockStartPattern) {
  const startMatch = blockStartPattern.exec(css);
  assert.ok(startMatch, `expected to find a block matching ${blockStartPattern}`);
  const blockStart = startMatch.index + startMatch[0].length;
  const blockEnd = css.indexOf('}', blockStart);
  const block = css.slice(blockStart, blockEnd);
  const tokens = {};
  const re = /--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6});/g;
  let m;
  while ((m = re.exec(block))) {
    tokens[m[1]] = m[2];
  }
  return tokens;
}

const darkTokens = extractTokens(CSS, /:root\s*\{/);
const lightTokens = extractTokens(CSS, /:root\[data-theme="light"\]\s*\{/);

test('sanity: both theme blocks were actually found and non-trivially parsed', () => {
  assert.ok(Object.keys(darkTokens).length > 5, 'dark token block should have several colors');
  assert.ok(Object.keys(lightTokens).length > 5, 'light token block should have several colors');
  assert.ok('status-protected' in darkTokens, 'dark block should define --status-protected');
  assert.ok('status-protected' in lightTokens, 'light block should define --status-protected');
});

const STATUS_TOKENS = ['status-protected', 'status-unprotected', 'status-unknown'];
const BACKGROUND_TOKENS = ['surface-canvas', 'surface-panel'];

for (const theme of [{ name: 'dark', tokens: darkTokens }, { name: 'light', tokens: lightTokens }]) {
  for (const statusToken of STATUS_TOKENS) {
    for (const bgToken of BACKGROUND_TOKENS) {
      test(`${theme.name} theme: --${statusToken} meets AA against --${bgToken}`, () => {
        const statusColor = theme.tokens[statusToken];
        const bgColor = theme.tokens[bgToken];
        assert.ok(statusColor, `--${statusToken} must exist in the ${theme.name} block`);
        assert.ok(bgColor, `--${bgToken} must exist in the ${theme.name} block`);
        assert.ok(
          meetsAA(statusColor, bgColor),
          `--${statusToken} (${statusColor}) against --${bgToken} (${bgColor}) in ${theme.name} theme: ${contrastRatio(statusColor, bgColor).toFixed(2)}:1, needs >= 4.5:1`,
        );
      });
    }
  }
}

// Regression pin on the two ratios tokens.css's own comments already
// hand-verified — confirms the existing comments are still true, not just
// that new code agrees with itself.
test('dark theme: --status-banner-text against --status-unknown is ~10.27:1 (per tokens.css\'s own comment)', () => {
  const ratio = contrastRatio(darkTokens['status-banner-text'], darkTokens['status-unknown']);
  assert.ok(Math.abs(ratio - 10.27) < 0.1, `expected ~10.27:1, got ${ratio.toFixed(2)}:1`);
});

test('light theme: --status-banner-text against --status-unknown is ~4.69:1 (per tokens.css\'s own comment)', () => {
  const ratio = contrastRatio(lightTokens['status-banner-text'], lightTokens['status-unknown']);
  assert.ok(Math.abs(ratio - 4.69) < 0.1, `expected ~4.69:1, got ${ratio.toFixed(2)}:1`);
});
