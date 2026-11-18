// Ruby helpers that interpolate a method argument into markup and mark it html_safe (CWE-79), src/sast/ruby-html-interpolation.js.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRubyHtmlInterpolation as scan } from '../src/sast/ruby-html-interpolation.js';
import { runScan } from '../src/runScan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (kind) => path.join(here, 'fixtures', 'ruby-html-interpolation', kind);
const lines = (code, file = 'app/helpers/x_helper.rb') => scan(file, code).map((f) => f.line);

describe('ruby-html-interpolation', () => {
  test('an argument interpolated into markup marked html_safe on the same line', () => {
    assert.deepEqual(lines('def badge(label)\n  "<b>#{label}</b>".html_safe\nend\n'), [2]);
    assert.deepEqual(lines('def badge(label)\n  raw("<b>#{label}</b>")\nend\n'), [2]);
  });

  test('a local carries the argument: reported where it was interpolated, which is where the escape belongs', () => {
    const code = "def placeholder(filename)\n  msg = \"'#{filename}' missing\"\n  \"<svg><!-- #{msg} --></svg>\".html_safe\nend\n";
    assert.deepEqual(lines(code), [2]);
    const held = 'def card(title)\n  html = "<h2>#{title}</h2>"\n  html.html_safe\nend\n';
    assert.deepEqual(lines(held), [2]);
  });

  test('block parameters of a call on an argument are tainted', () => {
    assert.deepEqual(lines('def list(items)\n  items.map do |it|\n    "<li>#{it}</li>".html_safe\n  end\nend\n'), [3]);
  });

  test('escaped, numeric and call-result interpolations are silent', () => {
    assert.deepEqual(lines('def badge(label)\n  "<b>#{ERB::Util.html_escape(label)}</b>".html_safe\nend\n'), []);
    assert.deepEqual(lines('def badge(label)\n  "<b>#{h(label)}</b>".html_safe\nend\n'), []);
    assert.deepEqual(lines('def badge(items)\n  "<b>#{items.size}</b>".html_safe\nend\n'), []);
    assert.deepEqual(lines('def badge(name)\n  "<b>#{hint(name)}</b>".html_safe\nend\n'), [], 'a call prints its result, not its argument');
    assert.deepEqual(lines('def badge(name)\n  m = "x #{CGI.escapeHTML(name)}"\n  "<b>#{m}</b>".html_safe\nend\n'), []);
  });

  test('markup not marked safe, a value that is not an argument, and specs are silent', () => {
    assert.deepEqual(lines('def badge(label)\n  "<b>#{label}</b>"\nend\n'), [], 'Rails escapes a string that is not marked safe');
    assert.deepEqual(lines('def badge\n  "<b>#{t(\'x\')}</b>".html_safe\nend\n'), []);
    assert.deepEqual(lines('def badge(label)\n  label = "fixed"\n  "<b>#{label}</b>".html_safe\nend\n'), [], 'reassigned from a literal');
    assert.deepEqual(scan('spec/helpers/x_spec.rb', 'def badge(label)\n  "<b>#{label}</b>".html_safe\nend\n'), []);
  });

  test('fixtures: vulnerable fires on both helpers, clean is silent', () => {
    const v = scan('badge_helper.rb', fs.readFileSync(path.join(fx('vulnerable'), 'badge_helper.rb'), 'utf8'));
    assert.deepEqual(v.map((f) => f.line), [3, 7]);
    assert.ok(v.every((f) => f.cwe === 'CWE-79' && f.family === 'xss' && f.parser === 'RUBY-HTML'));
    assert.deepEqual(scan('badge_helper.rb', fs.readFileSync(path.join(fx('clean'), 'badge_helper.rb'), 'utf8')), []);
  });

  test('end to end through the engine', async () => {
    const hits = async (dir) => (await runScan(dir)).scan.findings.filter((f) => f.parser === 'RUBY-HTML').map((f) => f.line).sort((a, b) => a - b);
    assert.deepEqual(await hits(fx('vulnerable')), [3, 7]);
    assert.deepEqual(await hits(fx('clean')), []);
  });
});
