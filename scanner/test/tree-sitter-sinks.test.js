import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanTreeSitterRust } from '../src/sast/tree-sitter-sinks.js';
import { isTreeSitterAvailable, treeSitterLangOf } from '../src/ir/tree-sitter-loader.js';

const VULN = 'fn run(input: String){ std::process::Command::new("sh").arg("-c").arg(input).output(); }';

test('loader maps long-tail extensions to languages', () => {
  assert.equal(treeSitterLangOf('a.rs'), 'rust');
  assert.equal(treeSitterLangOf('C.sol'), 'solidity');
  assert.equal(treeSitterLangOf('x.go'), 'go');
  assert.equal(treeSitterLangOf('y.js'), null); // first-class IR parser; not tree-sitter's job
});

test('detector is a no-op without the opt-in flag', async () => {
  delete process.env.AGENTIC_SECURITY_TREE_SITTER;
  assert.deepEqual(await scanTreeSitterRust('a.rs', VULN), []);
});

test('flag on: AST-accurate Rust shell-spawn detection (degrades if dep absent)', async () => {
  process.env.AGENTIC_SECURITY_TREE_SITTER = '1';
  try {
    const available = await isTreeSitterAvailable();
    const vuln = await scanTreeSitterRust('a.rs', VULN);
    if (!available) {
      // Optional dependency missing → must degrade to [], never throw.
      assert.deepEqual(vuln, []);
      return;
    }
    assert.equal(vuln.length, 1);
    assert.equal(vuln[0].cwe, 'CWE-78');
    assert.equal(vuln[0].parser, 'TREE-SITTER');

    // Direct (no-shell) invocation is safe.
    assert.equal((await scanTreeSitterRust('a.rs', 'fn r(){ std::process::Command::new("ls").arg("-la").output(); }')).length, 0);
    // Shell with a literal command is safe.
    assert.equal((await scanTreeSitterRust('a.rs', 'fn r(){ std::process::Command::new("sh").arg("-c").arg("echo hi").output(); }')).length, 0);
    // The AST advantage: the dangerous pattern inside a COMMENT must NOT fire.
    assert.equal((await scanTreeSitterRust('a.rs', '// Command::new("sh").arg("-c").arg(input)\nfn r(){}')).length, 0);
    // Non-rust files ignored.
    assert.equal((await scanTreeSitterRust('a.go', VULN)).length, 0);
  } finally {
    delete process.env.AGENTIC_SECURITY_TREE_SITTER;
  }
});
