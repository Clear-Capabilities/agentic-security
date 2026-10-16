// U-01: a missed real-code vulnerability recovered. basecamp/activerecord-tenanted, GHSA-pmwx-rm49-xv39 (CWE-22): the Active Storage disk service resolves
// `File.join(root, tenant, folder_for(key), key)` for a key a client can influence. The ruby path-join rule was written FROM this advisory and still missed it
// on the independent run, because the join is the RETURN VALUE of a path-resolving method and nothing in the file touches the filesystem with it. The rule now
// treats such a join as reaching the filesystem, but only when the method is named for a path AND the last component is one of its own parameters.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRubyPathJoin } from '../../src/sast/ruby.js';

const hits = (code, file = 'lib/active_record/tenanted/storage.rb') => scanRubyPathJoin(file, code);
const VULN = `module Storage
  module DiskService
    def path_for(key)
      if ActiveRecord::Tenanted.connection_class && key.include?("/")
        tenant, key = key.split("/", 2)
        File.join(root, tenant, folder_for(key), key)
      else
        super
      end
    end
  end
end
`;
const FIXED = `module Storage
  module DiskService
    def path_for(key)
      return super unless ActiveRecord::Tenanted.connection_class && key.include?("/")

      if key.split("/").intersect?(%w[. ..])
        raise ActiveStorage::InvalidKeyError, "key has path traversal segments"
      end

      tenant, key = key.split("/", 2)
      File.join(root, tenant, folder_for(key), key)
    end
  end
end
`;

test('THE REAL SHAPE IS FOUND, with a causal explanation, and the traversal check upstream shipped silences it', () => {
  const f = hits(VULN); assert.equal(f.length, 1); assert.equal(f[0].line, 6); assert.equal(f[0].cwe, 'CWE-22'); assert.match(f[0].description, /nothing in\s+the surrounding code rejects `\.\.` segments/); assert.match(f[0].remediation, /intersect\?/);
  assert.deepEqual(hits(FIXED), [], 'the upstream fix (reject . and .. segments) removes the finding');
});

test('A SEMANTICS-PRESERVING REWRITE KEEPS THE VERDICT: renamed method and parameter, comments, blank lines, an explicit return', () => {
  const v = `class Store
  # where a blob lives on disk
  def file_path(blob_key)

    parts = blob_key.split("/", 2)
    return File.join(base_dir, parts.first, blob_key)
  end
end
`;
  assert.equal(hits(v).length, 1);
  assert.deepEqual(hits(v.replace('return File.join(base_dir, parts.first, blob_key)', 'raise ArgumentError if blob_key.include?("..")\n    return File.join(base_dir, parts.first, blob_key)')), [], 'a containment check in the window silences it');
});

test('NEAR MISSES STAY SILENT: each refusal encodes one way this extension could become noise', () => {
  const wrap = (name, body, args = 'key') => `class A\n  def ${name}(${args})\n    ${body}\n  end\nend\n`;
  assert.deepEqual(hits(wrap('render_page', 'File.join(root, tenant, key)')), [], 'the method is not named for a path');
  assert.deepEqual(hits(wrap('path_for', 'File.join(root, tenant, "index.html")')), [], 'the last component is a literal');
  assert.deepEqual(hits(wrap('path_for', 'File.join(root, tenant, name)')), [], 'the last component is not one of the method\'s parameters');
  assert.deepEqual(hits(wrap('path_for', 'File.join(__dir__, "data", key)')), [], 'a project-relative constant root');
  assert.deepEqual(hits(wrap('path_for', 'File.join(root, tenant, key).to_s')), [], 'chained onto, so not the returned value as written');
  assert.deepEqual(hits(wrap('path_for', 'x = File.join(root, tenant, key)\n    log(x)\n    other')), [], 'assigned and not returned, no filesystem use');
  assert.deepEqual(hits(wrap('path_for', 'File.join(root, tenant, key)'), 'spec/storage_spec.rb'), [], 'test files are skipped for this extension');
});

test('THE ORIGINAL BEHAVIOUR IS UNCHANGED: a join wrapped directly by a filesystem call is still reported without the new rule', () => {
  assert.equal(hits("def show\n  File.read(File.join(root, params[:name]))\nend\n").length, 1);
});
