// Zip Slip in Go: an archive entry name that reaches a file operation without a containment check in the same function.
// Twins: the vulnerable shape, the documented fix, a renamed copy (must behave the same), and near misses (must stay silent or keep firing for the right reason).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanZipSlip } from '../src/sast/zip-slip.js';

const zs = (src, fp = 'extract.go') => scanZipSlip(fp, src).filter((f) => f.parser === 'ZIP-SLIP');
const ZIP_VULN = `package x
import (
  "archive/zip"
  "io"
  "os"
  "path/filepath"
)
func Unzip(src, dest string) error {
  r, err := zip.OpenReader(src)
  if err != nil { return err }
  defer r.Close()
  for _, f := range r.File {
    target := filepath.Join(dest, f.Name)
    out, err := os.Create(target)
    if err != nil { return err }
    rc, _ := f.Open()
    io.Copy(out, rc)
  }
  return nil
}
`;
const ZIP_FIXED = ZIP_VULN.replace('    out, err := os.Create(target)', '    if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) { return errors.New("bad path") }\n    out, err := os.Create(target)');
const TAR_VULN = `package x
import ("archive/tar"; "os"; "path/filepath"; "io")
func Untar(tr *tar.Reader, dest string) error {
  for {
    hdr, err := tr.Next()
    if err == io.EOF { return nil }
    if err != nil { return err }
    p := filepath.Join(dest, hdr.Name)
    if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { return err }
  }
}
`;

test('a zip entry name joined to the destination and then created is flagged, at the line of the file operation', () => {
  const f = zs(ZIP_VULN);
  assert.equal(f.length, 1); assert.equal(f[0].cwe, 'CWE-22'); assert.equal(f[0].line, 14);
});
test('a tar header name joined to the destination and then used to make directories is flagged', () => {
  assert.equal(zs(TAR_VULN).length, 1);
});
test('the entry name used directly in a file operation is flagged', () => {
  assert.equal(zs(ZIP_VULN.replace('target := filepath.Join(dest, f.Name)\n    out, err := os.Create(target)', 'out, err := os.Create(f.Name)')).length, 1);
});
test('FIXED: a prefix check on the joined path in the same function silences it', () => {
  assert.equal(zs(ZIP_FIXED).length, 0);
});
test('FIXED: filepath.IsLocal on the entry name, and a refusal of ".." in the name, also silence it', () => {
  assert.equal(zs(ZIP_VULN.replace('    target :=', '    if !filepath.IsLocal(f.Name) { return nil }\n    target :=')).length, 0);
  assert.equal(zs(ZIP_VULN.replace('    target :=', '    if strings.Contains(f.Name, "..") { return nil }\n    target :=')).length, 0);
});
test('MUTATION: renaming every identifier changes nothing', () => {
  const m = ZIP_VULN.replace(/\bf\b/g, 'entry').replace(/\btarget\b/g, 'outPath').replace(/\bdest\b/g, 'root').replace(/\br\b/g, 'rdr');
  assert.equal(zs(m).length, 1);
  assert.equal(zs(ZIP_FIXED.replace(/\bf\b/g, 'entry').replace(/\btarget\b/g, 'outPath').replace(/\bdest\b/g, 'root')).length, 0);
});
test('NEAR MISS: a check on an unrelated value in the same function does not count as a guard', () => {
  assert.equal(zs(ZIP_VULN.replace('    target :=', '    if strings.HasPrefix(src, "/tmp") { return nil }\n    target :=')).length, 1);
});
test('NEAR MISS: a check in a different function does not silence this one', () => {
  assert.equal(zs(ZIP_VULN + '\nfunc safe(p, d string) bool { return strings.HasPrefix(p, d) }\n').length, 1);
});
test('NEAR MISS: a constant file name, a file with no archive import, and a test file are silent', () => {
  assert.equal(zs(ZIP_VULN.replace('filepath.Join(dest, f.Name)', 'filepath.Join(dest, "out.bin")')).length, 0);
  assert.equal(zs(ZIP_VULN.replace('"archive/zip"', '"fmt"')).length, 0);
  assert.equal(zs(ZIP_VULN, 'extract_test.go').length, 0);
});
test('NEAR MISS: a name that is not an archive entry is not treated as one', () => {
  const src = `package x\nimport ("archive/zip"; "os"; "path/filepath")\nvar _ = zip.ErrFormat\nfunc W(dest string, u struct{ Name string }) error {\n  p := filepath.Join(dest, u.Name)\n  _, err := os.Create(p)\n  return err\n}\n`;
  assert.equal(zs(src).length, 0);
});
