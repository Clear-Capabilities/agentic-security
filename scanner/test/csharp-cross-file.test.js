import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCsharpCrossFile } from '../src/sast/csharp-cross-file.js';
import { scanCSharp } from '../src/sast/csharp.js';

test('a tainted value passed to a DIFFERENT class\'s static method in a DIFFERENT FILE reaches that method\'s own sink', () => {
  const callerFile = 'Caller.cs';
  const sinkFile = 'Sink.cs';
  const fc = {
    [callerFile]: `
      public class Caller : AbstractTestCaseWeb {
        public override void Bad(HttpRequest req, HttpResponse resp) {
          string data;
          data = req.Params.Get("name");
          Sink.BadSink(data, req, resp);
        }
      }`,
    [sinkFile]: `
      public class Sink {
        public static void BadSink(string data, HttpRequest req, HttpResponse resp) {
          if (data != null) {
            if (File.Exists(data)) {
              using (StreamReader sr = new StreamReader(data)) {
              }
            }
          }
        }
      }`,
  };
  const findings = scanCsharpCrossFile(fc);
  assert.ok(findings.some(f => f.family === 'path-traversal' && f.file === sinkFile),
    `expected a path-traversal finding attributed to ${sinkFile}, got: ${findings.map(f => `${f.file}:${f.family}`).join(',')}`);
  assert.ok(findings.every(f => f.isCrossFile === true), 'every finding from this module must be tagged isCrossFile');
});

test('a hardcoded value passed to a DIFFERENT class\'s static method in a DIFFERENT FILE does not fire', () => {
  const fc = {
    'Caller.cs': `
      public class Caller : AbstractTestCaseWeb {
        public override void Good(HttpRequest req, HttpResponse resp) {
          string data;
          data = "foo";
          Sink.GoodSink(data, req, resp);
        }
      }`,
    'Sink.cs': `
      public class Sink {
        public static void GoodSink(string data, HttpRequest req, HttpResponse resp) {
          if (data != null) {
            if (File.Exists(data)) {
              using (StreamReader sr = new StreamReader(data)) {
              }
            }
          }
        }
      }`,
  };
  const findings = scanCsharpCrossFile(fc);
  assert.ok(!findings.some(f => f.family === 'path-traversal'),
    `expected no path-traversal finding for a hardcoded cross-file argument, got: ${findings.map(f => f.family).join(',')}`);
});

test('a class name declared in TWO files is left ambiguous, never guessed', () => {
  const fc = {
    'Caller.cs': `
      public class Caller : AbstractTestCaseWeb {
        public override void Bad(HttpRequest req, HttpResponse resp) {
          string data;
          data = req.Params.Get("name");
          Sink.BadSink(data, req, resp);
        }
      }`,
    'SinkA.cs': `
      public class Sink {
        public static void BadSink(string data, HttpRequest req, HttpResponse resp) {
          if (data != null) { if (File.Exists(data)) { using (StreamReader sr = new StreamReader(data)) { } } }
        }
      }`,
    'SinkB.cs': `
      public class Sink {
        public static void BadSink(string data, HttpRequest req, HttpResponse resp) {
          if (data != null) { if (File.Exists(data)) { using (StreamReader sr = new StreamReader(data)) { } } }
        }
      }`,
  };
  const findings = scanCsharpCrossFile(fc);
  assert.ok(!findings.some(f => f.family === 'path-traversal'),
    `an ambiguous (two-file) class name must not be resolved, got: ${findings.map(f => `${f.file}:${f.family}`).join(',')}`);
});

test('a receiver resolving only to a NON-STATIC method in another file is left unresolved', () => {
  const fc = {
    'Caller.cs': `
      public class Caller : AbstractTestCaseWeb {
        public override void Bad(HttpRequest req, HttpResponse resp) {
          string data;
          data = req.Params.Get("name");
          Helper.BadSink(data, req, resp);
        }
      }`,
    'Helper.cs': `
      public class Helper {
        private void BadSink(string data, HttpRequest req, HttpResponse resp) {
          if (data != null) { if (File.Exists(data)) { using (StreamReader sr = new StreamReader(data)) { } } }
        }
      }`,
  };
  const findings = scanCsharpCrossFile(fc);
  assert.ok(!findings.some(f => f.family === 'path-traversal'),
    `a non-static candidate must not be resolved cross-file, got: ${findings.map(f => f.family).join(',')}`);
});

test('a finding the ordinary per-file scan already produces on its own is not double-reported by the cross-file pass', () => {
  const fc = {
    'Caller.cs': `
      public class Caller : AbstractTestCaseWeb {
        public override void Bad(HttpRequest req, HttpResponse resp) {
          string data;
          data = req.Params.Get("name");
          Sink.BadSink(data, req, resp);
        }
      }`,
    // Sink.cs ALSO has its own genuinely-tainted direct source, independent
    // of the caller — its finding must already exist in the ordinary scan
    // and must not be duplicated by this module.
    'Sink.cs': `
      public class Sink : AbstractTestCaseWeb {
        public static void BadSink(string data, HttpRequest req, HttpResponse resp) {
          if (data != null) { if (File.Exists(data)) { using (StreamReader sr = new StreamReader(data)) { } } }
        }
        public override void Bad(HttpRequest req, HttpResponse resp) {
          string ownData;
          ownData = req.Params.Get("other");
          if (ownData != null) { if (File.Exists(ownData)) { using (StreamReader sr = new StreamReader(ownData)) { } } }
        }
      }`,
  };
  const findings = scanCsharpCrossFile(fc);
  // The Sink.cs file's OWN direct finding(s) (from its own Bad(), a
  // standalone ordinary scan of Sink.cs on its own already reports these)
  // must NOT be re-reported here — every id this module returns must be
  // ABSENT from Sink.cs's own standalone scan.
  const standaloneIds = new Set(scanCSharp('Sink.cs', fc['Sink.cs']).map(f => f.id));
  for (const f of findings) {
    assert.ok(!standaloneIds.has(f.id), `finding ${f.id} was already produced by the ordinary per-file scan — must not be duplicated`);
  }
  // The genuinely new, cross-file-enabled finding(s) must exist (at BadSink's
  // line, not Bad()'s own line).
  assert.ok(findings.some(f => f.family === 'path-traversal'), 'expected at least one new cross-file finding');
  assert.ok(findings.every(f => f.line === 4), `expected every new finding to be at BadSink's own line (4), got: ${findings.map(f => f.line).join(',')}`);
});

test('fewer than two .cs files short-circuits to no findings', () => {
  const findings = scanCsharpCrossFile({ 'Only.cs': 'public class Only {}' });
  assert.deepEqual(findings, []);
});
