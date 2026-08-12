// Subprocess helper for test/lsp-server.test.js.
//
// scanFile() calls send(), which writes real LSP protocol frames to
// process.stdout — fine in production, but unsafe to invoke inside the
// `node --test` process itself: monkey-patching process.stdout.write to
// swallow those frames interferes with the test runner's own stdout-based
// reporting (observed: 3 of 4 sibling tests silently vanished from the
// summary when a stub-and-restore was used in-process). Running scanFile in
// a real child process isolates its stdout writes entirely; the result is
// reported back over stderr, a channel scanFile never touches.
import { _internals } from '../../src/lsp/server.js';

const [, , rootDir, absFilePath] = process.argv;
const { scanFile, pathToUri, _diagnosticsByUri, _setRootDir } = _internals;

_setRootDir(rootDir);
const uri = pathToUri(absFilePath);
await scanFile(uri);
process.stderr.write(JSON.stringify(_diagnosticsByUri.get(uri) || []));
