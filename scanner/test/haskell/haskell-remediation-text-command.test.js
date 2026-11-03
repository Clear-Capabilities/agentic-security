// hs-process-argv for Text commands (0.195.16): `system (cs t)` / `(T.unpack t)` where t is a `<>` concatenation, on the line or in a
// one-line `let` of the same function. The unpack is kept per piece so each argument is a String, the unused `let` is removed, and the
// patch is type-checked under GHC against declared stubs. A command whose program is a variable (the real IHP site: the editor comes from
// an environment variable and may itself be "code --goto") is refused with that decision named.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { planHaskellFix, validateHaskellFix, CLASS_REASONS } from '../../src/language/haskell-fix.js';

process.env.GHC_ENVIRONMENT = '-';
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const STUB_PROCESS = `module System.Process (system, callCommand, callProcess, rawSystem, ExitCode(..)) where
data ExitCode = ExitSuccess | ExitFailure Int
system :: String -> IO ExitCode
system _ = pure ExitSuccess
callCommand :: String -> IO ()
callCommand _ = pure ()
callProcess :: FilePath -> [String] -> IO ()
callProcess _ _ = pure ()
rawSystem :: FilePath -> [String] -> IO ExitCode
rawSystem _ _ = pure ExitSuccess
`;
const STUB_CS = `module Data.String.Conversions (cs) where
import qualified Data.Text as T
class ConvertibleStrings a b where cs :: a -> b
instance ConvertibleStrings T.Text String where cs = T.unpack
instance ConvertibleStrings String T.Text where cs = T.pack
`;
const finding = (file, line) => ({ cwe: 'CWE-78', rule: 'hs-shell-command', file, line, severity: 'high', vuln: 'OS Command Injection (shell string)' });

async function verified(files, file, line) {
  const plan = planHaskellFix(finding(file, line), files);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  const v = await validateHaskellFix(finding(file, line), { files, compile: true });
  assert.equal(v.gates.syntax.ok, true, JSON.stringify(v.gates.syntax));
  if (GHC) { assert.equal(v.gates.compile.ran, true, 'ghc ran'); assert.equal(v.gates.compile.ok, true, JSON.stringify(v.gates.compile)); }
  return plan;
}

test('a Text command in a one-line let: the let goes, each piece is unpacked, the literal program is called directly', async () => {
  const files = {
    'Open.hs': `{-# LANGUAGE OverloadedStrings #-}
module Open (openEditor) where
import qualified Data.Text as T
import qualified System.Process as Process

openEditor :: T.Text -> IO ()
openEditor path = do
    let command = "code" <> " --goto " <> path
    _ <- Process.system (T.unpack command)
    pure ()
`,
    'System/Process.hs': STUB_PROCESS,
  };
  const plan = await verified(files, 'Open.hs', 9);
  // no "--" is inserted: "--goto" is an option that may take a value, and the fixer never guesses (the explanation says so)
  assert.match(plan.after, /_ <- Process\.rawSystem "code" \["--goto", T\.unpack path\]/);
  assert.match(plan.explanation, /can still be read as an option/);
  assert.doesNotMatch(plan.after, /let command/, 'the now-unused let binding is removed');
});

test('a Text command on the line under cs keeps cs per piece', async () => {
  const files = {
    'Run.hs': `{-# LANGUAGE OverloadedStrings #-}
module Run (run) where
import qualified Data.Text as T
import Data.String.Conversions (cs)
import System.Process (callCommand)

run :: T.Text -> IO ()
run name = callCommand (cs ("convert " <> name <> " out.png"))
`,
    'System/Process.hs': STUB_PROCESS, 'Data/String/Conversions.hs': STUB_CS,
  };
  const plan = await verified(files, 'Run.hs', 8);
  assert.match(plan.after, /callProcess "convert" \["--", cs name, "out\.png"\]/);
});

test('refused with the decision named: the program is a variable, or the let has a conditional', () => {
  const ihp = {
    'Controller.hs': `module Controller (openEditor) where
import qualified Data.Text as T
import qualified System.Process as Process

openEditor :: T.Text -> T.Text -> Int -> IO ()
openEditor editor path line = do
    let command = editor <> " " <> path <> if line > 0 then ":" <> T.pack (show line) else ""
    _ <- Process.system (T.unpack command)
    pure ()
`,
  };
  const r = planHaskellFix(finding('Controller.hs', 8), ihp);
  assert.equal(r.ok, false);
  assert.match(r.reason, /program itself is a variable/);
  assert.equal(r.reason, CLASS_REASONS['CWE-78']);
  const varProg = { 'R.hs': 'module R (run) where\nimport System.Process (system)\nrun :: String -> String -> IO ()\nrun editor file = do\n  _ <- system (editor ++ " " ++ file)\n  pure ()\n' };
  assert.equal(planHaskellFix(finding('R.hs', 5), varProg).ok, false);
});
