-- Deliberately vulnerable: untrusted input is concatenated into a shell command (CWE-78).
module Main (main) where

import System.Environment (getArgs)
import System.Process (callCommand)

main :: IO ()
main = do
  args <- getArgs
  let name = case args of
        (a : _) -> a
        _ -> ""
  callCommand ("echo hello " ++ name)
