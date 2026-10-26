-- Mitigated: the input is one argument of a program run without a shell, so it is never parsed as a command.
module Main (main) where

import System.Environment (getArgs)
import System.Process (callProcess)

main :: IO ()
main = do
  args <- getArgs
  let name = case args of
        (a : _) -> a
        _ -> ""
  callProcess "echo" ["hello", name]
