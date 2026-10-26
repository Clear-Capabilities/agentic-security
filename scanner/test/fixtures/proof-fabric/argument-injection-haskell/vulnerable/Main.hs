-- Deliberately vulnerable: the command-line arguments become the argument vector of another program, with no end-of-options marker
-- and no check for a leading dash, so a caller can make the first argument an option of that program (CWE-88).
module Main (main) where

import System.Environment (getArgs)
import System.Process (callProcess)

main :: IO ()
main = do
  args <- getArgs
  callProcess "archive-tool" args
