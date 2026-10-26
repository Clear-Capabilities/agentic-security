-- Mitigated: a "--" ends option parsing, so everything after it is an operand of the program and never an option.
module Main (main) where

import System.Environment (getArgs)
import System.Process (callProcess)

main :: IO ()
main = do
  args <- getArgs
  callProcess "archive-tool" ("--" : args)
