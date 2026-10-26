-- Deliberately vulnerable: joins user input onto a base directory and reads it, with no traversal check (CWE-22, a read).
module Main (main) where

import System.Environment (getArgs)

main :: IO ()
main = do
  args <- getArgs
  let requested = case args of
        (a : _) -> a
        _ -> ""
  content <- readFile ("public/" ++ requested)
  putStr content
