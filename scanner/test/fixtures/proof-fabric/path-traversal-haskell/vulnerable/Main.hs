-- Deliberately vulnerable: joins user input onto a base directory with no traversal check.
module Main (main) where

import System.Directory (createDirectoryIfMissing)
import System.Environment (getArgs)

main :: IO ()
main = do
  createDirectoryIfMissing True "public"
  args <- getArgs
  let requested = case args of
        (a : _) -> a
        _ -> ""
  writeFile ("public/" ++ requested) "written-by-fixture"
