-- Mitigated: refuses any requested path that has a parent-directory component before it writes.
module Main (main) where

import System.Directory (createDirectoryIfMissing)
import System.Environment (getArgs)
import System.FilePath (isAbsolute, splitDirectories)

main :: IO ()
main = do
  createDirectoryIfMissing True "public"
  args <- getArgs
  let requested = case args of
        (a : _) -> a
        _ -> ""
  if ".." `elem` splitDirectories requested || isAbsolute requested
    then putStrLn "refused"
    else writeFile ("public/" ++ requested) "written-by-fixture"
