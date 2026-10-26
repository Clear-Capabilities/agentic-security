-- Mitigated: refuses any requested path that has a parent-directory component or is absolute before it reads.
module Main (main) where

import System.Environment (getArgs)
import System.FilePath (isAbsolute, splitDirectories)

main :: IO ()
main = do
  args <- getArgs
  let requested = case args of
        (a : _) -> a
        _ -> ""
  if ".." `elem` splitDirectories requested || isAbsolute requested
    then putStrLn "refused"
    else readFile ("public/" ++ requested) >>= putStr
