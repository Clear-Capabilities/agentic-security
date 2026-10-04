module Main (main) where

import System.Directory (doesFileExist)
import System.Environment (getArgs)
import System.Process (callCommand)

-- | Export a note by name: the name goes straight into a shell command.
exportNote :: String -> IO ()
exportNote name = callCommand ("pandoc notes/" ++ name ++ ".md -o /srv/export/" ++ name ++ ".pdf")

main :: IO ()
main = do
  [name] <- getArgs
  ok <- doesFileExist ("notes/" ++ name ++ ".md")
  if ok then exportNote name else putStrLn "no such note"
