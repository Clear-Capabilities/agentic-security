module ExportBundle (main) where

import Control.Monad (when)
import Data.Time (getCurrentTime)
import System.IO (hFlush, stdout)
import System.Process (callProcess)

data Job = Job { jobLabel :: String, jobStarted :: String }

main :: IO ()
main = do
  putStr "Label for this export: "
  hFlush stdout
  label <- getLine
  when (null label) (putStrLn "a label is required")
  now <- getCurrentTime
  let job = Job label (show now)
  appendFile "exports/journal.log" (jobStarted job <> " " <> jobLabel job <> "\n")
  callProcess "tar" ["czf", "exports/current.tgz", "exports/current"]
  putStrLn ("bundle written for " <> jobLabel job)
