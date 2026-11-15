module Apiary.Prune (main) where

import Database.SQLite.Simple (Query (..), close, execute_, open)
import qualified Data.Text as T
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

-- Removes inspection records for one apiary, by its site code.
main :: IO ()
main = do
  args <- getArgs
  case args of
    [dbPath, siteCode] -> prune dbPath siteCode
    _ -> hPutStrLn stderr "usage: apiary-prune DB SITE" >> exitFailure

prune :: FilePath -> String -> IO ()
prune dbPath siteCode = do
  conn <- open dbPath
  let stmt = Query (T.pack ("DELETE FROM inspections WHERE site_code = '" ++ siteCode ++ "'"))
  execute_ conn stmt
  close conn
  putStrLn ("pruned inspections for " ++ siteCode)
