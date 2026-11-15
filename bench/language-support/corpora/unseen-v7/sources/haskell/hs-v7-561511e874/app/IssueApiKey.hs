module Main (main) where

import Data.Time.Clock.POSIX (getPOSIXTime)
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import System.Random (mkStdGen, randomRs)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [partner] -> issue partner
    _ -> hPutStrLn stderr "usage: issue-api-key <partner>" >> exitFailure

issue :: String -> IO ()
issue partner = do
  key <- take 40 . randomRs ('a', 'z') . mkStdGen . round <$> getPOSIXTime
  conn <- open "partners.db"
  execute conn "INSERT INTO api_keys (partner, key, created_at) VALUES (?, ?, datetime('now'))" (partner, key)
  close conn
  putStrLn ("key for " ++ partner ++ ": " ++ key)
