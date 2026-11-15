module Main (main) where

import Data.String (fromString)
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [dbPath, carrier] -> purge dbPath carrier
    _ -> do
      hPutStrLn stderr "usage: shipment-purge <db> <carrier>"
      exitFailure

purge :: FilePath -> String -> IO ()
purge dbPath carrier = do
  conn <- open dbPath
  let stmt = "DELETE FROM shipments WHERE carrier = '" ++ carrier ++ "' AND delivered = 1"
  execute_ conn (fromString stmt)
  n <- changes conn
  putStrLn (show n ++ " delivered shipments removed for " ++ carrier)
  close conn
