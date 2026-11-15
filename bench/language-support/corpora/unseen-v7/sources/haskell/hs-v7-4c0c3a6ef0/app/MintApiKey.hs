module Main (main) where

import Crypto.Random (drgNew, randomBytesGenerate)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [partner] -> mint partner
    _ -> hPutStrLn stderr "usage: mint-api-key <partner>" >> exitFailure

newKey :: IO BS.ByteString
newKey = do
  drg <- drgNew
  let (bytes, _) = randomBytesGenerate 30 drg
  pure (B16.encode bytes)

mint :: String -> IO ()
mint partner = do
  key <- newKey
  conn <- open "partners.db"
  execute conn "INSERT INTO api_keys (partner, key, created_at) VALUES (?, ?, datetime('now'))" (partner, key)
  close conn
  putStrLn ("key for " ++ partner ++ ": " ++ BC.unpack key)
