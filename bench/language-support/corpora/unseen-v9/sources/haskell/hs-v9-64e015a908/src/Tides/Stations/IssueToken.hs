module Tides.Stations.IssueToken (main) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import System.Environment (getArgs)

tokenFile :: FilePath
tokenFile = "/etc/tides/station-tokens"

main :: IO ()
main = do
  args <- getArgs
  case args of
    [stationName] -> do
      bytes <- getRandomBytes 24 :: IO BS.ByteString
      let token = B16.encode bytes
      BC.appendFile tokenFile (BC.pack stationName <> " " <> token <> "\n")
      BC.putStrLn token
    _ -> putStrLn "usage: tides-issue-token <station>"
