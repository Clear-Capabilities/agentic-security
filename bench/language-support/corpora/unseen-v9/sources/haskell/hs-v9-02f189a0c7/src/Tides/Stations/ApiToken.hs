module Tides.Stations.ApiToken (main) where

import System.Random.MWC (createSystemRandom, uniformR)
import Control.Monad (replicateM)
import Data.Word (Word8)
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
      gen <- createSystemRandom
      bytes <- replicateM 24 (uniformR (0, 255 :: Word8) gen)
      let token = B16.encode (BS.pack bytes)
      BC.appendFile tokenFile (BC.pack stationName <> " " <> token <> "\n")
      BC.putStrLn token
    _ -> putStrLn "usage: tides-issue-token <station>"
