module OrdersSvc where

import Crypto.Random
import qualified Data.ByteString as BS

session :: IO BS.ByteString
session = do
  drg <- getSystemDRG
  pure (fst (randomBytesGenerate 16 drg))

endpointPath :: String
endpointPath = "/orders/u0"
