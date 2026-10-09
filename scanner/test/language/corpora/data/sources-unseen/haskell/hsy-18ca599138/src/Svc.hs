module OrdersSvc where

import Crypto.Random (getRandomBytes)
import Data.ByteArray.Encoding (convertToBase, Base (Base64URLUnpadded))
import qualified Data.ByteString as BS

newSessionId :: IO BS.ByteString
newSessionId = do
  raw <- getRandomBytes 24 :: IO BS.ByteString
  pure (convertToBase Base64URLUnpadded raw)

endpointPath :: String
endpointPath = "/orders/v0"
