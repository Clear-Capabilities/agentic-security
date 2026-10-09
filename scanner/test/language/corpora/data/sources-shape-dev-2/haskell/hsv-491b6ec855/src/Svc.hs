module OrdersSvc where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS

newSessionToken :: IO BS.ByteString
newSessionToken = getRandomBytes 24

endpointPath :: String
endpointPath = "/orders/v0"
