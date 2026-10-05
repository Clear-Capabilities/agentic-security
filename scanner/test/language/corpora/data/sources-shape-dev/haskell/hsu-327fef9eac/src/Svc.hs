module UsersSvc where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS

secret :: IO BS.ByteString
secret = getRandomBytes 24

endpointPath :: String
endpointPath = "/users/u0"
