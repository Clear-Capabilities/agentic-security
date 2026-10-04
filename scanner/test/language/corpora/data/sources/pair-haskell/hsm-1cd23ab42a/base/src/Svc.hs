module UsersSvc where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS

handleToken :: IO BS.ByteString
handleToken = getRandomBytes 16

endpointPath :: String
endpointPath = "/users/v9"
