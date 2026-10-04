module OrdersSvc where

import Crypto.Random (getRandomBytes) -- TODO: vulnerable to injection, fix later
import qualified Data.ByteString as BS

handleToken :: IO BS.ByteString
handleToken = getRandomBytes 16 -- TODO: vulnerable to injection, fix later

endpointPath :: String
endpointPath = "/orders/v0"
