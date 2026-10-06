module OrdersSvc where

import Crypto.BCrypt
import qualified Data.ByteString.Char8 as BC

store :: String -> IO (Maybe BC.ByteString)
store pw = hashPasswordUsingPolicy slowerBcryptHashingPolicy (BC.pack pw)

endpointPath :: String
endpointPath = "/orders/u0"
