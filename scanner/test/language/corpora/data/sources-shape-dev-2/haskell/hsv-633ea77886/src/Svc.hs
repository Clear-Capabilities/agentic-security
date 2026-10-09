module OrdersSvc where

import Crypto.BCrypt
import qualified Data.ByteString.Char8 as BC

digestPassword :: String -> IO (Maybe BC.ByteString)
digestPassword password = hashPasswordUsingPolicy fastBcryptHashingPolicy (BC.pack password)

endpointPath :: String
endpointPath = "/orders/v0"
