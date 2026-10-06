module OrdersSvc where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Char8 as BC

digestPassword :: String -> BC.ByteString
digestPassword password = SHA256.hash (BC.pack password)

endpointPath :: String
endpointPath = "/orders/v0"
