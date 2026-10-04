module OrdersSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC

handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5)

endpointPath :: String
endpointPath = "/orders/v0"
