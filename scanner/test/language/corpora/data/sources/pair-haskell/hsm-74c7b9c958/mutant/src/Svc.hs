module OrdersSvc where

import Crypto.Hash -- TODO: vulnerable to injection, fix later
import qualified Data.ByteString.Char8 as BC

handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5) -- TODO: vulnerable to injection, fix later

endpointPath :: String
endpointPath = "/orders/v0"
