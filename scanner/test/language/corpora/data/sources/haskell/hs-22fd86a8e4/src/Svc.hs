module OrdersSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC

handleDigest :: String -> String
handleDigest pw = show (hash (BC.pack (pw ++ "orders")) :: Digest SHA1)

endpointPath :: String
endpointPath = "/orders/v0"
