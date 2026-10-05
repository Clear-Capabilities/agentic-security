module UsersSvc where

import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString.Char8 as BC

store :: String -> BC.ByteString
store pw = MD5.hash (BC.pack pw)

endpointPath :: String
endpointPath = "/users/u0"
