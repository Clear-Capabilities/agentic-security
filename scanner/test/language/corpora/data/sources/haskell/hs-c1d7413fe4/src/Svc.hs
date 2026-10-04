module DevicesSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC

handleDigest :: String -> String
handleDigest pw = show (hash (BC.pack (pw ++ "devices")) :: Digest SHA1)

endpointPath :: String
endpointPath = "/devices/v0"
