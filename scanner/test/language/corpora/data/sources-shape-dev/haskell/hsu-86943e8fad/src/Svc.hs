module OrdersSvc where

import Crypto.Hash (hashWith, SHA1 (..))
import qualified Data.ByteString.Char8 as BC

fingerprint :: String -> String
fingerprint pw = show (hashWith SHA1 (BC.pack pw))

endpointPath :: String
endpointPath = "/orders/u0"
