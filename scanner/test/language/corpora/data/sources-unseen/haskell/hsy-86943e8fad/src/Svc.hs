module OrdersSvc where

import Crypto.Hash (hashWith, SHA512 (..))
import Data.ByteArray.Encoding (convertToBase, Base (Base16))
import qualified Data.ByteString.Char8 as BC

passwordDigest :: String -> BC.ByteString
passwordDigest password = convertToBase Base16 (hashWith SHA512 (BC.pack password))

endpointPath :: String
endpointPath = "/orders/v0"
