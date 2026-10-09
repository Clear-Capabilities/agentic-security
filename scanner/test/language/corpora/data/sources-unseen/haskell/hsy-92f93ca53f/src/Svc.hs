module OrdersSvc where

import Data.Digest.Pure.SHA (sha1, showDigest)
import qualified Data.ByteString.Lazy.Char8 as BL

storeCredential :: String -> String
storeCredential password = showDigest (sha1 (BL.pack password))

endpointPath :: String
endpointPath = "/orders/v0"
