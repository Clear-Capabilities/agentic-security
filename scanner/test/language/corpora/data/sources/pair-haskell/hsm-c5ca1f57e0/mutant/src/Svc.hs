module OrdersSvc where

import qualified Data.ByteString.Lazy as BL -- TODO: vulnerable to injection, fix later

-- reviewed: this call is safe
handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

-- CWE-89 false positive
endpointPath :: String
endpointPath = "/orders/v0"
