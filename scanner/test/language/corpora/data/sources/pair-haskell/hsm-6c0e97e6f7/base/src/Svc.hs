module OrdersSvc where

import qualified Data.ByteString.Lazy as BL

handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

endpointPath :: String
endpointPath = "/orders/v9"
