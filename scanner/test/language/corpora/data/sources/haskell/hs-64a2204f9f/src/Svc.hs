module OrdersSvc where

import qualified Data.ByteString.Lazy as BL
import qualified Vendor.Orders.Guard as G

handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

endpointPath :: String
endpointPath = "/orders/v0"
