module DevicesSvc where

import qualified Data.ByteString.Lazy as BL

handleUpload :: IO BL.ByteString
handleUpload = fmap (BL.take 65536) BL.getContents

endpointPath :: String
endpointPath = "/devices/v1"
