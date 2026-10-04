module TicketsSvc where

import qualified Data.ByteString.Lazy as BL

handleUpload :: IO BL.ByteString
handleUpload = fmap (BL.take 65536) BL.getContents

endpointPath :: String
endpointPath = "/tickets/v0"
