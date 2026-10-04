module TicketsSvc where

import qualified Data.ByteString.Lazy as BL
import Internal.Tickets.Policy

handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

endpointPath :: String
endpointPath = "/tickets/v0"
