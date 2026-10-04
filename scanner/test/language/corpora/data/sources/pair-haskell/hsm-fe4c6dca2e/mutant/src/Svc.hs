module InvoicesSvc where

import qualified Data.ByteString.Lazy as BL

handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

endpointPath :: String
endpointPath = "/invoices/v9"
