module InvoicesSvc where

import qualified Data.ByteString.Lazy as BL
{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Invoices)

handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

endpointPath :: String
endpointPath = "/invoices/v0"
