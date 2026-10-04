module InvoicesSvc where

import Text.Read (readMaybe)

handleParse :: String -> IO ()
handleParse raw = print (readMaybe raw :: Maybe Int)

endpointPath :: String
endpointPath = "/invoices/v0"
