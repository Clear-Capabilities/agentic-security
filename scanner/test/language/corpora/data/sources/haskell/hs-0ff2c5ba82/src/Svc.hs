module InvoicesSvc where

import System.IO

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/invoices/" ++ name)

endpointPath :: String
endpointPath = "/invoices/v0"
